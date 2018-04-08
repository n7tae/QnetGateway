/*
 *   Copyright (C) 2018 by Thomas A. Early N7TAE
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <exception>
#include <cstdio>
#include <cctype>
#include <cstring>
#include <csignal>
#include <ctime>
#include <cstdlib>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "versions.h"
#include "mmdvm_modem.h"
#include "g2_typedefs.h"

std::atomic<bool> CMMDVMModem::keep_running(true);

CMMDVMModem::CMMDVMModem() :
seed(time(NULL)),
COUNTER(0)
{
}

CMMDVMModem::~CMMDVMModem()
{
}

bool CMMDVMModem::Initialize(const char *cfgfile)
{
	if (ReadConfig(cfgfile))
		return true;

	struct sigaction act;
	act.sa_handler = &CMMDVMModem::SignalCatch;
	sigemptyset(&act.sa_mask);
	if (sigaction(SIGTERM, &act, 0) != 0) {
		printf("sigaction-TERM failed, error=%d\n", errno);
		return true;
	}
	if (sigaction(SIGHUP, &act, 0) != 0) {
		printf("sigaction-HUP failed, error=%d\n", errno);
		return true;
	}
	if (sigaction(SIGINT, &act, 0) != 0) {
		printf("sigaction-INT failed, error=%d\n", errno);
		return true;
	}

	return false;
}

int CMMDVMModem::OpenSocket(const std::string &address, unsigned short port)
{
	if (! port) {
		printf("ERROR: OpenSocket: non-zero port must be specified.\n");
		return -1;
	}

	int fd = ::socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		printf("Cannot create the UDP socket, err: %d, %s\n", errno, strerror(errno));
		return -1;
	}

	sockaddr_in addr;
	::memset(&addr, 0, sizeof(sockaddr_in));
	addr.sin_family      = AF_INET;
	addr.sin_port        = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (! address.empty()) {
		addr.sin_addr.s_addr = ::inet_addr(address.c_str());
		if (addr.sin_addr.s_addr == INADDR_NONE) {
			printf("The local address is invalid - %s\n", address.c_str());
			close(fd);
			return -1;
		}
	}

	int reuse = 1;
	if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) == -1) {
		printf("Cannot set the UDP socket %s:%u option, err: %d, %s\n", address.c_str(), port, errno, strerror(errno));
		close(fd);
		return -1;
	}

	if (::bind(fd, (sockaddr*)&addr, sizeof(sockaddr_in)) == -1) {
		printf("Cannot bind the UDP socket %s:%u address, err: %d, %s\n", address.c_str(), port, errno, strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

void CMMDVMModem::Run(const char *cfgfile)
{
	if (Initialize(cfgfile))
		return;

	msock = OpenSocket(MMDVM_IP, MMDVM_PORT);
	if (msock < 0)
		return;

	gsock = OpenSocket(G2_INTERNAL_IP, G2_INTERNAL_PORT);
	if (gsock < 0) {
		::close(msock);
		return;
	}
	printf("msock=%d, gsock=%d\n", msock, gsock);

	keep_running = true;

	while (keep_running) {
		struct timeval tv;
		fd_set readfds;

		tv.tv_sec = 0;
		tv.tv_usec = 1000;	// wait 1ms for some input

		FD_ZERO(&readfds);
		FD_SET(msock, &readfds);
		FD_SET(gsock, &readfds);
		int maxfd = (msock > gsock) ? msock : gsock;

		// don't care about writefds and exceptfds:
		int ret = ::select(maxfd+1, &readfds, NULL, NULL, &tv);
		if (ret < 0)
			break;
		if (ret == 0)
			continue;

		// there is something to read!
		unsigned char buf[100];
		sockaddr_in addr;
		memset(&addr, 0, sizeof(sockaddr_in));
		socklen_t size = sizeof(sockaddr);
		ssize_t len;
		if (FD_ISSET(msock, &readfds)) {
			len = ::recvfrom(msock, buf, 100, 0, (sockaddr *)&addr, &size);

			if (len < 0) {
				printf("ERROR: RUN: recvfrom(mmdvm) return error %d, %s\n", errno, strerror(errno));
				break;
			}

			if (ntohs(addr.sin_port) == G2_INTERNAL_PORT)
				printf("DEBUG: Run: reading from msock but port was %u.\n", ntohs(addr.sin_port));

		} else if (FD_ISSET(gsock, &readfds)) {
			len = ::recvfrom(gsock, buf, 100, 0, (sockaddr *)&addr, &size);

			if (len < 0) {
				printf("ERROR: RUN: recvfrom(g2) return error %d, %s\n", errno, strerror(errno));
				break;
			}

			if (ntohs(addr.sin_port) == MMDVM_PORT)
				printf("DEBUG: Run: reading from gsock but port was %u.\n", ntohs(addr.sin_port));

		} else {
			printf("ERROR: Run: Input from unknown fd!\n");
			break;
		}
		if (len == 0)
			continue;

		if (ntohs(addr.sin_port) == MMDVM_PORT) {
			printf("read %d bytes from MMDVMHost\n", (int)len);
			if (ProcessMMDVM(len, buf))
				break;
		} else if (ntohs(addr.sin_port) == G2_INTERNAL_PORT) {
			printf("read %d bytes from Gateway\n", (int)len);
			if (ProcessGateway(len, buf))
				break;
		} else
			printf("read %d bytes from unknown port %u!\n", (int)len, ntohs(addr.sin_port));
	}

	::close(msock);
	::close(gsock);
}

int CMMDVMModem::SendTo(const int fd, const unsigned char *buf, const int size, const std::string &address, const unsigned short port)
{
	sockaddr_in addr;
	::memset(&addr, 0, sizeof(sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = ::inet_addr(address.c_str());
	addr.sin_port = htons(port);

	int len = ::sendto(fd, buf, size, 0, (sockaddr *)&addr, sizeof(sockaddr_in));
	if (len < 0)
		printf("ERROR: SendTo: fd=%d failed sendto err: %d, %s\n", fd, errno, strerror(errno));
	else if (len != size)
		printf("ERROR: SendTo: fd=%d tried to send %d bytes, actually sent %d.\n", fd, size, len);
	return len;
}

bool CMMDVMModem::ProcessGateway(const int len, const unsigned char *raw)
{
	SPKT buf;
	::memcpy(buf.pkt_id, raw, len);

	// if there is data, translate it and send it to the MMDVM Modem
	if (29==len || 58==len) { //here is dstar data
		SMMDVMPKT pkt;

		::memcpy(pkt.title, "DSRP", 4);
		if (29 == len) {	// write an AMBE packet
			pkt.tag = 0x21U;
			pkt.voice.id = buf.vpkt.streamid;
			pkt.voice.seq = buf.vpkt.ctrl;
			if (pkt.voice.seq & 0x40)
				printf("INFO: ProcessGateway: sending voice end-of-stream\n");
			else if (pkt.voice.seq > 20)
				printf("DEBUG: ProcessGateway: unexpected voice sequence number %d\n", pkt.voice.seq);

			memcpy(pkt.voice.ambe, buf.vpkt.vasd.text, 12);
			int ret = SendTo(msock, pkt.title, 21, MMDVM_IP, MMDVM_PORT);
			if (ret != 21) {
				printf("ERROR: ProcessGateway: Could not write AMBE mmdvm packet\n");
				return true;
			}
		} else {			// write a Header packet
			pkt.tag = 0x20U;
			pkt.header.id = buf.vpkt.streamid;
			pkt.header.seq = buf.vpkt.ctrl;
			if (pkt.header.seq) {
				printf("DEBUG: ProcessGateway: unexpected .header.seq %d, resetting to 0\n", pkt.header.seq);
				pkt.header.seq = 0;
			}

			memcpy(pkt.header.flag, buf.vpkt.hdr.flag, 41);
			int ret = SendTo(msock, pkt.title, 49, MMDVM_IP, MMDVM_PORT);
			if (ret != 49) {
				printf("ERROR: ProcessGateway: Could not write Header mmdvm packet\n");
				return true;
			}
		}
	} else
		printf("DEBUG: ProcessGateway: unusual packet size read len=%d\n", len);
	return false;
}

bool CMMDVMModem::ProcessMMDVM(const int len, const unsigned char *raw)
{
	SMMDVMPKT mpkt;
	SPKT gpkt;

	::memcpy(mpkt.title, raw, len);

	// if there is data, translate it and send it to the Gateway
	if (49 == len) {
		// sets most of the params with the header
		::memcpy(gpkt.pkt_id, "DSTR", 4);
		gpkt.counter = COUNTER++;
		gpkt.flag[0] = 0x72;
		gpkt.flag[1] = 0x12;
		gpkt.flag[2] = 0x0;
		gpkt.remaining = 0x30;
		gpkt.vpkt.icm_id = 0x20;
		gpkt.vpkt.dst_rptr_id = 0x0;
		gpkt.vpkt.snd_rptr_id = 0x1;
		gpkt.vpkt.snd_term_id = ('B'==RPTR_MOD) ? 0x1 : (('C'==RPTR_MOD) ? 0x2 : 0x3);
		gpkt.vpkt.streamid = (rand_r(&seed) % 65535U) + 1U;
		gpkt.vpkt.ctrl = mpkt.header.seq;
		memcpy(gpkt.vpkt.hdr.flag, mpkt.header.flag, 41);
		int ret = SendTo(gsock, gpkt.pkt_id, 58, G2_INTERNAL_IP, G2_INTERNAL_PORT);
		if (ret != 58) {
			printf("ERROR: ProcessMMDVM: Could not write gateway header packet\n");
			return true;
		}
	} else if (21 == len) {
		// just a few need updating in a voice data frame
		gpkt.counter = COUNTER++;
		gpkt.remaining = 0x16;
		gpkt.vpkt.ctrl = mpkt.voice.seq;
		memcpy(gpkt.vpkt.vasd.text, mpkt.voice.ambe, 12);
		int ret = SendTo(gsock, gpkt.pkt_id, 29, G2_INTERNAL_IP, G2_INTERNAL_PORT);
		if (ret != 29) {
			printf("ERROR: ProcessMMDVM: Could not write gateway voice packet\n");
			return true;
		}
	} else
		printf("DEBUG: ProcessMMDVM: unusual packet size read len=%d\n", len);
	return false;
}

bool CMMDVMModem::GetValue(const Config &cfg, const char *path, int &value, const int min, const int max, const int default_value)
{
	if (cfg.lookupValue(path, value)) {
		if (value < min || value > max)
			value = default_value;
	} else
		value = default_value;
	printf("%s = [%d]\n", path, value);
	return true;
}

bool CMMDVMModem::GetValue(const Config &cfg, const char *path, double &value, const double min, const double max, const double default_value)
{
	if (cfg.lookupValue(path, value)) {
		if (value < min || value > max)
			value = default_value;
	} else
		value = default_value;
	printf("%s = [%lg]\n", path, value);
	return true;
}

bool CMMDVMModem::GetValue(const Config &cfg, const char *path, bool &value, const bool default_value)
{
	if (! cfg.lookupValue(path, value))
		value = default_value;
	printf("%s = [%s]\n", path, value ? "true" : "false");
	return true;
}

bool CMMDVMModem::GetValue(const Config &cfg, const char *path, std::string &value, int min, int max, const char *default_value)
{
	if (cfg.lookupValue(path, value)) {
		int l = value.length();
		if (l<min || l>max) {
			printf("%s value '%s' is wrong size\n", path, value.c_str());
			return false;
		}
	} else
		value = default_value;
	printf("%s = [%s]\n", path, value.c_str());
	return true;
}

// process configuration file and return true if there was a problem
bool CMMDVMModem::ReadConfig(const char *cfgFile)
{
	Config cfg;

	printf("Reading file %s\n", cfgFile);
	// Read the file. If there is an error, report it and exit.
	try {
		cfg.readFile(cfgFile);
	}
	catch(const FileIOException &fioex) {
		printf("Can't read %s\n", cfgFile);
		return true;
	}
	catch(const ParseException &pex) {
		printf("Parse error at %s:%d - %s\n", pex.getFile(), pex.getLine(), pex.getError());
		return true;
	}

	std::string mmdvm_path, value;
	int i;
	for (i=0; i<3; i++) {
		mmdvm_path = "module.";
		mmdvm_path += ('a' + i);
		if (cfg.lookupValue(mmdvm_path + ".type", value)) {
			if (0 == strcasecmp(value.c_str(), "mmdvm"))
				break;
		}
	}
	if (i >= 3) {
		printf("mmdvm not defined in any module!\n");
		return true;
	}
	RPTR_MOD = 'A' + i;

	if (cfg.lookupValue(std::string(mmdvm_path+".callsign").c_str(), value) || cfg.lookupValue("ircddb.login", value)) {
		int l = value.length();
		if (l<3 || l>CALL_SIZE-2) {
			printf("Call '%s' is invalid length!\n", value.c_str());
			return true;
		} else {
			for (i=0; i<l; i++) {
				if (islower(value[i]))
					value[i] = toupper(value[i]);
			}
			value.resize(CALL_SIZE, ' ');
		}
		strcpy(RPTR, value.c_str());
	} else {
		printf("%s.login is not defined!\n", mmdvm_path.c_str());
		return true;
	}

	if (cfg.lookupValue("ircddb.login", value)) {
		int l = value.length();
		if (l<3 || l>CALL_SIZE-2) {
			printf("Call '%s' is invalid length!\n", value.c_str());
			return true;
		} else {
			for (i=0; i<l; i++) {
				if (islower(value[i]))
					value[i] = toupper(value[i]);
			}
			value.resize(CALL_SIZE, ' ');
		}
		strcpy(OWNER, value.c_str());
		printf("ircddb.login = [%s]\n", OWNER);
	} else {
		printf("ircddb.login is not defined!\n");
		return true;
	}

	if (GetValue(cfg, std::string(mmdvm_path+".internal_ip").c_str(), value, 7, IP_SIZE, "0.0.0.0")) {
		MMDVM_IP = value;
	} else
		return true;

	GetValue(cfg, std::string(mmdvm_path+".port").c_str(), i, 10000, 65535, 20011);
	MMDVM_PORT = (unsigned short)i;

	if (GetValue(cfg, "gateway.ip", value, 7, IP_SIZE, "127.0.0.1")) {
		G2_INTERNAL_IP = value;
	} else
		return true;

	GetValue(cfg, "gateway.internal.port", i, 10000, 65535, 20010);
	G2_INTERNAL_PORT = (unsigned short)i;

	GetValue(cfg, "timing.play.delay", DELAY_BETWEEN, 9, 25, 19);

	GetValue(cfg, "timing.play.wait", DELAY_BEFORE, 1, 10, 2);

	GetValue(cfg, std::string(mmdvm_path+".acknowledge").c_str(), RPTR_ACK, false);

	GetValue(cfg, std::string(mmdvm_path+".packet_wait").c_str(), WAIT_FOR_PACKETS, 6, 100, 25);

	return false;
}

void CMMDVMModem::SignalCatch(int signum)
{
	if ((signum == SIGTERM) || (signum == SIGINT)  || (signum == SIGHUP))
		keep_running = false;
	exit(0);
}

int main(int argc, const char **argv)
{
	setbuf(stdout, NULL);
	if (2 != argc) {
		printf("usage: %s path_to_config_file\n", argv[0]);
		printf("       %s --version\n", argv[0]);
		return 1;
	}

	if ('-' == argv[1][0]) {
		printf("\nMMDVM Modem Version #%s Copyright (C) 2018 by Thomas A. Early N7TAE\n", MMDVM_VERSION);
		printf("MMDVM Modem comes with ABSOLUTELY NO WARRANTY; see the LICENSE for details.\n");
		printf("This is free software, and you are welcome to distribute it\nunder certain conditions that are discussed in the LICENSE file.\n\n");
		return 0;
	}

	CMMDVMModem mmdvm;

	mmdvm.Run(argv[1]);

	printf("%s is closing.\n", argv[0]);

	return 0;
}
