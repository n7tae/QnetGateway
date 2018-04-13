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
#include "QnetRelay.h"
#include "QnetTypeDefs.h"

std::atomic<bool> CQnetRelay::keep_running(true);

CQnetRelay::CQnetRelay() :
seed(time(NULL)),
COUNTER(0)
{
}

CQnetRelay::~CQnetRelay()
{
}

bool CQnetRelay::Initialize(const char *cfgfile)
{
	if (ReadConfig(cfgfile))
		return true;

	struct sigaction act;
	act.sa_handler = &CQnetRelay::SignalCatch;
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

int CQnetRelay::OpenSocket(const std::string &address, unsigned short port)
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

void CQnetRelay::Run(const char *cfgfile)
{
	if (Initialize(cfgfile))
		return;

	msock = OpenSocket(MMDVM_IP, MMDVM_OUT_PORT);
	if (msock < 0)
		return;

	gsock = OpenSocket(G2_INTERNAL_IP, G2_OUT_PORT);
	if (gsock < 0) {
		::close(msock);
		return;
	}

	printf("msock=%d, gsock=%d\n", msock, gsock);

	keep_running = true;

	while (keep_running) {
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(msock, &readfds);
		FD_SET(gsock, &readfds);
		int maxfs = (msock > gsock) ? msock : gsock;

		// don't care about writefds and exceptfds:
		// and we'll wait as long as needed
		int ret = ::select(maxfs+1, &readfds, NULL, NULL, NULL);
		if (ret < 0) {
			printf("ERROR: Run: select returned err=%d, %s\n", errno, strerror(errno));
			break;
		}
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
				printf("ERROR: Run: recvfrom(mmdvm) return error %d, %s\n", errno, strerror(errno));
				break;
			}

			if (ntohs(addr.sin_port) != MMDVM_IN_PORT)
				printf("DEBUG: Run: read from msock but port was %u, expected %u.\n", ntohs(addr.sin_port), MMDVM_IN_PORT);

		}

		if (FD_ISSET(gsock, &readfds)) {
			len = ::recvfrom(gsock, buf, 100, 0, (sockaddr *)&addr, &size);

			if (len < 0) {
				printf("ERROR: Run: recvfrom(gsock) returned error %d, %s\n", errno, strerror(errno));
				break;
			}

			if (ntohs(addr.sin_port) != G2_IN_PORT)
				printf("DEBUG: Run: read from gsock but the port was %u, expected %u\n", ntohs(addr.sin_port), G2_IN_PORT);

		}

		if (len == 0) {
			printf("DEBUG: Run: read zero bytes from %u\n", ntohs(addr.sin_port));
			continue;
		}

		if (0 == memcmp(buf, "DSRP", 4)) {
			//printf("read %d bytes from MMDVMHost\n", (int)len);
			if (ProcessMMDVM(len, buf))
				break;
		} else if (0 == ::memcmp(buf, "DSTR", 4)) {
			//printf("read %d bytes from MMDVMHost\n", (int)len);
			if (ProcessGateway(len, buf))
				break;
		} else {
			char title[5];
			for (int i=0; i<4; i++)
				title[i] = (buf[i]>=0x20u && buf[i]<0x7fu) ? buf[i] : '.';
			title[4] = '\0';
			printf("DEBUG: Run: received unknow packet '%s' len=%d\n", title, (int)len);
		}
	}

	::close(msock);
	::close(gsock);
}

int CQnetRelay::SendTo(const int fd, const unsigned char *buf, const int size, const std::string &address, const unsigned short port)
{
	sockaddr_in addr;
	::memset(&addr, 0, sizeof(sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = ::inet_addr(address.c_str());
	addr.sin_port = htons(port);

	int len = ::sendto(fd, buf, size, 0, (sockaddr *)&addr, sizeof(sockaddr_in));
	if (len < 0)
		printf("ERROR: SendTo: fd=%d failed sendto %s:%u err: %d, %s\n", fd, address.c_str(), port, errno, strerror(errno));
	else if (len != size)
		printf("ERROR: SendTo: fd=%d tried to sendto %s:%u %d bytes, actually sent %d.\n", fd, address.c_str(), port, size, len);
	return len;
}

bool CQnetRelay::ProcessGateway(const int len, const unsigned char *raw)
{
	if (29==len || 58==len) { //here is dstar data
		SPKT buf;
		::memcpy(buf.pkt_id, raw, len);	// transfer raw data to SPKT struct

		SMMDVMPKT pkt;	// destination
		// fill in some inital stuff
		::memcpy(pkt.title, "DSRP", 4);
		pkt.voice.id = buf.vpkt.streamid;
		pkt.voice.seq = buf.vpkt.ctrl;
		if (29 == len) {	// write an AMBE packet
			pkt.tag = 0x21U;
			if (pkt.voice.seq & 0x40)
//				printf("INFO: ProcessGateway: sending voice end-of-stream\n");
				;
			else if (pkt.voice.seq > 20)
				printf("DEBUG: ProcessGateway: unexpected voice sequence number %d\n", pkt.voice.seq);
			pkt.voice.err = 0;	// NOT SURE WHERE TO GET THIS FROM THE INPUT buf
			memcpy(pkt.voice.ambe, buf.vpkt.vasd.voice, 12);
			int ret = SendTo(msock, pkt.title, 21, MMDVM_IP, MMDVM_IN_PORT);
			if (ret != 21) {
				printf("ERROR: ProcessGateway: Could not write AMBE mmdvm packet\n");
				return true;
			}
		} else {			// write a Header packet
			pkt.tag = 0x20U;
			pkt.header.id =  buf.vpkt.streamid;
			if (pkt.header.seq) {
//				printf("DEBUG: ProcessGateway: unexpected pkt.header.seq %d, resetting to 0\n", pkt.header.seq);
				pkt.header.seq = 0;
			}
			memcpy(pkt.header.flag, buf.vpkt.hdr.flag, 41);
			int ret = SendTo(msock, pkt.title, 49, MMDVM_IP, MMDVM_IN_PORT);
			if (ret != 49) {
				printf("ERROR: ProcessGateway: Could not write Header mmdvm packet\n");
				return true;
			}
			printf("INFO: ProcessGateway: sent header to port %u pkt = '%s'\n", MMDVM_IN_PORT, std::string((char *)pkt.header.r2, 36).c_str());
		}

	} else
		printf("DEBUG: ProcessGateway: unusual packet size read len=%d\n", len);
	return false;
}

bool CQnetRelay::ProcessMMDVM(const int len, const unsigned char *raw)
{
	static short old_id = 0U;
	static short stream_id = 0U;
	SMMDVMPKT mpkt;
	if (len < 65)
		::memcpy(mpkt.title, raw, len);	// transfer raw data to SMMDVMPKT struct

	if (49==len || 21==len) {
		// grab the stream id if this is a header
		if (49 == len) {
			stream_id = mpkt.header.id;
			if (old_id == stream_id)
				return false;
			old_id = stream_id;
		}

		SPKT gpkt;	// destination
		// sets most of the params
		::memcpy(gpkt.pkt_id, "DSTR", 4);
		gpkt.counter = COUNTER++;
		gpkt.flag[0] = 0x73;
		gpkt.flag[1] = 0x12;
		gpkt.flag[2] = 0x0;
		gpkt.vpkt.icm_id = 0x20;
		gpkt.vpkt.dst_rptr_id = 0x0;
		gpkt.vpkt.snd_rptr_id = 0x1;
		gpkt.vpkt.snd_term_id = ('B'==RPTR_MOD) ? 0x1 : (('C'==RPTR_MOD) ? 0x2 : 0x3);
		gpkt.vpkt.streamid = stream_id;

		if (49 == len) {	// header
			gpkt.remaining = 0x30;
			gpkt.vpkt.ctrl = 0x80;
			::memcpy(gpkt.vpkt.hdr.flag, mpkt.header.flag, 41);
			int ret = SendTo(msock, gpkt.pkt_id, 58, G2_INTERNAL_IP, G2_IN_PORT);
			if (ret != 58) {
				printf("ERROR: ProcessMMDVM: Could not write gateway header packet\n");
				return true;
			}
			printf("INFO: ProcessMMDVM: sent header to port %u pkt = '%s'\n", G2_IN_PORT, std::string((char *)gpkt.vpkt.hdr.rpt1, 36).c_str());
		} else if (21 == len) {	// ambe
			gpkt.remaining = 0x16;
			gpkt.vpkt.ctrl = mpkt.header.seq;
			::memcpy(gpkt.vpkt.vasd.voice, mpkt.voice.ambe, 12);
			int ret = SendTo(msock, gpkt.pkt_id, 29, G2_INTERNAL_IP, G2_IN_PORT);
			if (ret != 29) {
				printf("ERROR: ProcessMMDVM: Could not write gateway voice packet\n");
				return true;
			}
		}
	} else if (len < 65 && mpkt.tag == 0xAU) {
//		printf("MMDVM Poll: '%s'\n", (char *)mpkt.poll_msg);
	} else
		printf("DEBUG: ProcessMMDVM: unusual packet len=%d\n", len);
	return false;
}

bool CQnetRelay::GetValue(const Config &cfg, const char *path, int &value, const int min, const int max, const int default_value)
{
	if (cfg.lookupValue(path, value)) {
		if (value < min || value > max)
			value = default_value;
	} else
		value = default_value;
	printf("%s = [%d]\n", path, value);
	return true;
}

bool CQnetRelay::GetValue(const Config &cfg, const char *path, double &value, const double min, const double max, const double default_value)
{
	if (cfg.lookupValue(path, value)) {
		if (value < min || value > max)
			value = default_value;
	} else
		value = default_value;
	printf("%s = [%lg]\n", path, value);
	return true;
}

bool CQnetRelay::GetValue(const Config &cfg, const char *path, bool &value, const bool default_value)
{
	if (! cfg.lookupValue(path, value))
		value = default_value;
	printf("%s = [%s]\n", path, value ? "true" : "false");
	return true;
}

bool CQnetRelay::GetValue(const Config &cfg, const char *path, std::string &value, int min, int max, const char *default_value)
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
bool CQnetRelay::ReadConfig(const char *cfgFile)
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
	int repeater_module = i;

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

	GetValue(cfg, "gateway.internal.port", i, 10000, 65535, 19000);
	G2_IN_PORT = (unsigned short)i;

	GetValue(cfg, std::string(mmdvm_path+".port").c_str(), i, 10000, 65535, 19998+repeater_module);
	G2_OUT_PORT = (unsigned short)i;

	GetValue(cfg, "mmdvm.local_port", i, 10000, 65535, 20011);
	MMDVM_IN_PORT = (unsigned short)i;

	GetValue(cfg, "mmdvm.gateway_port", i, 10000, 65535, 20010);
	MMDVM_OUT_PORT = (unsigned short)i;

	if (GetValue(cfg, "gateway.ip", value, 7, IP_SIZE, "127.0.0.1")) {
		G2_INTERNAL_IP = value;
	} else
		return true;

	GetValue(cfg, "timing.play.delay", DELAY_BETWEEN, 9, 25, 19);

	GetValue(cfg, "timing.play.wait", DELAY_BEFORE, 1, 10, 2);

	GetValue(cfg, std::string(mmdvm_path+".packet_wait").c_str(), WAIT_FOR_PACKETS, 6, 100, 25);

	return false;
}

void CQnetRelay::SignalCatch(const int signum)
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

	CQnetRelay qnmmdvm;

	qnmmdvm.Run(argv[1]);

	printf("%s is closing.\n", argv[0]);

	return 0;
}
