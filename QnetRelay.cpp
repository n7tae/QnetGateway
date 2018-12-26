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
#include "QnetConfigure.h"

std::atomic<bool> CQnetRelay::keep_running(true);

CQnetRelay::CQnetRelay(int mod) :
assigned_module(mod),
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

bool CQnetRelay::Run(const char *cfgfile)
{
	if (Initialize(cfgfile))
		return true;

	msock = OpenSocket(MMDVM_IP, MMDVM_OUT_PORT);
	if (msock < 0)
		return true;

	if (Gate2Modem.Open(gate2modem.c_str()) || Modem2Gate.Open(modem2gate.c_str()))
		return true;

	int fd = Gate2Modem.GetFD();

	printf("msock=%d, gateway=%d\n", msock, fd);

	keep_running = true;

	while (keep_running) {
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(msock, &readfds);
		FD_SET(fd, &readfds);
		int maxfs = (msock > fd) ? msock : fd;

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
				fprintf(stderr, "ERROR: Run: recvfrom(mmdvm) return error %d: %s\n", errno, strerror(errno));
				break;
			}

			if (ntohs(addr.sin_port) != MMDVM_IN_PORT)
				fprintf(stderr, "DEBUG: Run: read from msock but port was %u, expected %u.\n", ntohs(addr.sin_port), MMDVM_IN_PORT);

		}

		if (FD_ISSET(fd, &readfds)) {
			len = Gate2Modem.Read(buf, 100);

			if (len < 0) {
				fprintf(stderr, "ERROR: Run: Gate2Modem.Read() returned error %d: %s\n", errno, strerror(errno));
				break;
			}
		}

		if (len == 0) {
			fprintf(stderr, "DEBUG: Run: read zero bytes from %u\n", ntohs(addr.sin_port));
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
			fprintf(stderr, "DEBUG: Run: received unknow packet '%s' len=%d\n", title, (int)len);
		}
	}

	::close(msock);
	Gate2Modem.Close();
	Modem2Gate.Close();
	return false;
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
		SDSTR dstr;
		::memcpy(dstr.pkt_id, raw, len);	// transfer raw data to SDSTR struct

		SDSRP dsrp;	// destination
		// fill in some inital stuff
		::memcpy(dsrp.title, "DSRP", 4);
		dsrp.voice.id = dstr.vpkt.streamid;	// voice or header is the same position
		dsrp.voice.seq = dstr.vpkt.ctrl;	// ditto
		if (29 == len) {	// write an AMBE packet
			dsrp.tag = 0x21U;
			if (log_qso && (dsrp.voice.seq & 0x40))
				printf("Sent DSRP end of streamid=%04x\n", ntohs(dsrp.voice.id));
			if ((dsrp.voice.seq & ~0x40U) > 20)
				printf("DEBUG: ProcessGateway: unexpected voice sequence number %d\n", dsrp.voice.seq);
			dsrp.voice.err = 0;	// NOT SURE WHERE TO GET THIS FROM THE INPUT buf
			memcpy(dsrp.voice.ambe, dstr.vpkt.vasd.voice, 12);
			int ret = SendTo(msock, dsrp.title, 21, MMDVM_IP, MMDVM_IN_PORT);
			if (ret != 21) {
				printf("ERROR: ProcessGateway: Could not write AMBE mmdvm packet\n");
				return true;
			}
		} else {			// write a Header packet
			dsrp.tag = 0x20U;
			if (dsrp.header.seq) {
//				printf("DEBUG: ProcessGateway: unexpected pkt.header.seq %d, resetting to 0\n", pkt.header.seq);
				dsrp.header.seq = 0;
			}
			//memcpy(dsrp.header.flag, dstr.vpkt.hdr.flag, 41);
			memcpy(dsrp.header.flag, dstr.vpkt.hdr.flag, 3);
			memcpy(dsrp.header.r1,   dstr.vpkt.hdr.r1,   8);
			memcpy(dsrp.header.r2,   dstr.vpkt.hdr.r2,   8);
			memcpy(dsrp.header.ur,   dstr.vpkt.hdr.ur,   8);
			memcpy(dsrp.header.my,   dstr.vpkt.hdr.my,   8);
			memcpy(dsrp.header.nm,   dstr.vpkt.hdr.nm,   4);
			memcpy(dsrp.header.pfcs, dstr.vpkt.hdr.pfcs, 2);
			int ret = SendTo(msock, dsrp.title, 49, MMDVM_IP, MMDVM_IN_PORT);
			if (ret != 49) {
				printf("ERROR: ProcessGateway: Could not write Header mmdvm packet\n");
				return true;
			}
			if (log_qso)
				printf("Sent DSRP to %u, streamid=%04x ur=%.8s r1=%.8s r2=%.8s my=%.8s/%.4s\n", MMDVM_IN_PORT, ntohs(dsrp.header.id), dsrp.header.ur, dsrp.header.r2, dsrp.header.r1, dsrp.header.my, dsrp.header.nm);
		}

	} else
		printf("DEBUG: ProcessGateway: unusual packet size read len=%d\n", len);
	return false;
}

bool CQnetRelay::ProcessMMDVM(const int len, const unsigned char *raw)
{
	static short old_id = 0U;
	static short stream_id = 0U;
	SDSRP dsrp;
	if (len < 65)
		::memcpy(dsrp.title, raw, len);	// transfer raw data to SDSRP struct

	if (49==len || 21==len) {
		// grab the stream id if this is a header
		if (49 == len) {
			stream_id = dsrp.header.id;
			if (old_id == stream_id)
				return false;
			old_id = stream_id;
		}

		SDSTR dstr;	// destination
		// sets most of the params
		::memcpy(dstr.pkt_id, "DSTR", 4);
		dstr.counter = htons(COUNTER++);
		dstr.flag[0] = 0x73;
		dstr.flag[1] = 0x12;
		dstr.flag[2] = 0x0;
		dstr.vpkt.icm_id = 0x20;
		dstr.vpkt.dst_rptr_id = 0x0;
		dstr.vpkt.snd_rptr_id = 0x1;
		dstr.vpkt.snd_term_id = ('B'==RPTR_MOD) ? 0x1 : (('C'==RPTR_MOD) ? 0x2 : 0x3);
		dstr.vpkt.streamid = stream_id;

		if (49 == len) {	// header
			dstr.remaining = 0x30;
			dstr.vpkt.ctrl = 0x80;
			//memcpy(dstr.vpkt.hdr.flag, dsrp.header.flag, 41);
			memcpy(dstr.vpkt.hdr.flag, dsrp.header.flag, 3);
			memcpy(dstr.vpkt.hdr.r1,   dsrp.header.r1,   8);
			memcpy(dstr.vpkt.hdr.r2,   dsrp.header.r2,   8);
			memcpy(dstr.vpkt.hdr.ur,   dsrp.header.ur,   8);
			memcpy(dstr.vpkt.hdr.my,   dsrp.header.my,   8);
			memcpy(dstr.vpkt.hdr.nm,   dsrp.header.nm,   4);
			memcpy(dstr.vpkt.hdr.pfcs, dsrp.header.pfcs, 2);
			int ret = Modem2Gate.Write(dstr.pkt_id, 58);
			if (ret != 58) {
				printf("ERROR: ProcessMMDVM: Could not write gateway header packet\n");
				return true;
			}
			if (log_qso)
				printf("Sent DSTR streamid=%04x ur=%.8s r1=%.8s r2=%.8s my=%.8s/%.4s\n", ntohs(dstr.vpkt.streamid), dstr.vpkt.hdr.ur, dstr.vpkt.hdr.r1, dstr.vpkt.hdr.r2, dstr.vpkt.hdr.my, dstr.vpkt.hdr.nm);
		} else if (21 == len) {	// ambe
			dstr.remaining = 0x16;
			dstr.vpkt.ctrl = dsrp.header.seq;
			memcpy(dstr.vpkt.vasd.voice, dsrp.voice.ambe, 12);
			int ret = Modem2Gate.Write(dstr.pkt_id, 29);
			if (log_qso && dstr.vpkt.ctrl&0x40)
				printf("Sent DSTR end of streamid=%04x\n", ntohs(dstr.vpkt.streamid));

			if (ret != 29) {
				printf("ERROR: ProcessMMDVM: Could not write gateway voice packet\n");
				return true;
			}
		}
	} else if (len < 65 && dsrp.tag == 0xAU) {
//		printf("MMDVM Poll: '%s'\n", (char *)mpkt.poll_msg);
	} else
		printf("DEBUG: ProcessMMDVM: unusual packet len=%d\n", len);
	return false;
}

// process configuration file and return true if there was a problem
bool CQnetRelay::ReadConfig(const char *cfgFile)
{
	CQnetConfigure cfg;
	printf("Reading file %s\n", cfgFile);
	if (cfg.Initialize(cfgFile))
		return true;

	const std::string estr;	// an empty GetDefaultString
	std::string type;
	std::string mmdvm_path("module_");
	mmdvm_path.append(1, 'a' + assigned_module);
	if (cfg.KeyExists(mmdvm_path)) {
		cfg.GetValue(mmdvm_path, estr, type, 1, 16);
		if (type.compare("mmdvm")) {
			fprintf(stderr, "%s = %s is not 'mmdvm' type!\n", mmdvm_path.c_str(), type.c_str());
			return true;
		}
	} else {
		fprintf(stderr, "Module '%c' is not defined.\n", 'a'+assigned_module);
		return true;
	}
	RPTR_MOD = 'A' + assigned_module;

	cfg.GetValue(mmdvm_path+"_gate2modem"+std::to_string(assigned_module), type, gate2modem, 1, FILENAME_MAX);
	cfg.GetValue(mmdvm_path+"_modem2gate"+std::to_string(assigned_module), type, modem2gate, 1, FILENAME_MAX);
	cfg.GetValue(mmdvm_path+"_internal_ip", type, MMDVM_IP, 7, IP_SIZE);
	int i;
	cfg.GetValue(mmdvm_path+"_local_port", type, i, 10000, 65535);
	MMDVM_IN_PORT = (unsigned short)i;
	cfg.GetValue(mmdvm_path+"+gateway_port", type, i, 10000, 65535);
	MMDVM_OUT_PORT = (unsigned short)i;

	cfg.GetValue("log.qso", estr, log_qso);

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
	if (3 != argc) {
		fprintf(stderr, "usage: %s assigned_module path_to_config_file\n", argv[0]);
		return 1;
	} else {
		printf("\nQnetRelay Version #%s Copyright (C) 2018 by Thomas A. Early N7TAE\n", RELAY_VERSION);
		printf("QnetRelay comes with ABSOLUTELY NO WARRANTY; see the LICENSE for details.\n");
		printf("This is free software, and you are welcome to distribute it\nunder certain conditions that are discussed in the LICENSE file.\n\n");
		return 0;
	}

	int module;
	switch (argv[1][0]) {
		case '0':
		case 'a':
		case 'A':
			module = 0;
			break;
		case '1':
		case 'b':
		case 'B':
			module = 1;
			break;
		case '2':
		case 'c':
		case 'C':
			module = 2;
			break;
		default:
			fprintf(stderr, "assigned module must be 0, a, A, 1, b, B, 2, c or C\n");
			return 1;
	}

	CQnetRelay qnmmdvm(module);

	bool trouble = qnmmdvm.Run(argv[2]);

	printf("%s is closing.\n", argv[0]);

	return trouble ? 1 : 0;
}
