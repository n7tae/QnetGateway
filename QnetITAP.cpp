/*
 *   Copyright (C) 2018 by Thomas A. Early N7TAE
 *   Copyright (C) 2011-2015,2018 by Jonathan Naylor G4KLX
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
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <termios.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <thread>
#include <chrono>

#include "versions.h"
#include "QnetITAP.h"
#include "QnetTypeDefs.h"

std::atomic<bool> CQnetITAP::keep_running(true);

CQnetITAP::CQnetITAP() :
COUNTER(0)
{
}

CQnetITAP::~CQnetITAP()
{
}

bool CQnetITAP::Initialize(const char *cfgfile)
{
	if (ReadConfig(cfgfile))
		return true;

	struct sigaction act;
	act.sa_handler = &CQnetITAP::SignalCatch;
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

int CQnetITAP::OpenITAP()
{
	int fd = open(ITAP_DEVICE.c_str(), O_RDWR | O_NOCTTY | O_NDELAY, 0);
	if (fd < 0) {
		printf("Failed to open device [%s], error=%d, message=%s\n", ITAP_DEVICE.c_str(), errno, strerror(errno));
		return -1;
	}

	if (isatty(fd) == 0) {
		printf("Device %s is not a tty device\n", ITAP_DEVICE.c_str());
		close(fd);
		return -1;
	}

	static termios t;
	if (tcgetattr(fd, &t) < 0) {
		printf("tcgetattr failed for %s, error=%d, message-%s\n", ITAP_DEVICE.c_str(), errno, strerror(errno));
		close(fd);
		return -1;
	}

	t.c_lflag    &= ~(ECHO | ECHOE | ICANON | IEXTEN | ISIG);
	t.c_iflag    &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON | IXOFF | IXANY);
	t.c_cflag    &= ~(CSIZE | CSTOPB | PARENB | CRTSCTS);
	t.c_cflag    |= CS8;
	t.c_oflag    &= ~(OPOST);
	t.c_cc[VMIN]  = 0;
	t.c_cc[VTIME] = 10;

	cfsetospeed(&t, B38400);
	cfsetispeed(&t, B38400);

	if (tcsetattr(fd, TCSANOW, &t) < 0) {
		printf("tcsetattr failed for %s, error=%dm message=%s\n", ITAP_DEVICE.c_str(), errno, strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

int CQnetITAP::OpenSocket(const std::string &address, const unsigned short port)
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

REPLY_TYPE CQnetITAP::GetITAPData(unsigned char *buf)
{
	// Shamelessly adapted from Jonathan G4KLX's CIcomController::GetResponse()
	// and CSerialController::read()
	// Get the start of the frame or nothing at all
	int ret = ::read(serfd, buf, 1U);
	if (ret < 0) {
		printf("Error when reading first byte from the Icom radio %d: %s", errno, strerror(errno));
		return RT_ERROR;
	}

	if (ret == 0)
		return RT_TIMEOUT;

	if (buf[0U] == 0xFFU)
		return RT_TIMEOUT;

	unsigned int length = buf[0U];

	if (length >= 100U) {
		printf("Invalid data received from the Icom radio, length=%d\n", length);
		return RT_ERROR;
	}

	unsigned int offset = 1U;

	while (offset < length) {
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(serfd, &fds);
		int n = ::select(serfd+1, &fds, NULL, NULL, NULL);	// wait untill it's ready. won't return a zero.
		if (n < 0) {
			printf("ERROR: GetITAPData: select returned error %d: %s\n", errno, strerror(errno));
			return RT_ERROR;
		}

		ret = ::read(serfd, buf + offset, length - offset);
		if (ret < 0 && errno!=EAGAIN) {
			printf("Error when reading buffer from the Icom radio %d: %s\n", errno, strerror(errno));
			return RT_ERROR;
		}

		if (ret > 0)
			offset += ret;
	}

	switch (buf[1U]) {
		case 0x03U:
			return RT_PONG;
		case 0x10U:
			return RT_HEADER;
		case 0x12U:
			return RT_DATA;
		case 0x21U:
			return RT_HEADER_ACK;
		case 0x23U:
			return RT_DATA_ACK;
		default:
			return RT_UNKNOWN;
	}
}

void CQnetITAP::Run(const char *cfgfile)
{
	if (Initialize(cfgfile))
		return;

	serfd = OpenITAP();
	if (serfd < 0)
		return;

	gsock = OpenSocket(G2_INTERNAL_IP, G2_OUT_PORT);
	if (gsock < 0) {
		::close(serfd);
		return;
	}

	vsock = OpenSocket(std::string("0.0.0.0"), MMDVM_OUT_PORT);
	if (vsock < 0) {
		::close(serfd);
		::close(gsock);
		return;
	}

	printf("vsock=%d, gsock=%d serfd=%d\n", vsock, gsock, serfd);

	keep_running = true;
	unsigned poll_counter = 0;
	bool is_alive = false;

	while (keep_running) {
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(serfd, &readfds);
		FD_SET(gsock, &readfds);
		int maxfs = (serfd > gsock) ? serfd : gsock;

		struct timeval tv;
		tv.tv_sec = (poll_counter >= 18) ? 1 : 0;
		tv.tv_usec = (poll_counter >= 18) ? 0 : 100000;

		// don't care about writefds and exceptfds:
		// and we'll wait for 100 ms or 1 s, depending on ;
		int ret = ::select(maxfs+1, &readfds, NULL, NULL, &tv);
		if (ret < 0) {
			printf("ERROR: Run: select returned err=%d, %s\n", errno, strerror(errno));
			break;
		}

		if (0 == ret) {
			// nothing to read, so do the polling or pinging
			unsigned char buf[3];
			if (poll_counter++ < 18) {
				unsigned char poll[3] = { 0xffu, 0xffu, 0xffu };
				::memcpy(buf, poll, 3);
			} else {
				unsigned char ping[3] = { 0x02u, 0x02u, 0xffu };
				::memcpy(buf, ping, 3);
			}
			SendTo((unsigned char)0x03U, buf);
			continue;
		}

		// there is something to read!
		unsigned char buf[100];
		ssize_t len;
		REPLY_TYPE rt = RT_NOTHING;

		if (FD_ISSET(serfd, &readfds)) {
			rt = GetITAPData(buf);

			if (rt == RT_ERROR)
				break;

			if (rt == RT_TIMEOUT)
				continue;

		} else if (FD_ISSET(gsock, &readfds)) {
			sockaddr_in addr;
			memset(&addr, 0, sizeof(sockaddr_in));
			socklen_t size = sizeof(sockaddr);
			len = ::recvfrom(gsock, buf, 100, 0, (sockaddr *)&addr, &size);

			if (len < 0) {
				printf("ERROR: Run: recvfrom(gsock) returned error %d, %s\n", errno, strerror(errno));
				break;
			}

			if (ntohs(addr.sin_port) != G2_IN_PORT)
				printf("DEBUG: Run: read from gsock but the port was %u, expected %u\n", ntohs(addr.sin_port), G2_IN_PORT);

		}

		if (rt != RT_NOTHING) {
			//printf("read %d bytes from ITAP\n", (int)buf[0]);
			if (RT_DATA==rt || RT_HEADER==rt) {
				if (ProcessITAP(buf))
					break;
			} else {
				switch (rt) {
					//case RT_HEADER_ACK:
					//	printf("DEBUG: Run: got header acknowledgement\n");
					//	break;
					//case RT_DATA_ACK:
					//	printf("DEBUG: Run: got data   acknowledgement\n");
					//	break;
					case RT_PONG:
						if (! is_alive) {
							printf("Icom Radio is connected.\n");
							is_alive = true;
						}
						break;
					case RT_TIMEOUT:
						printf("DEBUG: Run: got a timeout.\n");
						break;
					default:
						break;
				}
			}
		} else if (0 == ::memcmp(buf, "DSTR", 4)) {
			//printf("read %d bytes from QnetGateway\n", (int)len);
			if (ProcessGateway(len, buf))
				break;
		}
	}

	::close(serfd);
	::close(gsock);
	::close(vsock);
}

int CQnetITAP::SendTo(const unsigned char length, const unsigned char *buf)
{
	unsigned int ptr = 0;
	const unsigned int len = (int)length;

	while (ptr < len) {
		ssize_t n = ::write(serfd, buf + ptr, len - ptr);
		if (n < 0) {
			if (EAGAIN != errno) {
				printf("Error %d writing to dvap, message=%s\n", errno, strerror(errno));
				return -1;
			}
		}

		if (n > 0)
			ptr += n;
	}

	return len;
}

int CQnetITAP::SendTo(const int fd, const unsigned char *buf, const int size, const std::string &address, const unsigned short port)
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

bool CQnetITAP::ProcessGateway(const int len, const unsigned char *raw)
{
	static unsigned char counter = 0;
	if (29==len || 58==len) { //here is dstar data
		SDSTR dstr;
		::memcpy(dstr.pkt_id, raw, len);	// transfer raw data to SDSTR struct

		SITAP itap;	// destination
		if (58 == len) {			// write a Header packet
			counter = 0;
			itap.length = 41U;
			itap.type = 0x20;
			memcpy(itap.header.flag, dstr.vpkt.hdr.flag, 3);
			memcpy(itap.header.r1,   dstr.vpkt.hdr.r1,   8);
			memcpy(itap.header.r2,   dstr.vpkt.hdr.r2,   8);
			memcpy(itap.header.ur,   dstr.vpkt.hdr.ur,   8);
			memcpy(itap.header.my,   dstr.vpkt.hdr.my,   8);
			memcpy(itap.header.nm,   dstr.vpkt.hdr.nm,   4);
			itap.header.end = 0xFFU;
			if (42 != SendTo(42U, &itap.length)) {
				printf("ERROR: ProcessGateway: Could not write Header ITAP packet\n");
				return true;
			}
			if (log_qso)
				printf("Sent ITAP to %s ur=%.8s r1=%.8s r2=%.8s my=%.8s/%.4s\n", ITAP_DEVICE.c_str(),
						itap.header.ur, itap.header.r1, itap.header.r2, itap.header.my, itap.header.nm);
		} else {	// write an AMBE packet
			itap.length = 16U;
			itap.type = 0x22U;
			itap.voice.counter = counter++;
			itap.voice.sequence = dstr.vpkt.ctrl;
			if (log_qso && dstr.vpkt.ctrl&0x40)
				printf("Sent ITAP end of stream\n");
			else if (dstr.vpkt.ctrl > 20)
				printf("DEBUG: ProcessGateway: unexpected voice sequence number %d\n", itap.voice.sequence);
			memcpy(itap.voice.ambe, dstr.vpkt.vasd.voice, 12);
			itap.voice.end = 0xFFU;
			if (17 != SendTo(17U, &itap.length)) {
				printf("ERROR: ProcessGateway: Could not write AMBE ITAP packet\n");
				return true;
			}
		}

	} else
		printf("DEBUG: ProcessGateway: unusual packet size read len=%d\n", len);
	return false;
}

bool CQnetITAP::ProcessITAP(const unsigned char *buf)
{
	static short stream_id = 0U;
	SITAP itap;
	unsigned int len = (0x10U == buf[1]) ? 41 : 16;
	::memcpy(&itap.length, buf, len);	// transfer raw data to SITAP struct

	// create a stream id if this is a header
	if (41 == len)
		stream_id = random.NewStreamID();

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
	dstr.vpkt.streamid = htons(stream_id);

	if (41 == len) {	// header
		dstr.remaining = 0x30;
		dstr.vpkt.ctrl = 0x80;


		memcpy(dstr.vpkt.hdr.flag, itap.header.flag, 3);
		if (0 == memcmp(itap.header.r1, "DIRECT", 6)) {
			// Terminal Mode!
			memcpy(dstr.vpkt.hdr.r1, RPTR, 7);	// build r1
			dstr.vpkt.hdr.r1[7] = RPTR_MOD;		// with module
			memcpy(dstr.vpkt.hdr.r2, RPTR, 7);	// build r1
			dstr.vpkt.hdr.r2[7] = 'G';			// with gateway
			if (' ' == itap.header.ur[2]) {
				// it's command, we have to right-shift it!
				memset(dstr.vpkt.hdr.ur, ' ', 8);	// first file ur with spaces
				if (' ' == itap.header.ur[1])
					dstr.vpkt.hdr.ur[7] = itap.header.ur[0];		// one char command, like "E" or "I"
				else
					memcpy(dstr.vpkt.hdr.ur+6, itap.header.ur, 2);	// two char command, like "HX" or "S0"
			} else
				memcpy(dstr.vpkt.hdr.ur,   itap.header.ur,   8);	// ur is at least 3 chars
		} else {
			// Access Point Mode
			memcpy(dstr.vpkt.hdr.r1,   itap.header.r1,   8);
			memcpy(dstr.vpkt.hdr.r2,   itap.header.r2,   8);
			memcpy(dstr.vpkt.hdr.ur,   itap.header.ur,   8);	// ur is at least 3 chars
		}
		memcpy(dstr.vpkt.hdr.my,   itap.header.my,   8);
		memcpy(dstr.vpkt.hdr.nm,   itap.header.nm,   4);
		calcPFCS(dstr.vpkt.hdr.flag, dstr.vpkt.hdr.pfcs);
		int ret = SendTo(vsock, dstr.pkt_id, 58, G2_INTERNAL_IP, G2_IN_PORT);
		if (ret != 58) {
			printf("ERROR: ProcessITAP: Could not write gateway header packet\n");
			return true;
		}
		if (log_qso)
			printf("Sent DSTR to %u, streamid=%04x ur=%.8s r1=%.8s r2=%.8s my=%.8s/%.4s\n", G2_IN_PORT, ntohs(dstr.vpkt.streamid),
					dstr.vpkt.hdr.ur, dstr.vpkt.hdr.r1, dstr.vpkt.hdr.r2, dstr.vpkt.hdr.my, dstr.vpkt.hdr.nm);
	} else if (16 == len) {	// ambe
		dstr.remaining = 0x16;
		dstr.vpkt.ctrl = itap.voice.sequence;
		memcpy(dstr.vpkt.vasd.voice, itap.voice.ambe, 12);
		int ret = SendTo(vsock, dstr.pkt_id, 29, G2_INTERNAL_IP, G2_IN_PORT);
		if (ret != 29) {
			printf("ERROR: ProcessMMDVM: Could not write gateway voice packet\n");
			return true;
		}

		if (log_qso && (dstr.vpkt.ctrl & 0x40))
			printf("Sent dstr end of streamid=%04x\n", ntohs(dstr.vpkt.streamid));
	}

	return false;
}

bool CQnetITAP::GetValue(const Config &cfg, const char *path, int &value, const int min, const int max, const int default_value)
{
	if (cfg.lookupValue(path, value)) {
		if (value < min || value > max)
			value = default_value;
	} else
		value = default_value;
	printf("%s = [%d]\n", path, value);
	return true;
}

bool CQnetITAP::GetValue(const Config &cfg, const char *path, double &value, const double min, const double max, const double default_value)
{
	if (cfg.lookupValue(path, value)) {
		if (value < min || value > max)
			value = default_value;
	} else
		value = default_value;
	printf("%s = [%lg]\n", path, value);
	return true;
}

bool CQnetITAP::GetValue(const Config &cfg, const char *path, bool &value, const bool default_value)
{
	if (! cfg.lookupValue(path, value))
		value = default_value;
	printf("%s = [%s]\n", path, value ? "true" : "false");
	return true;
}

bool CQnetITAP::GetValue(const Config &cfg, const char *path, std::string &value, int min, int max, const char *default_value)
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
bool CQnetITAP::ReadConfig(const char *cfgFile)
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

	std::string itap_path, value;
	int i;
	for (i=0; i<3; i++) {
		itap_path = "module.";
		itap_path += ('a' + i);
		if (cfg.lookupValue(itap_path + ".type", value)) {
			if (0 == strcasecmp(value.c_str(), "itap"))
				break;
		}
	}
	if (i >= 3) {
		printf("itap not defined in any module!\n");
		return true;
	}
	RPTR_MOD = 'A' + i;
	int repeater_module = i;
	MMDVM_OUT_PORT = (unsigned short int)(i + 19998);

	if (cfg.lookupValue(std::string(itap_path+".callsign").c_str(), value) || cfg.lookupValue("ircddb.login", value)) {
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
		printf("%s.login is not defined!\n", itap_path.c_str());
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

	if (GetValue(cfg, std::string(itap_path+".device").c_str(), value, 7, 25, "/dev/ttyUSB0")) {
		ITAP_DEVICE = value;
	} else
		return true;

	GetValue(cfg, "gateway.internal.port", i, 10000, 65535, 19000);
	G2_IN_PORT = (unsigned short)i;

	GetValue(cfg, std::string(itap_path+".port").c_str(), i, 10000, 65535, 19998+repeater_module);
	G2_OUT_PORT = (unsigned short)i;

	if (GetValue(cfg, "gateway.ip", value, 7, IP_SIZE, "127.0.0.1")) {
		G2_INTERNAL_IP = value;
	} else
		return true;

	GetValue(cfg, "log.qso", log_qso, false);

	return false;
}

void CQnetITAP::SignalCatch(const int signum)
{
	if ((signum == SIGTERM) || (signum == SIGINT)  || (signum == SIGHUP))
		keep_running = false;
	exit(0);
}

void CQnetITAP::calcPFCS(const unsigned char *packet, unsigned char *pfcs)
{
	unsigned short crc_dstar_ffff = 0xffff;
	unsigned short tmp, short_c;
	unsigned short crc_tabccitt[256] = {
		0x0000,0x1189,0x2312,0x329b,0x4624,0x57ad,0x6536,0x74bf,0x8c48,0x9dc1,0xaf5a,0xbed3,0xca6c,0xdbe5,0xe97e,0xf8f7,
		0x1081,0x0108,0x3393,0x221a,0x56a5,0x472c,0x75b7,0x643e,0x9cc9,0x8d40,0xbfdb,0xae52,0xdaed,0xcb64,0xf9ff,0xe876,
		0x2102,0x308b,0x0210,0x1399,0x6726,0x76af,0x4434,0x55bd,0xad4a,0xbcc3,0x8e58,0x9fd1,0xeb6e,0xfae7,0xc87c,0xd9f5,
		0x3183,0x200a,0x1291,0x0318,0x77a7,0x662e,0x54b5,0x453c,0xbdcb,0xac42,0x9ed9,0x8f50,0xfbef,0xea66,0xd8fd,0xc974,
		0x4204,0x538d,0x6116,0x709f,0x0420,0x15a9,0x2732,0x36bb,0xce4c,0xdfc5,0xed5e,0xfcd7,0x8868,0x99e1,0xab7a,0xbaf3,
		0x5285,0x430c,0x7197,0x601e,0x14a1,0x0528,0x37b3,0x263a,0xdecd,0xcf44,0xfddf,0xec56,0x98e9,0x8960,0xbbfb,0xaa72,
		0x6306,0x728f,0x4014,0x519d,0x2522,0x34ab,0x0630,0x17b9,0xef4e,0xfec7,0xcc5c,0xddd5,0xa96a,0xb8e3,0x8a78,0x9bf1,
		0x7387,0x620e,0x5095,0x411c,0x35a3,0x242a,0x16b1,0x0738,0xffcf,0xee46,0xdcdd,0xcd54,0xb9eb,0xa862,0x9af9,0x8b70,
		0x8408,0x9581,0xa71a,0xb693,0xc22c,0xd3a5,0xe13e,0xf0b7,0x0840,0x19c9,0x2b52,0x3adb,0x4e64,0x5fed,0x6d76,0x7cff,
		0x9489,0x8500,0xb79b,0xa612,0xd2ad,0xc324,0xf1bf,0xe036,0x18c1,0x0948,0x3bd3,0x2a5a,0x5ee5,0x4f6c,0x7df7,0x6c7e,
		0xa50a,0xb483,0x8618,0x9791,0xe32e,0xf2a7,0xc03c,0xd1b5,0x2942,0x38cb,0x0a50,0x1bd9,0x6f66,0x7eef,0x4c74,0x5dfd,
		0xb58b,0xa402,0x9699,0x8710,0xf3af,0xe226,0xd0bd,0xc134,0x39c3,0x284a,0x1ad1,0x0b58,0x7fe7,0x6e6e,0x5cf5,0x4d7c,
		0xc60c,0xd785,0xe51e,0xf497,0x8028,0x91a1,0xa33a,0xb2b3,0x4a44,0x5bcd,0x6956,0x78df,0x0c60,0x1de9,0x2f72,0x3efb,
		0xd68d,0xc704,0xf59f,0xe416,0x90a9,0x8120,0xb3bb,0xa232,0x5ac5,0x4b4c,0x79d7,0x685e,0x1ce1,0x0d68,0x3ff3,0x2e7a,
		0xe70e,0xf687,0xc41c,0xd595,0xa12a,0xb0a3,0x8238,0x93b1,0x6b46,0x7acf,0x4854,0x59dd,0x2d62,0x3ceb,0x0e70,0x1ff9,
		0xf78f,0xe606,0xd49d,0xc514,0xb1ab,0xa022,0x92b9,0x8330,0x7bc7,0x6a4e,0x58d5,0x495c,0x3de3,0x2c6a,0x1ef1,0x0f78
	};

	for (int i = 0; i < 39 ; i++) {
		short_c = 0x00ff & (unsigned short)packet[i];
		tmp = (crc_dstar_ffff & 0x00ff) ^ short_c;
		crc_dstar_ffff = (crc_dstar_ffff >> 8) ^ crc_tabccitt[tmp];
	}
	crc_dstar_ffff =  ~crc_dstar_ffff;
	tmp = crc_dstar_ffff;

	pfcs[0] = (unsigned char)(crc_dstar_ffff & 0xff);
	pfcs[1] = (unsigned char)((tmp >> 8) & 0xff);

	return;
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
		printf("\nQnetITAP Version #%s Copyright (C) 2018 by Thomas A. Early N7TAE\n", ITAP_VERSION);
		printf("QnetITAP comes with ABSOLUTELY NO WARRANTY; see the LICENSE for details.\n");
		printf("This is free software, and you are welcome to distribute it\nunder certain conditions that are discussed in the LICENSE file.\n\n");
		return 0;
	}

	CQnetITAP qnitap;

	qnitap.Run(argv[1]);

	printf("%s is closing.\n", argv[0]);

	return 0;
}
