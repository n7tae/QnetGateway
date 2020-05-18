/*
 *   Copyright (C) 2018-2020 by Thomas A. Early N7TAE
 *
 *   CQnetITAP::GetITAPData() is based on some code that is...
 *   Copyright (C) 2011-2015,2018,2020 by Jonathan Naylor G4KLX
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

#include "QnetITAP.h"
#include "QnetTypeDefs.h"
#include "QnetConfigure.h"
#include "Timer.h"

#define ITAP_VERSION "QnetITAP-518"

std::atomic<bool> CQnetITAP::keep_running(true);

CQnetITAP::CQnetITAP(int mod)
: assigned_module(mod)
{
}

CQnetITAP::~CQnetITAP()
{
}

bool CQnetITAP::Initialize(const char *cfgfile)
{
	if (ReadConfig(cfgfile))
		return true;

	std::signal(SIGTERM, CQnetITAP::SignalCatch);
	std::signal(SIGHUP,  CQnetITAP::SignalCatch);
	std::signal(SIGINT,  CQnetITAP::SignalCatch);

	Modem2Gate.SetUp(modem2gate.c_str());
	if (Gate2Modem.Open(gate2modem.c_str()))
		return true;

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

void CQnetITAP::DumpSerialPacket(const char *title, const unsigned char *buf)
{
	printf("%s: ", title);
	if (buf[0] > 41) {
		printf("UNKNOWN: length=%u", (unsigned)buf[0]);
		return;
	}
	SITAP itap;
	memcpy(&itap, buf, buf[0]);
	switch (itap.type) {
		case 0x03U:	//pong
			printf("Pong\n");
			break;
		case 0x10U: // header
		case 0x20U:
			printf("Header ur=%8.8s r1=%8.8s r2=%8.8s my=%8.8s/%4.4s", itap.header.ur, itap.header.r1, itap.header.r2, itap.header.my, itap.header.nm);
			break;
		case 0x12U: // data
		case 0x22U:
			printf("Data count=%u  seq=%u f=%02u%02u%02u a=%02u%02u%02u%02u%02u%02u%02u%02u%02u t=%02u%02u%02u\n", itap.voice.counter, itap.voice.sequence, itap.header.flag[0], itap.header.flag[1], itap.header.flag[2], itap.voice.ambe[0], itap.voice.ambe[1], itap.voice.ambe[2], itap.voice.ambe[3], itap.voice.ambe[4], itap.voice.ambe[5], itap.voice.ambe[6], itap.voice.ambe[7], itap.voice.ambe[8], itap.voice.text[0], itap.voice.text[1], itap.voice.text[2]);
			break;
		case 0x11U: // header acknowledgement
		case 0x21U:
			printf("Header acknowledgement code=%02u", itap.header.flag[0]);
			break;
		case 0x13U: // data acknowledgment
		case 0x23U:
			printf("Data acknowledgement seq=%02u code=%02u", itap.header.flag[0], itap.header.flag[1]);
			break;
		default:
			printf("UNKNOWN packet buf[0] = 0x%02u\n", buf[0]);
			break;
	}
}

REPLY_TYPE CQnetITAP::GetITAPData(unsigned char *buf)
{
	// Some methods adapted from Jonathan G4KLX's CIcomController::GetResponse()
	// and CSerialController::read()

	// Get the buffer size or nothing at all
	int ret = read(serfd, buf, 1U);
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

		ret = read(serfd, buf + offset, length - offset);
		if (ret<0 && errno!=EAGAIN) {
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

	int ug2m = Gate2Modem.GetFD();
	printf("gate2modem=%d, serial=%d\n", ug2m, serfd);

	keep_running = true;
	unsigned int poll_counter = 0;
	bool is_alive = false;
	acknowledged = true;
	CTimer ackTimer;
	CTimer lastdataTimer;
	CTimer pingTimer;
	double pingtime = 0.001;
	const double ackwait = AP_MODE ? 0.4 : 0.06;

	while (keep_running) {

		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(serfd, &readfds);
		FD_SET(ug2m, &readfds);
		int maxfs = (serfd > ug2m) ? serfd : ug2m;

		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 5000;

		// don't care about writefds and exceptfds:
		// and we'll wait for 5 ms
		int ret = select(maxfs+1, &readfds, NULL, NULL, &tv);
		if (ret < 0) {
			printf("ERROR: Run: select returned err=%d, %s\n", errno, strerror(errno));
			break;
		}

		// check for a dead or disconnected radio
		if (10.0 < lastdataTimer.time()) {
			printf("no activity from radio for 10 sec. Exiting...\n");
			break;
		}

		if (pingTimer.time() >= pingtime) {
			if (poll_counter < 18 ) {
				const unsigned char poll[2] = { 0xffu, 0xffu };
				SendTo(poll);
				if (poll_counter == 17)
					pingtime = 1.0;
			} else {
				const unsigned char ping[2] = { 0x02u, 0x02u };
				SendTo(ping);
			}
			poll_counter++;
			pingTimer.start();
		}

		unsigned char buf[100];

		if (keep_running && FD_ISSET(serfd, &readfds)) {	// there is something to read!
			switch (GetITAPData(buf)) {
				case RT_ERROR:
					keep_running = false;
					break;
				case RT_HEADER:
					{
						unsigned char ack_header[3] = { 0x03U, 0x11U, 0x0U };
						SendTo(ack_header);
					}
					if (ProcessITAP(buf))
						keep_running = false;
					lastdataTimer.start();
					break;
				case RT_DATA:
					{
						unsigned char ack_voice[4] = { 0x04U, 0x13U, 0x0U, 0x0U };
						ack_voice[2] = buf[2];
						SendTo(ack_voice);
					}
					if (ProcessITAP(buf))
						keep_running = false;
					lastdataTimer.start();
					break;
				case RT_PONG:
					if (! is_alive) {
						if (LOG_DEBUG) {
							auto count = queue.size();
							if (count)
								printf("%u packets in queue. Icom radio is connected.", (unsigned int)count);
						} else
							printf("Icom Radio is connected.\n");
						is_alive = true;
					}
					lastdataTimer.start();
					break;
				case RT_HEADER_ACK:
					if (acknowledged) {
						fprintf(stderr, "ERROR: Header already acknowledged!\n");
					} else {
						if (0x0U == buf[2])
							acknowledged = true;
					}
					lastdataTimer.start();
					break;
				case RT_DATA_ACK:
					if (acknowledged) {
						fprintf(stderr, "ERROR: voice frame %d already acknowledged!\n", (int)buf[2]);
					} else {
						if (0x0U == buf[3])
							acknowledged = true;
					}
					lastdataTimer.start();
					break;
				case RT_TIMEOUT:	// nothing or 0xff
					break;
				default:
					if (buf[0] != 255)
						DumpSerialPacket("GetITAPData returned", buf);
					break;
			}
			FD_CLR(serfd, &readfds);
		}

		if (keep_running && FD_ISSET(ug2m, &readfds)) {
			ssize_t len = Gate2Modem.Read(buf, 100);

			if (len < 0) {
				printf("ERROR: Run: recvfrom(gsock) returned error %d, %s\n", errno, strerror(errno));
				break;
			}

			if (0 == memcmp(buf, "DSVT", 4)) {
				//printf("read %d bytes from QnetGateway\n", (int)len);
				if (ProcessGateway(len, buf))
					break;
			}
			FD_CLR(ug2m, &readfds);
		}

		// send queued frames
		if (keep_running) {
			if (acknowledged) {
				if (is_alive) {
					if (! queue.empty()) {
						CFrame frame = queue.front();
						queue.pop();
						SendTo(frame.data());
						ackTimer.start();
						acknowledged = false;
					}
				}
			} else {	// we are waiting on an acknowledgement
				if (ackTimer.time() >= ackwait) {
					fprintf(stderr, "Icom failure suspected, restarting...\n");
					close(serfd);
					poll_counter = 0;
					pingtime = 0.001;
					is_alive = false;
					acknowledged = true;
					lastdataTimer.start();
					pingTimer.start();
					serfd = OpenITAP();
					if (serfd < 0) {
						keep_running = false;
					} else {
						while (! queue.empty())
							queue.pop();
					}
				}
			}
		}
	}

	close(serfd);
	Gate2Modem.Close();
}

int CQnetITAP::SendTo(const unsigned char *buf)
{
	ssize_t n;
	unsigned int ptr = 0;
	unsigned int length = (0xffu == buf[0]) ? 2 : buf[0];

	while (ptr < length) {
		n = write(serfd, buf + ptr, length - ptr);
		if (n < 0) {
			if (EAGAIN != errno) {
				printf("Error %d writing to dvap, message=%s\n", errno, strerror(errno));
				return -1;
			}
		}
		ptr += n;
	}

	n = 0;	// send an ending 0xffu
	while (0 == n) {
		const unsigned char push = 0xffu;
		n = write(serfd, &push, 1);
		if (n < 0) {
			if (EAGAIN != errno) {
				printf("Error %d writing to dvap, message=%s\n", errno, strerror(errno));
				return -1;
			}
		}
	}

	return length;
}

bool CQnetITAP::ProcessGateway(const int len, const unsigned char *raw)
{
	static unsigned char counter = 0;
	if (27==len || 56==len) { //here is dstar data
		SDSVT dsvt;
		memcpy(dsvt.title, raw, len);	// transfer raw data to SDSVT struct

		SITAP itap;	// destination
		if (56 == len) {			// write a Header packet
			counter = 0;
			itap.length = 41U;
			itap.type = 0x20;
			memcpy(itap.header.flag, dsvt.hdr.flag, 3);
			if (RPTR_MOD == dsvt.hdr.rpt2[7]) {
				memcpy(itap.header.r1, dsvt.hdr.rpt2, 8);
				memcpy(itap.header.r2, dsvt.hdr.rpt1, 8);
			} else {
				memcpy(itap.header.r1, dsvt.hdr.rpt1, 8);
				memcpy(itap.header.r2, dsvt.hdr.rpt2, 8);
			}
			memcpy(itap.header.ur, dsvt.hdr.urcall, 8);
			memcpy(itap.header.my, dsvt.hdr.mycall, 8);
			memcpy(itap.header.nm, dsvt.hdr.sfx,    4);
			if (LOG_QSO)
				printf("Queued ITAP to %s ur=%.8s r1=%.8s r2=%.8s my=%.8s/%.4s\n", ITAP_DEVICE.c_str(), itap.header.ur, itap.header.r1, itap.header.r2, itap.header.my, itap.header.nm);
		} else {	// write an AMBE packet
			itap.length = 16U;
			itap.type = 0x22U;
			itap.voice.counter = counter++;
			itap.voice.sequence = dsvt.ctrl;
			if (LOG_QSO && (dsvt.ctrl & 0x40))
				printf("Queued ITAP end of stream\n");
			if ((dsvt.ctrl & ~0x40U) > 20)
				printf("DEBUG: ProcessGateway: unexpected voice sequence number %d\n", itap.voice.sequence);
			memcpy(itap.voice.ambe, dsvt.vasd.voice, 12);
		}
		queue.push(CFrame(&itap.length));

	} else
		printf("DEBUG: ProcessGateway: unusual packet size read len=%d\n", len);
	return false;
}

bool CQnetITAP::ProcessITAP(const unsigned char *buf)
{
	static short stream_id = 0U;
	SITAP itap;
	unsigned int len = (0x10U == buf[1]) ? 41 : 16;
	memcpy(&itap.length, buf, len);	// transfer raw data to SITAP struct

	// create a stream id if this is a header
	if (41 == len)
		stream_id = random.NewStreamID();

	SDSVT dsvt;	// destination
	// sets most of the params
	memcpy(dsvt.title, "DSVT", 4);
	dsvt.config = (len==41) ? 0x10U : 0x20U;
	memset(dsvt.flaga, 0U, 3U);
	dsvt.id = 0x20;
	dsvt.flagb[0] = 0x0;
	dsvt.flagb[1] = 0x1;
	dsvt.flagb[2] = ('B'==RPTR_MOD) ? 0x1 : (('C'==RPTR_MOD) ? 0x2 : 0x3);
	dsvt.streamid = htons(stream_id);

	if (41 == len) {	// header
		dsvt.ctrl = 0x80;

		memcpy(dsvt.hdr.flag, itap.header.flag, 3);

		////////////////// Terminal or Access /////////////////////////
		if (0 == memcmp(itap.header.r1, "DIRECT", 6)) {
			// Terminal Mode!
			memcpy(dsvt.hdr.rpt1, RPTR.c_str(), 7);	// build r1
			dsvt.hdr.rpt1[7] = RPTR_MOD;			// with module
			memcpy(dsvt.hdr.rpt2, RPTR.c_str(), 7);	// build r2
			dsvt.hdr.rpt2[7] = 'G';					// with gateway
			if (' '==itap.header.ur[2] && ' '!=itap.header.ur[0]) {
				// it's a command because it has as space in the 3rd position, we have to right-justify it!
				// Terminal Mode left justifies short commands.
				memset(dsvt.hdr.urcall, ' ', 8);	// first file ur with spaces
				if (' ' == itap.header.ur[1])
					dsvt.hdr.urcall[7] = itap.header.ur[0];		// one char command, like "E" or "I"
				else
					memcpy(dsvt.hdr.urcall+6, itap.header.ur, 2);	// two char command, like "HX" or "S0"
			} else
				memcpy(dsvt.hdr.urcall, itap.header.ur, 8);	// ur is at least 3 chars
		} else {
			// Access Point Mode
			memcpy(dsvt.hdr.rpt1,   itap.header.r1,   8);
			memcpy(dsvt.hdr.rpt2,   itap.header.r2,   8);
			memcpy(dsvt.hdr.urcall, itap.header.ur,   8);
			dsvt.hdr.flag[0] &= ~0x40U;	// clear this bit
		}

		memcpy(dsvt.hdr.mycall, itap.header.my,   8);
		memcpy(dsvt.hdr.sfx,    itap.header.nm,   4);
		calcPFCS(dsvt.hdr.flag, dsvt.hdr.pfcs);
		if (56 != Modem2Gate.Write(dsvt.title, 56)) {
			printf("ERROR: ProcessITAP: Could not write gateway header packet\n");
			return true;
		}
		if (LOG_QSO)
			printf("Sent DSVT to gateway, streamid=%04x ur=%.8s r1=%.8s r2=%.8s my=%.8s/%.4s\n", ntohs(dsvt.streamid), dsvt.hdr.urcall, dsvt.hdr.rpt1, dsvt.hdr.rpt2, dsvt.hdr.mycall, dsvt.hdr.sfx);
	} else if (16 == len) {	// ambe
		dsvt.ctrl = itap.voice.sequence;
		memcpy(dsvt.vasd.voice, itap.voice.ambe, 12);
		if (27 != Modem2Gate.Write(dsvt.title, 27)) {
			printf("ERROR: ProcessMMDVM: Could not write gateway voice packet\n");
			return true;
		}

		if (LOG_QSO && (dsvt.ctrl & 0x40))
			printf("Sent dsvt end of streamid=%04x\n", ntohs(dsvt.streamid));
	}

	return false;
}

// process configuration file and return true if there was a problem
bool CQnetITAP::ReadConfig(const char *cfgFile)
{
	CQnetConfigure cfg;
	printf("Reading file %s\n", cfgFile);
	if (cfg.Initialize(cfgFile))
		return true;

	const std::string estr;	// an empty string
	std::string type;
	std::string itap_path("module_");
	if (0 > assigned_module) {
		// we need to find the lone itap module
		for (int i=0; i<3; i++) {
			std::string test(itap_path);
			test.append(1, 'a'+i);
			if (cfg.KeyExists(test)) {
				cfg.GetValue(test, estr, type, 1, 16);
				if (type.compare("itap"))
					continue;	// this ain't it!
				itap_path.assign(test);
				assigned_module = i;
				break;
			}
		}
		if (0 > assigned_module) {
			fprintf(stderr, "Error: no 'itap' module found\n!");
			return true;
		}
	} else {
		// make sure itap module is defined
		itap_path.append(1, 'a' + assigned_module);
		if (cfg.KeyExists(itap_path)) {
			cfg.GetValue(itap_path, estr, type, 1, 16);
			if (type.compare("itap")) {
				fprintf(stderr, "%s = %s is not 'itap' type!\n", itap_path.c_str(), type.c_str());
				return true;
			}
		} else {
			fprintf(stderr, "Module '%c' is not defined.\n", 'a'+assigned_module);
			return true;
		}
	}
	RPTR_MOD = 'A' + assigned_module;

	cfg.GetValue(itap_path+"_device", type, ITAP_DEVICE, 7, FILENAME_MAX);
	cfg.GetValue(itap_path+"_ap_mode", type, AP_MODE);

	itap_path.append("_callsign");
	if (cfg.KeyExists(itap_path)) {
		if (cfg.GetValue(itap_path, type, RPTR, 3, 6))
			return true;
	} else {
		itap_path.assign("ircddb_login");
		if (cfg.KeyExists(itap_path)) {
			if (cfg.GetValue(itap_path, estr, RPTR, 3, 6))
				return true;
		}
	}
	int l = RPTR.length();
	if (l<3 || l>6) {
		printf("Call '%s' is invalid length!\n", RPTR.c_str());
		return true;
	} else {
		for (int i=0; i<l; i++) {
			if (islower(RPTR[i]))
				RPTR[i] = toupper(RPTR[i]);
		}
		RPTR.resize(CALL_SIZE, ' ');
	}

	cfg.GetValue(std::string("gateway_gate2modem")+std::string(1, 'a'+assigned_module), estr, gate2modem, 1, FILENAME_MAX);
	cfg.GetValue("gateway_modem2gate", estr, modem2gate, 1, FILENAME_MAX);
	cfg.GetValue("log_qso", estr, LOG_QSO);
	cfg.GetValue("log_debug", estr, LOG_DEBUG);
	return false;
}

void CQnetITAP::SignalCatch(const int signum)
{
	if ((signum == SIGTERM) || (signum == SIGINT)  || (signum == SIGHUP))
		keep_running = false;
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
		fprintf(stderr, "usage: %s path_to_config_file\n", argv[0]);
		return 1;
	}

	if ('-' == argv[1][0]) {
		printf("\nQnetITAP Version #%s Copyright (C) 2018-2019 by Thomas A. Early N7TAE\n", ITAP_VERSION);
		printf("QnetITAP comes with ABSOLUTELY NO WARRANTY; see the LICENSE for details.\n");
		printf("This is free software, and you are welcome to distribute it\nunder certain conditions that are discussed in the LICENSE file.\n\n");
		return 0;
	}

	const char *qn = strstr(argv[0], "qnitap");
	if (NULL == qn) {
		fprintf(stderr, "Error finding 'qnitap' in %s!\n", argv[0]);
		return 1;
	}
	qn += 6;

	int assigned_module;
	switch (*qn) {
		case NULL:
			assigned_module = -1;
			break;
		case 'a':
			assigned_module = 0;
			break;
		case 'b':
			assigned_module = 1;
			break;
		case 'c':
			assigned_module = 2;
			break;
		default:
			fprintf(stderr, "assigned module must be a, b or c\n");
			return 1;
	}

	CQnetITAP qnitap(assigned_module);

	qnitap.Run(argv[1]);

	printf("%s is closing.\n", argv[0]);

	return 0;
}
