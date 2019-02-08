/*
 *   Copyright (C) 2019 by Thomas A. Early N7TAE
 *
 *   CQnetModem is inspired by {Modem,MMDVMHost}.cpp in
 *   Jonathan Naylor's brilliant MMDVMHost that is...
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

#include "QnetModem.h"
#include "QnetTypeDefs.h"
#include "QnetConfigure.h"

#define MODEM_VERSION "QnetModem-0.0.0"
#define MAX_RESPONSES 30

std::atomic<bool> CQnetModem::keep_running(true);

const unsigned char FRAME_START  = 0xE0U;

const unsigned char TYPE_VERSION = 0x00U;
const unsigned char TYPE_STATUS  = 0x01U;
const unsigned char TYPE_CONFIG  = 0x02U;
const unsigned char TYPE_MODE    = 0x03U;
const unsigned char TYPE_FREQ    = 0x04U;

const unsigned char TYPE_CWID    = 0x0AU;

const unsigned char TYPE_HEADER  = 0x10U;
const unsigned char TYPE_DATA    = 0x11U;
const unsigned char TYPE_LOST    = 0x12U;
const unsigned char TYPE_EOT     = 0x13U;

const unsigned char TYPE_ACK     = 0x70U;
const unsigned char TYPE_NACK    = 0x7FU;

CQnetModem::CQnetModem(int mod)
: assigned_module(mod)
, COUNTER(0)
, dstarSpace(0U)
, g2_is_active(false)
{
}

CQnetModem::~CQnetModem()
{
}

bool CQnetModem::GetBufferSize()
{
	std::this_thread::sleep_for(std::chrono::seconds(2));

	for (int i=0; i<6; i++) {
		SMODEM frame;

		frame.start = FRAME_START;
		frame.length = 0x3U;
		frame.type = TYPE_STATUS;

		if (3 != SendToModem(&frame.start))
			return true;

		for (int count = 0; count < MAX_RESPONSES; count++) {
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
			MODEM_RESPONSE resp = GetModemData(&frame.start, sizeof(SVERSION));
			if (resp == STATUS_RESPONSE) {
				dstarSpace = frame.status.dsrsize;
				printf("D-Star buffer will hold %u voice frames\n", dstarSpace);
				return false;
			}
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(1500));
	}
	fprintf(stderr, "Unable to read the firmware version after six attempts\n");
	return true;
}

bool CQnetModem::GetVersion()
{
	std::this_thread::sleep_for(std::chrono::seconds(2));

	for (int i=0; i<6; i++) {
		SVERSION frame;

		frame.start = FRAME_START;
		frame.length = 0x3U;
		frame.type = TYPE_VERSION;

		if (3 != SendToModem(&frame.start))
			return true;

		for (int count = 0; count < MAX_RESPONSES; count++) {
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
			MODEM_RESPONSE resp = GetModemData(&frame.start, sizeof(SVERSION));
			if (resp == VERSION_RESPONSE && frame.length > 14U) {
				frame.version[frame.length-4U] = '\0';	// just to make sure!
				if      (0 == memcmp(frame.version, "MMDVM ", 6U))
					hardwareType = HWT_MMDVM;
				else if (0 == memcmp(frame.version, "DVMEGA", 6U))
					hardwareType = HWT_DVMEGA;
				else if (0 == memcmp(frame.version, "ZUMspot", 7U))
					hardwareType = HWT_MMDVM_ZUMSPOT;
				else if (0 == memcmp(frame.version, "MMDVM_HS_Hat", 12U))
					hardwareType = HWT_MMDVM_HS_HAT;
				else if (0 == memcmp(frame.version, "MMDVM_HS_Dual_Hat", 17U))
					hardwareType = HWT_MMDVM_HS_DUAL_HAT;
				else if (0 == memcmp(frame.version, "Nano_hotSPOT", 12U))
					hardwareType = HWT_NANO_HOTSPOT;
				else if (0 == memcmp(frame.version, "Nano_DV", 7U))
					hardwareType = HWT_NANO_DV;
				else if (0 == memcmp(frame.version, "MMDVM_HS-", 9U))
					hardwareType = HWT_MMDVM_HS;
				else {
					hardwareType = HWT_UNKNOWN;
				}

				printf("MMDVM protocol version: %u, Modem: %s\n", (unsigned int)frame.protocol, (char *)frame.version);
				return false;
			}
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(1500));
	}
	fprintf(stderr, "Unable to read the firmware version after six attempts\n");
	return true;
}

bool CQnetModem::SetFrequency()
{
	uint32_t  pocsagFrequency = 433000000U;
	SMODEM frame;

	frame.start = FRAME_START;
	frame.type = TYPE_FREQ;

	if (hardwareType == HWT_DVMEGA)
		frame.length = 12U;
	else {
		frame.frequency.level = 255U;
		frame.frequency.ps = __builtin_bswap32(htonl(pocsagFrequency));

		frame.length = 17U;
	}

	frame.frequency.zero = 0x0U;
	uint32_t rx_frequency = (uint32_t)((RX_FREQUENCY + RX_OFFSET) * 1000000.0);
	frame.frequency.rx = __builtin_bswap32(htonl(rx_frequency));
	uint32_t tx_frequency = (uint32_t)((TX_FREQUENCY + TX_OFFSET) * 1000000.0);
	frame.frequency.tx = __builtin_bswap32(htonl(tx_frequency));

	if ((int)frame.length != SendToModem(&frame.start))
		return true;

	int count = 0;
	bool got_ack = false;
	while (! got_ack) {
		std::this_thread::sleep_for(std::chrono::milliseconds(10));

		switch (GetModemData(&frame.start, sizeof(SMODEM))) {
			case ACK_RESPONSE:
				got_ack = true;
				break;
			case NACK_RESPONSE:
				fprintf(stderr, "SET_FREQ failed, returned NACK reason %u\n", frame.nack.reason);
				return true;
			default:
				if (++count >= MAX_RESPONSES) {
					fprintf(stderr, "The MMDVM is not responding to the SET_FREQ command!\n");
					return true;
				}
				break;
		}
	}
	printf("Modem frequencies set: rx=%u(%u) tx=%u(%u) Hz\n", (uint32_t)(1.0E6 * RX_FREQUENCY), rx_frequency, (uint32_t)(1.0E6 * TX_FREQUENCY), tx_frequency);
	return false;
}

bool CQnetModem::Initialize(const char *cfgfile)
{
	if (ReadConfig(cfgfile))
		return true;

	struct sigaction act;
	act.sa_handler = &CQnetModem::SignalCatch;
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

	Modem2Gate.SetUp(modem2gate.c_str());
	if (Gate2Modem.Open(gate2modem.c_str()))
		return true;

	serfd = OpenModem();
	if (serfd < 0)
		return true;

	if (GetVersion())
		return true;

	if (SetFrequency())
		return true;

	if (SetConfiguration())
		return true;

	if (GetBufferSize())
		return true;

	return false;
}

bool CQnetModem::SetConfiguration()
{
	SMODEM frame;
	memset(&frame.start, 0, sizeof(SMODEM));	// star with a clean slate
	frame.start = FRAME_START;
	frame.length = 21U;
	frame.type = TYPE_CONFIG;

	if (RX_INVERT)
		frame.config.flags |= 0x01U;
	if (TX_INVERT)
		frame.config.flags |= 0x02U;
	if (PTT_INVERT)
		frame.config.flags |= 0x04U;
	if (! DUPLEX)
		frame.config.flags |= 0x80U;

	frame.config.mode           = 0x1U;	// Only D-Star is enabled!
	frame.config.tx_delay       = (unsigned char)(TX_DELAY / 10);	// In 10ms units
	frame.config.init_mode      = 0x1U;	// yup, just D-Star
	frame.config.rx_level       = (unsigned char)RX_LEVEL;
	frame.config.osc_offset     = 128U;           // Was OscOffset
	frame.config.dstar_tx_level = (unsigned char)TX_LEVEL;
	frame.config.tx_dc_offset   = 128U;
	frame.config.rx_dc_offset   = 128U;

	// CUtils::dump(1U, "Written", buffer, 21U);

	if (21 != SendToModem(&frame.start))
		return false;

	int count = 0;
	bool got_ack = false;
	while (! got_ack) {
		std::this_thread::sleep_for(std::chrono::milliseconds(10));

		switch (GetModemData(&frame.start, sizeof(SMODEM))) {
			case ACK_RESPONSE:
				got_ack = true;
				break;
			case NACK_RESPONSE:
				fprintf(stderr, "SET_CONFIG failed, returned NACK reason %u\n", frame.nack.reason);
				return true;
			default:
				if (++count >= MAX_RESPONSES) {
					fprintf(stderr, "The MMDVM is not responding to the SET_CONFIG command!\n");
					return true;
				}
				break;
		}
	}
	printf("Modem configuration set for D-Star only\n");
	return false;
}

int CQnetModem::OpenModem()
{
	int fd = open(MODEM_DEVICE.c_str(), O_RDWR | O_NOCTTY | O_SYNC, 0);
	if (fd < 0) {
		printf("Failed to open device [%s], error=%d, message=%s\n", MODEM_DEVICE.c_str(), errno, strerror(errno));
		return -1;
	}

	if (isatty(fd) == 0) {
		printf("Device %s is not a tty device\n", MODEM_DEVICE.c_str());
		close(fd);
		return -1;
	}

	static termios t;
	if (tcgetattr(fd, &t) < 0) {
		printf("tcgetattr failed for %s, error=%d, message-%s\n", MODEM_DEVICE.c_str(), errno, strerror(errno));
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

	cfsetospeed(&t, B115200);
	cfsetispeed(&t, B115200);

	if (tcsetattr(fd, TCSANOW, &t) < 0) {
		printf("tcsetattr failed for %s, error=%dm message=%s\n", MODEM_DEVICE.c_str(), errno, strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

MODEM_RESPONSE CQnetModem::GetModemData(unsigned char *buf, unsigned int size)
{
	if (size < 4U) {
		fprintf(stderr, "Buffer size, %u is too small\n", size);
		return ERROR_RESPONSE;
	}

	// Get the start byte
	int ret = read(serfd, buf, 1U);
	if (ret < 0) {
		fprintf(stderr, "Error when reading frame start byte: %s\n", strerror(errno));
		return ERROR_RESPONSE;
	} else if (ret == 0) {
		printf("READ START RETURNED A ZERO!\n");
		return TIMEOUT_RESPONSE;
	} else if (buf[0] != FRAME_START)
		return TIMEOUT_RESPONSE;

	//get the length byte
	ret = read(serfd, buf+1, 1U);
	if (ret < 0) {
		fprintf(stderr, "Error when reading frame length: %s\n", strerror(errno));
		return ERROR_RESPONSE;
	} else if (ret == 0) {
		printf("READ LENGTH RETURNED A ZERO!\n");
		return(TIMEOUT_RESPONSE);
	}
	// is the packet size bigger than a D-Star header (44 bytes)?
	unsigned int junk_count = ((unsigned int)buf[1] > size) ? (unsigned int)buf[1] - size : 0;

	// get the type byte
	ret = read(serfd, buf+2, 1U);
	if (ret < 0) {
		fprintf(stderr, "Error when reading frame type: %s\n", strerror(errno));
		return ERROR_RESPONSE;
	} else if (ret == 0) {
		printf("READ TYPE RETURNED A ZERO!\n");
		return(TIMEOUT_RESPONSE);
	}
	// get the data
	unsigned int length = buf[1];
	unsigned int offset = 3;
	while (offset < length) {
		ret = read(serfd, buf + offset, length - offset);
		if (ret < 0) {
			printf("Error when reading data: %s\n", strerror(errno));
			return ERROR_RESPONSE;
		}
		if (ret == 0) {
			printf("READ DATA RETURNED A ZERO!\n");
		} else
			offset += ret;
	}

	while (junk_count) {
		unsigned char junk[8];
		ret = read(serfd, junk, (junk_count > 8U) ? 8U : junk_count);
		if (ret < 0) {
			printf("Error when reading junk: %s\n", strerror(errno));
			return ERROR_RESPONSE;
		} else if (ret == 0) {
			printf("READ junk RETURNED A ZERO!\n");
		} else
			junk_count -= (unsigned int)ret;
	}

	switch (buf[2]) {
		case TYPE_ACK:
			return ACK_RESPONSE;
		case TYPE_NACK:
			return NACK_RESPONSE;
		case TYPE_HEADER:
			return HEADER_RESPONSE;
		case TYPE_DATA:
			return DATA_RESPONSE;
		case TYPE_LOST:
			return LOST_RESPONSE;
		case TYPE_EOT:
			return EOT_RESPONSE;
		case TYPE_VERSION:
			return VERSION_RESPONSE;
		case TYPE_STATUS:
			return STATUS_RESPONSE;
		default:
			return ERROR_RESPONSE;
	};
}

void CQnetModem::Run(const char *cfgfile)
{
	if (Initialize(cfgfile))
		return;

	int ug2m = Gate2Modem.GetFD();
	printf("gate2modem=%d, serial=%d\n", ug2m, serfd);

	keep_running = true;

	CTimer statusTimer;
	CTimer deadTimer;

	while (keep_running) {

		SMODEM frame;
		frame.start = FRAME_START;
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(serfd, &readfds);
		FD_SET(ug2m, &readfds);
		int maxfs = (serfd > ug2m) ? serfd : ug2m;

		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 3000;	// select will return a zero after 3 msec of inactivity

		// don't care about writefds and exceptfds:
		int ret = select(maxfs+1, &readfds, NULL, NULL, &tv);
		if (ret < 0) {
			printf("ERROR: Run: select returned err=%d, %s\n", errno, strerror(errno));
			break;
		}

		// check for a dead or disconnected radio
		if (10.0 < deadTimer.time()) {
			printf("no activity from radio for 10 sec. Exiting...\n");
			keep_running = false;
		}

		if (keep_running && FD_ISSET(serfd, &readfds)) {
			deadTimer.start();
			switch (GetModemData(&frame.start, sizeof(SMODEM))) {
				case DATA_RESPONSE:
				case HEADER_RESPONSE:
				case EOT_RESPONSE:
				case LOST_RESPONSE:
					if (ProcessModem(frame))
						keep_running = false;
					break;
				case STATUS_RESPONSE:
					if (frame.status.flags & 0x02U)
						fprintf(stderr, "Modem ADC levels have overflowed\n");
					if (frame.status.flags & 0x04U)
						fprintf(stderr, "Modem RX buffer has overflowed\n");
					if (frame.status.flags & 0x08U)
						fprintf(stderr, "Modem TX buffer has overflowed\n");
					if (frame.status.flags & 0x20U)
						fprintf(stderr, "Modem DAC levels have overflowed\n");
					dstarSpace = frame.status.dsrsize;
					break;
				default:
					break;
			}
			FD_CLR(serfd, &readfds);
		}

		if (keep_running && FD_ISSET(ug2m, &readfds)) {
			unsigned char buf[100];
			ssize_t len = Gate2Modem.Read(buf, 100);

			if (len < 0) {
				printf("ERROR: Run: recvfrom(gsock) returned error %d, %s\n", errno, strerror(errno));
				break;
			}

			if (0 == memcmp(buf, "DSTR", 4)) {
				//printf("read %d bytes from QnetGateway\n", (int)len);
				if (ProcessGateway(len, buf))
					break;
			}
			FD_CLR(ug2m, &readfds);
		}

		if (keep_running) {
			//if (g2_is_active && PacketWait.time() > packet_wait) {
			//	// g2 has timed out
			//	frame.length = 3U;
			//	frame.type = TYPE_LOST;
			//	queue.push(CFrame(&frame.start));
			//	g2_is_active = false;
			//}
			if (! queue.empty()) {
				// send queued D-Star frames to modem
				CFrame cframe = queue.front();
				const unsigned char type = cframe.type();
				if ((type==TYPE_HEADER && dstarSpace>3U) || ((type==TYPE_DATA || type==TYPE_EOT || type==TYPE_LOST) && dstarSpace>0U)) {
					queue.pop();
					SendToModem(cframe.data());
					dstarSpace -= (type==TYPE_HEADER) ? 4U : 1U;
				}
			}
			if (dstarSpace<4 || statusTimer.time()>0.1) {
				// request a status update every 100 milliseconds or when needed
				frame.length = 3U;
				frame.type = TYPE_STATUS;
				if (3 != SendToModem(&frame.start))
					keep_running = false;
				statusTimer.start();
			}
		}
	}
	close(serfd);
	Gate2Modem.Close();
}

int CQnetModem::SendToModem(const unsigned char *buf)
{
	ssize_t n;
	size_t ptr = 0;
	ssize_t length = buf[1];

	while ((ssize_t)ptr < length) {
		n = write(serfd, buf + ptr, length - ptr);
		if (n < 0) {
			if (EAGAIN != errno) {
				printf("Error %d writing to dvap, message=%s\n", errno, strerror(errno));
				return -1;
			}
		}
		ptr += n;
	}

	return length;
}

bool CQnetModem::ProcessGateway(const int len, const unsigned char *raw)
{
	if (29==len || 58==len) { //here is dstar data
		SDSTR dstr;
		memcpy(dstr.pkt_id, raw, len);	// transfer raw data to SDSTR struct

		SMODEM frame;	// destination
		frame.start = FRAME_START;
		if (58 == len) {			// write a Header packet
			frame.length = 44U;
			frame.type = TYPE_HEADER;
			memcpy(frame.header.flag, dstr.vpkt.hdr.flag, 3);
			if (RPTR_MOD == dstr.vpkt.hdr.r2[7]) {
				memcpy(frame.header.r1,   dstr.vpkt.hdr.r2,   8);
				memcpy(frame.header.r2,   dstr.vpkt.hdr.r1,   8);
			} else {
				memcpy(frame.header.r1,   dstr.vpkt.hdr.r1,   8);
				memcpy(frame.header.r2,   dstr.vpkt.hdr.r2,   8);
			}
			memcpy(frame.header.ur,   dstr.vpkt.hdr.ur,   8);
			memcpy(frame.header.my,   dstr.vpkt.hdr.my,   8);
			memcpy(frame.header.nm,   dstr.vpkt.hdr.nm,   4);
			memcpy(frame.header.pfcs, dstr.vpkt.hdr.pfcs, 2);
			queue.push(CFrame(&frame.start));
			PacketWait.start();
			g2_is_active = true;
			if (LOG_QSO)
				printf("Queued to %s flags=%02x:%02x:%02x ur=%.8s r1=%.8s r2=%.8s my=%.8s/%.4s\n", MODEM_DEVICE.c_str(), frame.header.flag[0], frame.header.flag[1], frame.header.flag[2], frame.header.ur, frame.header.r1, frame.header.r2, frame.header.my, frame.header.nm);
		} else {	// write a voice data packet
			if (g2_is_active) {
				//const unsigned char sdsync[3] = { 0x55U, 0x2DU, 0x16U };
				if (0U == (0x3FU & dstr.vpkt.ctrl)) {
					if (0x55U!=dstr.vpkt.vasd.text[0] || 0x2DU!=dstr.vpkt.vasd.text[1] || 0x16U!=dstr.vpkt.vasd.text[2])
						printf("Warning: Voice sync frame contained text %02x:%02x:%02x!\n", dstr.vpkt.vasd.text[0], dstr.vpkt.vasd.text[1], dstr.vpkt.vasd.text[2]);
				}
				if (dstr.vpkt.ctrl & 0x40U) {
					frame.length = 3U;
					frame.type = TYPE_EOT;
					g2_is_active = false;
					if (LOG_QSO)
						printf("Queued modem end of transmission\n");
				} else {
					frame.length = 15U;
					frame.type = TYPE_DATA;
					memcpy(frame.voice.ambe, dstr.vpkt.vasd.voice, 12);
				}
				queue.push(CFrame(&frame.start));
				PacketWait.start();
			}
		}
	} else
		printf("DEBUG: ProcessGateway: unusual packet size read len=%d\n", len);
	return false;
}

bool CQnetModem::ProcessModem(const SMODEM &frame)
{
	static short stream_id = 0U;
	static unsigned char ctrl = 0U;

	// create a stream id if this is a header
	if (frame.type == TYPE_HEADER)
		stream_id = random.NewStreamID();

	SDSTR dstr;	// destination
	// sets most of the params
	memcpy(dstr.pkt_id, "DSTR", 4);
	dstr.counter = htons(COUNTER++);
	dstr.flag[0] = 0x73;
	dstr.flag[1] = 0x12;
	dstr.flag[2] = 0x0;
	dstr.vpkt.icm_id = 0x20;
	dstr.vpkt.dst_rptr_id = 0x0;
	dstr.vpkt.snd_rptr_id = 0x1;
	dstr.vpkt.snd_term_id = ('B'==RPTR_MOD) ? 0x1 : (('C'==RPTR_MOD) ? 0x2 : 0x3);
	dstr.vpkt.streamid = htons(stream_id);

	if (frame.type == TYPE_HEADER) {	// header
		ctrl = 0U;
		dstr.remaining = 0x30;
		dstr.vpkt.ctrl = 0x80;

		memcpy(dstr.vpkt.hdr.flag, frame.header.flag, 3);
		memcpy(dstr.vpkt.hdr.r1,   frame.header.r1,   8);
		memcpy(dstr.vpkt.hdr.r2,   frame.header.r2,   8);
		memcpy(dstr.vpkt.hdr.ur,   frame.header.ur,   8);
		dstr.vpkt.hdr.flag[0] &= ~0x40U;	// clear this bit

		memcpy(dstr.vpkt.hdr.my,   frame.header.my,   8);
		memcpy(dstr.vpkt.hdr.nm,   frame.header.nm,   4);
		memcpy(dstr.vpkt.hdr.pfcs, frame.header.pfcs, 2);
		if (58 != Modem2Gate.Write(dstr.pkt_id, 58)) {
			printf("ERROR: ProcessModem: Could not write gateway header packet\n");
			return true;
		}
		if (LOG_QSO)
			printf("Sent DSTR to gateway, streamid=%04x flags=%02x:%02x:%02x ur=%.8s r1=%.8s r2=%.8s my=%.8s/%.4s\n", ntohs(dstr.vpkt.streamid), dstr.vpkt.hdr.flag[0], dstr.vpkt.hdr.flag[1], dstr.vpkt.hdr.flag[2], dstr.vpkt.hdr.ur, dstr.vpkt.hdr.r1, dstr.vpkt.hdr.r2, dstr.vpkt.hdr.my, dstr.vpkt.hdr.nm);
	} else if (frame.type==TYPE_DATA || frame.type==TYPE_EOT || frame.type==TYPE_LOST) {	// ambe
		dstr.remaining = 0x16;
		dstr.vpkt.ctrl = ctrl++;
		if (ctrl >= 21U)
			ctrl = 0U;
		if (frame.type == TYPE_DATA) {
			//const unsigned char sdsync[3] = { 0x55U, 0x2DU, 0x16U };
			if (0U == (0x3FU & dstr.vpkt.ctrl)) {
				if (0x55U!=frame.voice.text[0] || 0x2DU!=frame.voice.text[1] || 0x16U!=frame.voice.text[2])
					printf("Warning: Voice sync frame contained text %02x:%02x:%02x!\n", frame.voice.text[0], frame.voice.text[1], frame.voice.text[2]);
			}
			memcpy(dstr.vpkt.vasd.voice, frame.voice.ambe, 12);
		} else {
			const unsigned char silence[12] = { 0x4EU,0x8DU,0x32U,0x88U,0x26U,0x1AU,0x3FU,0x61U,0xE8U,0x70U,0x4FU,0x93U };
			const unsigned char silsync[12] = { 0x4EU,0x8DU,0x32U,0x88U,0x26U,0x1AU,0x3FU,0x61U,0xE8U,0x55U,0x2DU,0x16U };
			if (0U == dstr.vpkt.ctrl)
				memcpy(dstr.vpkt.vasd.voice, silsync, 12);
			else
				memcpy(dstr.vpkt.vasd.voice, silence, 12);
			dstr.vpkt.ctrl |= 0x40U;
		}
		if (29 != Modem2Gate.Write(dstr.pkt_id, 29)) {
			printf("ERROR: ProcessModem: Could not write gateway voice packet\n");
			return true;
		}

		if (LOG_QSO && (dstr.vpkt.ctrl & 0x40)) {
			if (frame.type == TYPE_EOT)
				printf("Sent dstr end of streamid=%04x\n", ntohs(dstr.vpkt.streamid));
			else
				printf("Sent lost end of streamid=%04x\n", ntohs(dstr.vpkt.streamid));
		}
	} else {
		fprintf(stderr, "Warning! Unexpected frame type %02x", frame.start);
		for (unsigned int i=0; i<frame.length; i++)
			fprintf(stderr, ":%02x", *(&frame.start + i));
		fprintf(stderr, "\n");
	}

	return false;
}

// process configuration file and return true if there was a problem
bool CQnetModem::ReadConfig(const char *cfgFile)
{
	CQnetConfigure cfg;
	printf("Reading file %s\n", cfgFile);
	if (cfg.Initialize(cfgFile))
		return true;

	const std::string estr;	// an empty string
	std::string type;
	std::string modem_path("module_");
	if (0 > assigned_module) {
		// we need to find the lone mmdvmmodem module
		for (int i=0; i<3; i++) {
			std::string test(modem_path);
			test.append(1, 'a'+i);
			if (cfg.KeyExists(test)) {
				cfg.GetValue(test, estr, type, 1, 16);
				if (type.compare("mmdvmmodem"))
					continue;	// this ain't it!
				modem_path.assign(test);
				assigned_module = i;
				break;
			}
		}
		if (0 > assigned_module) {
			fprintf(stderr, "Error: no 'mmdvmmodem' module found\n!");
			return true;
		}
	} else {
		// make sure mmdvmmodem module is defined
		modem_path.append(1, 'a' + assigned_module);
		if (cfg.KeyExists(modem_path)) {
			cfg.GetValue(modem_path, estr, type, 1, 16);
			if (type.compare("mmdvmmodem")) {
				fprintf(stderr, "%s = %s is not 'mmdvmmodem' type!\n", modem_path.c_str(), type.c_str());
				return true;
			}
		} else {
			fprintf(stderr, "Module '%c' is not defined.\n", 'a'+assigned_module);
			return true;
		}
	}
	RPTR_MOD = 'A' + assigned_module;

	cfg.GetValue(modem_path+"_device", type, MODEM_DEVICE, 7, FILENAME_MAX);
	cfg.GetValue("gateway_gate2modem"+std::string(1, 'a'+assigned_module), estr, gate2modem, 1, FILENAME_MAX);
	cfg.GetValue("gateway_modem2gate", estr, modem2gate, 1, FILENAME_MAX);

	if (cfg.GetValue(modem_path+"_tx_frequency", type, TX_FREQUENCY, 1.0, 6000.0))
		return true;	// we have to have a valid frequency
	cfg.GetValue(modem_path+"_rx_frequency", type, RX_FREQUENCY, 0.0, 6000.0);
	if (RX_FREQUENCY <= 0.0)
		RX_FREQUENCY = TX_FREQUENCY;
	cfg.GetValue(modem_path+"_tx_offset", type, TX_OFFSET, -10.0, 10.0);
	cfg.GetValue(modem_path+"_rx_offset", type, RX_OFFSET, -10.0, 10.0);
	cfg.GetValue(modem_path+"_duplex", type, DUPLEX);
	cfg.GetValue(modem_path+"_rx_invert", type, RX_INVERT);
	cfg.GetValue(modem_path+"_tx_invert", type, TX_INVERT);
	cfg.GetValue(modem_path+"_ptt_invert", type, PTT_INVERT);
	cfg.GetValue(modem_path+"_tx_delay", type, TX_DELAY, 0, 1000);
	cfg.GetValue(modem_path+"_rx_level", type, RX_LEVEL, 0, 255);
	cfg.GetValue(modem_path+"_tx_level", type, TX_LEVEL, 0, 255);
	cfg.GetValue(modem_path+"_packet_wait", type, PACKET_WAIT, 18, 30);
	packet_wait = 1.0E-3 * double(PACKET_WAIT);

	modem_path.append("_callsign");
	if (cfg.KeyExists(modem_path)) {
		if (cfg.GetValue(modem_path, type, RPTR, 3, 6))
			return true;
	} else {
		modem_path.assign("ircddb_login");
		if (cfg.KeyExists(modem_path)) {
			if (cfg.GetValue(modem_path, estr, RPTR, 3, 6))
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

	cfg.GetValue("log_qso", estr, LOG_QSO);

	return false;
}

void CQnetModem::SignalCatch(const int signum)
{
	if ((signum == SIGTERM) || (signum == SIGINT)  || (signum == SIGHUP))
		keep_running = false;
	exit(0);
}

int main(int argc, const char **argv)
{
	setbuf(stdout, NULL);
	if (2 != argc) {
		fprintf(stderr, "usage: %s path_to_config_file\n", argv[0]);
		return 1;
	}

	if ('-' == argv[1][0]) {
		printf("\nQnetModem Version %s Copyright (C) 2019 by Thomas A. Early N7TAE\n", MODEM_VERSION);
		printf("QnetModem comes with ABSOLUTELY NO WARRANTY; see the LICENSE for details.\n");
		printf("This is free software, and you are welcome to distribute it\n");
		printf("under certain conditions that are discussed in the LICENSE file.\n\n");
		return 0;
	}

	const char *qn = strstr(argv[0], "qnmodem");
	if (NULL == qn) {
		fprintf(stderr, "Error finding 'qnmodem' in %s!\n", argv[0]);
		return 1;
	}
	qn += 7;

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

	CQnetModem qnmodem(assigned_module);

	qnmodem.Run(argv[1]);

	printf("%s is closing.\n", argv[0]);

	return 0;
}
