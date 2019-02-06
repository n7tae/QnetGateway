/*
 *   Copyright (C) 2019 by Thomas A. Early N7TAE
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

#pragma once

#include <atomic>
#include <cstring>
#include <string>
#include <queue>

#include <netinet/in.h>
#include "Random.h"	// for streamid generation
#include "UnixDgramSocket.h"

#define CALL_SIZE 8
#define IP_SIZE 15

enum MODEM_RESPONSE {
	ACK_RESPONSE,
	NACK_RESPONSE,
	TIMEOUT_RESPONSE,
	ERROR_RESPONSE,
	HEADER_RESPONSE,
	DATA_RESPONSE,
	LOST_RESPONSE,
	EOT_RESPONSE,
	STATUS_RESPONSE,
	VERSION_RESPONSE
};

enum HARDWARE_TYPE {
	HWT_MMDVM,
	HWT_DVMEGA,
	HWT_MMDVM_ZUMSPOT,
	HWT_MMDVM_HS_HAT,
	HWT_MMDVM_HS_DUAL_HAT,
	HWT_NANO_HOTSPOT,
	HWT_NANO_DV,
	HWT_MMDVM_HS,
	HWT_UNKNOWN
};

// Icom Terminal and Access Point Mode data structure
#pragma pack(push, 1)
typedef struct version_tag {
	unsigned char start;
	unsigned char length;
	unsigned char type;
	unsigned char protocol;
	unsigned char version[251];
} SVERSION;

typedef struct mmodem_tag {
	unsigned char start;	// always 0xEOU
	unsigned char length;	// 3 - 255
	unsigned char type;
		// 0x70U acknowledge from modem, ACK
		// 0x7FU error from modem, NACK
		// 0x00U version
		// 0x01U status
		// 0x02U configure
		// 0x03U mode
		// 0x04U frequency
		// 0x10U header
		// 0x11U data
		// 0x12U transmission lost
		// 0x13U transmission end
	union {
		unsigned char ack;			// the type being acknowledged
		unsigned char mode;			// 0 idle, 1 dstar, 2 dmr, 3 ysf, 99 calibration
		struct {
			unsigned char ack;		// the type being acknowledged
			unsigned char reason;	// reason for the NAK
				// 1 - invalid command
				// 2 - wrong mode
				// 3 - command too long
				// 4 - data incorrect
				// 5 - Not enough buffer space
		} nack;
		// don't want to inflate the struct size, so it's here for reference only
		//struct {
		//	unsigned char protocol_version;
		//	unsigned char version[250];
		//} version;
		struct {
			unsigned char modes;	// 0x1U dstar | 0x2 dmr | 0x4 system fusion
			unsigned char status;	// 0 idle, 1 dstar, 2 dmr, 3 system fusion, 99 calibration
			unsigned char flags;	// 0x1 Tx on, 0x2 adc overflow
			unsigned char dsrsize;	// dstar buffersize
			unsigned char dm1size;	// drm timeslot 1 buffersize
			unsigned char dm2size;	// dmr timeslot 2 buffersize
			unsigned char ysfsize;  // ysf buffersize
		} status;
		struct {
			unsigned char flags;		// 0x1 rx 0x2 tx 0x4 ptt 0x8 ysf lodev 0x10 debug 0x80 not duplex
			unsigned char mode;			// 0x1 dstar 0x2 drm 0x4 ysf 0x8 p25 0x10 nxdx 0x20 pocsag
			unsigned char tx_delay;		// tx delay in 10 millisecond increments
			unsigned char init_mode;	// inital state 0 idle 1 dstar 2 dmr 3 ysf 99 calibration
			unsigned char rx_level;		// rx input level 0-255
			unsigned char cw_tx_level;	// cw tx output
			unsigned char color;		// dmr color 0-15
			unsigned char drm_delay;
			unsigned char osc_offset;	// 128U
			unsigned char dstar_tx_level;
			unsigned char dmr_tx_level;
			unsigned char ysf_tx_level;
			unsigned char p25_tx_level;
			unsigned char tx_dc_offset;
			unsigned char rx_dc_offset;
			unsigned char nxdn_tx_level;
			unsigned char ysf_tx_hang;
			unsigned char pocsag_tx;
		} config;
		struct {
			unsigned char zero;	// should be zero;
			uint32_t rx;	// receive frequency
			uint32_t tx;	// transmitter frequency
			unsigned char level;	// rf level for pocsag?
			uint32_t ps;	// pocsag frequency, default 433000000U
		} frequency;
		struct {
			unsigned char flag[3];
			unsigned char r2[8];
			unsigned char r1[8];
			unsigned char ur[8];
			unsigned char my[8];
			unsigned char nm[4];
			unsigned char pfcs[2];
		} header;
		struct {
			unsigned char ambe[9];
			unsigned char text[3];
		} voice;
	};
} SMODEM;
#pragma pack(pop)

class CFrame
{
public:
	CFrame(const unsigned char *buf) {
		memcpy(&frame.start, buf, buf[1]);
	}

	CFrame(const CFrame &from) {
		memcpy(&frame.start, from.data(), from.size());
	}

	~CFrame() {}

	size_t size() const { return (size_t)frame.length; }

	const unsigned char *data() const { return &frame.start; }
	unsigned char type() { return frame.type; }

private:
	SMODEM frame;
};

class CTimer
{
public:
	CTimer() { start(); }
	~CTimer() {}
	void start() {
		starttime = std::chrono::steady_clock::now();
	}
	double time() {
		std::chrono::steady_clock::duration elapsed = std::chrono::steady_clock::now() - starttime;
		return double(elapsed.count() * std::chrono::steady_clock::period::num / std::chrono::steady_clock::period::den);
	}
private:
	std::chrono::steady_clock::time_point starttime;
};

class CQnetModem
{
public:
	// functions
	CQnetModem(int mod);
	~CQnetModem();
	void Run(const char *cfgfile);

	// data
	static std::atomic<bool> keep_running;

private:
	int assigned_module;
	unsigned short COUNTER;
	unsigned char dstarSpace;
	bool g2_is_active;

	// functions
	bool Initialize(const char *cfgfile);
	static void SignalCatch(const int signum);
	bool ProcessGateway(const int len, const unsigned char *raw);
	bool ProcessModem(const SMODEM &frame);
	int OpenModem();
	int SendToModem(const unsigned char *buf);
	MODEM_RESPONSE GetModemData(unsigned char *buf, unsigned int size);
	bool GetVersion();
	bool SetFrequency();
	bool SetConfiguration();

	// read configuration file
	bool ReadConfig(const char *);

	// config data
	char RPTR_MOD;
	std::string MODEM_DEVICE, RPTR;
	double TX_FREQUENCY, RX_FREQUENCY, TX_OFFSET, RX_OFFSET, packet_wait;
	int TX_DELAY, RX_LEVEL, TX_LEVEL, PACKET_WAIT;
	bool DUPLEX, RX_INVERT, TX_INVERT, PTT_INVERT, LOG_QSO;

	// parameters
	HARDWARE_TYPE hardwareType;
	int serfd;


	// helpers
	CRandom random;
	CTimer PacketWait;

	// unix sockets
	std::string modem2gate, gate2modem;
	CUnixDgramWriter Modem2Gate;
	CUnixDgramReader Gate2Modem;

	// Queue
	std::queue<CFrame> queue;
};
