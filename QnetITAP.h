/*
 *   Copyright (C) 2018-2020 by Thomas A. Early N7TAE
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
#include <fstream>
#include <string>
#include <queue>

#include <netinet/in.h>
#include "Random.h"	// for streamid generation
#include "UnixDgramSocket.h"
#include "Base.h"

#define CALL_SIZE 8
#define IP_SIZE 15

enum REPLY_TYPE
{
	RT_TIMEOUT,
	RT_ERROR,
	RT_UNKNOWN,
	RT_HEADER,
	RT_DATA,
	RT_HEADER_ACK,
	RT_DATA_ACK,
	RT_PONG,
	RT_DATA_BT
};
struct ambe_frame {
	unsigned char sequence;
	unsigned char ambe[9];
	unsigned char text[3];
};
// Icom Terminal and Access Point Mode data structure
#pragma pack(push, 1)
using SITAP = struct itap_tag
{
	unsigned char length;
	// 41 for header
	// 16 for voice
	unsigned char type;
	// 0x03U pong
	// 0x10U header from icom
	// 0x11U acknowledgment
	// 0x12U data   from icom (it's EOT if voice.sequence bit 0x40 is set)
	// 0x13U acknowledgment
	// 0x20U header to icom
	// 0x21U header acknowledgment
	// 0x22U   data to icom
	// 0x23U   data acknowledgment
	union
	{
		struct
		{
			unsigned char flag[3];
			unsigned char r2[8];
			unsigned char r1[8];
			unsigned char ur[8];
			unsigned char my[8];
			unsigned char nm[4];
		} header;
		struct
		{
			unsigned char counter;	// ordinal counter is reset with each header
			ambe_frame frame;
		} voice;
		struct
		{
			unsigned char counter;
			unsigned char count;
			ambe_frame frame[4];
		} voice_bt;
	};
};
#pragma pack(pop)

class CFrame
{
public:
	CFrame(const unsigned char *buf)
	{
		memcpy(&frame.length, buf, buf[0]);
	}

	CFrame(const CFrame &from)
	{
		memcpy(&frame.length, from.data(), from.size());
	}

	~CFrame() {}

	size_t size() const { return (size_t)frame.length; }

	const unsigned char *data() const { return &frame.length; }

private:
	SITAP frame;
};

class CQnetITAP : public CModem
{
public:
	// functions
	CQnetITAP(int mod) : CModem(mod) {}
	~CQnetITAP() {}
	bool Initialize(const std::string &cfgfile);
	void Run();
	void Close();

	// data

private:
	// functions
	bool ProcessGateway(const int len, const unsigned char *raw);
	bool ProcessITAP(const unsigned char *raw);
	int OpenITAP();
	void SendToIcom(const unsigned char *buf);
	REPLY_TYPE GetITAPData(unsigned char *buf);
	void calcPFCS(const unsigned char *packet, unsigned char *pfcs);
	void DumpSerialPacket(const char *title, const unsigned char *, const char dir);

	// read configuration file
	bool ReadConfig(const std::string &path);

	// config data
	char RPTR_MOD;
	std::string ITAP_DEVICE, RPTR;
	bool LOG_QSO, LOG_DEBUG, AP_MODE;

	// parameters
	int serfd;
	unsigned char tapcounter;

	// helpers
	CRandom random;

	// unix sockets
	CUnixDgramWriter ToGate;
	CUnixDgramReader FromGate;

	// Queue
	std::queue<CFrame> queue;
	bool acknowledged;

	std::ofstream serialLog;
};
