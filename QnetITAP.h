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
	RT_PONG
};

// Icom Terminal and Access Point Mode data structure
#pragma pack(push, 1)
using SITAP = struct itap_tag
{
	uint8_t length;
	// 41 for header
	// 16 for voice
	uint8_t type;
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
			uint8_t flag[3];
			uint8_t r2[8];
			uint8_t r1[8];
			uint8_t ur[8];
			uint8_t my[8];
			uint8_t nm[4];
		} header;
		struct
		{
			uint8_t counter;	// ordinal counter is reset with each header
			uint8_t sequence;	// is modulo 21
			uint8_t ambe[9];
			uint8_t text[3];
		} voice;
	};
};
#pragma pack(pop)

class CFrame
{
public:
	CFrame(const uint8_t *buf)
	{
		memcpy(&frame.length, buf, buf[0]);
	}

	CFrame(const CFrame &from)
	{
		memcpy(&frame.length, from.data(), from.size());
	}

	~CFrame() {}

	size_t size() const { return (size_t)frame.length; }

	const uint8_t *data() const { return &frame.length; }

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
	bool ProcessGateway(const int len, const uint8_t *raw);
	bool ProcessITAP(const uint8_t *raw);
	int OpenITAP();
	void SendToIcom(const uint8_t *buf);
	REPLY_TYPE GetITAPData(uint8_t *buf);
	void calcPFCS(const uint8_t *packet, uint8_t *pfcs);
	void DumpSerialPacket(const char *title, const uint8_t *);

	// read configuration file
	bool ReadConfig(const std::string &path);

	// config data
	char RPTR_MOD;
	std::string ITAP_DEVICE, RPTR;
	bool LOG_QSO, LOG_DEBUG, AP_MODE;

	// parameters
	int serfd;
	uint8_t tapcounter;

	// helpers
	CRandom random;

	// unix sockets
	CUnixDgramWriter ToGate;
	CUnixDgramReader FromGate;

	// Queue
	std::queue<CFrame> queue;
	bool acknowledged;
};
