/*
 *   Copyright (C) 2016-2020,2026 by Thomas A. Early N7TAE
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

#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/tcp.h>

#include <thread>
#include <chrono>
#include <sstream>

#include "aprs.h"

CAPRS::CAPRS(SRPTR *prptr, bool debug) : m_rptr(prptr), m_debug(debug) {}

CAPRS::~CAPRS()
{
	aprs_sock.Close();
}

// This is called when header comes in from repeater
void CAPRS::SelectBand(int16_t rptr_idx, uint16_t streamID)
{
	if ((rptr_idx < 0) || (rptr_idx > 2))
	{
		printf("ERROR in aprs_select_band, invalid mod %d\n", rptr_idx);
		return;
	}

	/* lock on the streamID */
	aprs_streamID[rptr_idx].streamID = streamID;
	// aprs_streamID[rptr_idx].last_time = 0;

	Reset(rptr_idx);
	return;
}

// This is called when data(text) comes in from repeater
// Parameter buf is either:
//              12 bytes(packet from repeater was 29 bytes) or
//              15 bytes(packet from repeater was 32 bytes)
// Paramter seq is the byte at pos# 16(counting from zero) in the repeater data
void CAPRS::ProcessText(uint16_t streamID, uint8_t seq, uint8_t *buf)
{
	uint8_t aprs_data[200];
	char aprs_buf[1024];
	time_t tnow = 0;

	int16_t rptr_idx = -1;

	for (int16_t i = 0; i < 3; i++)
	{
		if (streamID == aprs_streamID[i].streamID)
		{
			rptr_idx = i;
			break;
		}
	}

	if ((rptr_idx < 0) || (rptr_idx > 2))
	{
		printf("ERROR in aprs_process_text: rptr_idx %d is invalid\n", rptr_idx);
		return;
	}

	if ((seq & 0x40) == 0x40)
		return;

	if ((seq & 0x1f) == 0x00)
	{
		SyncIt(rptr_idx);
		return;
	}

	bool done = WriteData(rptr_idx, buf + 9);
	if (!done)
		return;

	unsigned int aprs_len = GetData(rptr_idx, aprs_data, 200);
	aprs_data[aprs_len] = '\0';

	time(&tnow);
	if ((tnow - aprs_streamID[rptr_idx].last_time) < 30)
		return;

	if (aprs_sock.GetFD() == -1)
		return;

	char *p = strchr((char*)aprs_data, ':');
	if (!p)
	{
		Reset(rptr_idx);
		return;
	}
	*p = '\0';


	char *hdr = (char *)aprs_data;
	char *aud = p + 1;
	if (strchr(hdr, 'q') != NULL)
		return;

	p = strchr(aud, '\r');
	*p = '\0';

	sprintf(aprs_buf, "%s,qAR,%s:%s", hdr, m_rptr->mod[rptr_idx].call.c_str(), aud);
	std::string gpsA(aprs_buf);
	if (m_debug)
		printf("GPS-A: %s\n", aprs_buf);
	if (aprs_sock.WriteLine(gpsA)) {
		fprintf(stderr, "ERROR: could not write %s\n", aprs_buf);
	}
	time(&aprs_streamID[rptr_idx].last_time);

	return;
}

void CAPRS::Init()
{
	/* Initialize the statistics on the APRS packets */
	for (int16_t rptr_idx = 0; rptr_idx < 3; rptr_idx++)
	{
		aprs_pack[rptr_idx].al = EAprsLevel::none;
		memset(aprs_pack[rptr_idx].data, 0, sizeof(aprs_pack[rptr_idx].data));
		aprs_pack[rptr_idx].len = 0;
		memset(aprs_pack[rptr_idx].buf, 0, sizeof(aprs_pack[rptr_idx].buf));
		aprs_pack[rptr_idx].sl = ESlowLevel::first;
		aprs_pack[rptr_idx].is_sent = false;
	}

	for (int16_t i = 0; i < 3; i++)
	{
		aprs_streamID[i].streamID = 0;
		aprs_streamID[i].last_time = 0;
	}

	return;
}

bool CAPRS::WriteData(int16_t rptr_idx, uint8_t *data)
{

	if ((rptr_idx < 0) || (rptr_idx > 2))
	{
		printf("CAPRS::WriteData: rptr_idx %d is invalid\n", rptr_idx);
		return false;
	}

	if (aprs_pack[rptr_idx].is_sent)
		return false;

	switch (aprs_pack[rptr_idx].sl)
	{
	case ESlowLevel::first:
		aprs_pack[rptr_idx].buf[0] = data[0] ^ 0x70;
		aprs_pack[rptr_idx].buf[1] = data[1] ^ 0x4f;
		aprs_pack[rptr_idx].buf[2] = data[2] ^ 0x93;
		aprs_pack[rptr_idx].sl = ESlowLevel::second;
		return false;

	case ESlowLevel::second:
		aprs_pack[rptr_idx].buf[3] = data[0] ^ 0x70;
		aprs_pack[rptr_idx].buf[4] = data[1] ^ 0x4f;
		aprs_pack[rptr_idx].buf[5] = data[2] ^ 0x93;
		aprs_pack[rptr_idx].sl = ESlowLevel::first;
		break;
	}

	if ((aprs_pack[rptr_idx].buf[0] & 0xf0) != 0x30)
		return false;

	return AddData(rptr_idx, aprs_pack[rptr_idx].buf + 1);

}

void CAPRS::SyncIt(int16_t rptr_idx)
{
	if ((rptr_idx < 0) || (rptr_idx > 2))
	{
		printf("CAPRS::SyncIt(): rptr_idx %d is invalid\n", rptr_idx);
		return;
	}

	aprs_pack[rptr_idx].sl = ESlowLevel::first;
	return;
}

void CAPRS::Reset(int16_t rptr_idx)
{
	if ((rptr_idx < 0) || (rptr_idx > 2))
	{
		printf("CAPRS::Reset(): rptr_idx %d is invalid\n", rptr_idx);
		return;
	}

	aprs_pack[rptr_idx].al = EAprsLevel::none;
	aprs_pack[rptr_idx].len = 0;
	aprs_pack[rptr_idx].sl = ESlowLevel::first;
	aprs_pack[rptr_idx].is_sent = false;

	return;
}

unsigned int CAPRS::GetData(int16_t rptr_idx, uint8_t *data, unsigned int len)
{
	if ((rptr_idx < 0) || (rptr_idx > 2))
	{
		printf("CAPRS::GetData: rptr_idx %d is invalid\n", rptr_idx);
		return 0;
	}

	unsigned int l = aprs_pack[rptr_idx].len - 10;

	if (l > len)
		l = len;

	memcpy(data, aprs_pack[rptr_idx].data  + 10, l);

	aprs_pack[rptr_idx].al = EAprsLevel::none;
	aprs_pack[rptr_idx].len = 0;
	aprs_pack[rptr_idx].is_sent = true;

	return l;
}

void CAPRS::Open(const std::string &OWNER, const std::string &NAME)
{
	while (aprs_sock.Open(m_rptr->aprs.ip, AF_UNSPEC, std::to_string(m_rptr->aprs.port), m_debug))
	{
		fprintf(stderr, "Failed to open %s, retry in 10 seconds...\n", m_rptr->aprs.ip.c_str());
		std::this_thread::sleep_for(std::chrono::seconds(10));
	}

	/* login to aprs */
	//sprintf(snd_buf, "user %s pass %d vers QnetGateway 9 UDP 5 ", OWNER.c_str(), m_rptr->aprs_hash);
	std::stringstream ss;
	ss << "user " << OWNER << " pass " << m_rptr->aprs_hash << " version " << NAME;

	/* add the user's filter */
	if (m_rptr->aprs_filter.length())
	{
		ss << " filter " << m_rptr->aprs_filter;
	}
	std::string str(ss.str());
	if (m_debug)
		printf("APRS Login: %s\n", str.c_str());

	if (aprs_sock.WriteLine(str)) {
		fprintf(stderr, "Could write login into aprs\n");
		aprs_sock.Close();
		return;
	} else {	// successfully wrote login packet
		if (aprs_sock.ReadLine(str)) {
			fprintf(stderr, "Did not receive aprs login ackn\n");
			aprs_sock.Close();
			return;
		} else {
			if (m_debug)
				printf("APRS Login returned: %s\n", str.c_str());
		}
	}
	return;
}

bool CAPRS::AddData(int16_t rptr_idx, uint8_t *data)
{
	if ((rptr_idx < 0) || (rptr_idx > 2))
	{
		printf("CAPRS::AddData(): rptr_idx %d is invalid\n", rptr_idx);
		return false;
	}

	for (unsigned int i = 0; i < 5; i++)
	{
		uint8_t c = data[i];

		switch (aprs_pack[rptr_idx].al)
		{
		case EAprsLevel::none:
			if (c == '$')
			{
				aprs_pack[rptr_idx].data[aprs_pack[rptr_idx].len] = c;
				aprs_pack[rptr_idx].len++;
				aprs_pack[rptr_idx].al = EAprsLevel::one;
			}
			break;
		case EAprsLevel::one:
			if (c == '$')
			{
				aprs_pack[rptr_idx].data[aprs_pack[rptr_idx].len] = c;
				aprs_pack[rptr_idx].len++;
				aprs_pack[rptr_idx].al = EAprsLevel::two;
			}
			break;
		case EAprsLevel::two:
			if (c == 'C')
			{
				aprs_pack[rptr_idx].data[aprs_pack[rptr_idx].len] = c;
				aprs_pack[rptr_idx].len++;
				aprs_pack[rptr_idx].al = EAprsLevel::c1;
			}
			break;
		case EAprsLevel::c1:
			if (c == 'R')
			{
				aprs_pack[rptr_idx].data[aprs_pack[rptr_idx].len] = c;
				aprs_pack[rptr_idx].len++;
				aprs_pack[rptr_idx].al = EAprsLevel::r1;
			}
			break;
		case EAprsLevel::r1:
			if (c == 'C')
			{
				aprs_pack[rptr_idx].data[aprs_pack[rptr_idx].len] = c;
				aprs_pack[rptr_idx].len++;
				aprs_pack[rptr_idx].al = EAprsLevel::c2;
			}
			break;
		case EAprsLevel::c2:
			aprs_pack[rptr_idx].data[aprs_pack[rptr_idx].len] = c;
			aprs_pack[rptr_idx].len++;
			aprs_pack[rptr_idx].al = EAprsLevel::csum1;
			break;
		case EAprsLevel::csum1:
			aprs_pack[rptr_idx].data[aprs_pack[rptr_idx].len] = c;
			aprs_pack[rptr_idx].len++;
			aprs_pack[rptr_idx].al = EAprsLevel::csum2;
			break;
		case EAprsLevel::csum2:
			aprs_pack[rptr_idx].data[aprs_pack[rptr_idx].len] = c;
			aprs_pack[rptr_idx].len++;
			aprs_pack[rptr_idx].al = EAprsLevel::csum3;
			break;
		case EAprsLevel::csum3:
			aprs_pack[rptr_idx].data[aprs_pack[rptr_idx].len] = c;
			aprs_pack[rptr_idx].len++;
			aprs_pack[rptr_idx].al = EAprsLevel::csum4;
			break;
		case EAprsLevel::csum4:
			if (c == ',')
			{
				aprs_pack[rptr_idx].data[aprs_pack[rptr_idx].len] = c;
				aprs_pack[rptr_idx].len++;
				aprs_pack[rptr_idx].al = EAprsLevel::data;
			}
			break;
		case EAprsLevel::data:
			if (c != '\r')
			{
				aprs_pack[rptr_idx].data[aprs_pack[rptr_idx].len] = c;
				aprs_pack[rptr_idx].len++;

				if (aprs_pack[rptr_idx].len >= 300)
				{
					printf("ERROR in aprs_add_data: Expected END of APRS data\n");
					aprs_pack[rptr_idx].len = 0;
					aprs_pack[rptr_idx].al  = EAprsLevel::none;
				}
			}
			break;
		case EAprsLevel::end:
			if (c == '\r')
			{
				aprs_pack[rptr_idx].data[aprs_pack[rptr_idx].len] = c;
				aprs_pack[rptr_idx].len++;


				bool ok = CheckData(rptr_idx);
				if (ok)
				{
					aprs_pack[rptr_idx].al = EAprsLevel::end;
					return true;
				}
				else
				{
					printf("BAD checksum in APRS data\n");
					aprs_pack[rptr_idx].al = EAprsLevel::none;
					aprs_pack[rptr_idx].len = 0;
					return true;
				}
			}
			else
			{
				aprs_pack[rptr_idx].al = EAprsLevel::none;
				aprs_pack[rptr_idx].len = 0;
			}
			break;
		}
	}
	return false;
}

bool CAPRS::CheckData(int16_t rptr_idx)
{
	unsigned int my_sum;
	char buf[5];

	if ((rptr_idx < 0) || (rptr_idx > 2))
	{
		printf("CAPRS::CheckData(): rptr_idx %d is invalid\n", rptr_idx);
		return false;
	}
	my_sum = CalcCRC(aprs_pack[rptr_idx].data + 10, aprs_pack[rptr_idx].len - 10);

	sprintf(buf, "%04X", my_sum);

	return (0 == memcmp(buf, aprs_pack[rptr_idx].data + 5, 4));
}

unsigned int CAPRS::CalcCRC(uint8_t* buf, unsigned int len)
{
	unsigned int my_crc = 0xffff;

	if (!buf)
		return 0;

	if (len <= 0)
		return 0;

	for (unsigned int j = 0; j < len; j++)
	{
		unsigned int c = buf[j];

		for (unsigned int i = 0; i < 8; i++)
		{
			bool xor_val = (((my_crc ^ c) & 0x01) == 0x01);
			my_crc >>= 1;

			if (xor_val)
				my_crc ^= 0x8408;

			c >>= 1;
		}
	}
	return (~my_crc & 0xffff);
}
