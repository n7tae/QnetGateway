/*
 *   Copyright (C) 2016-2020 by Thomas A. Early N7TAE
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

#include "aprs.h"

// This is called when header comes in from repeater
void CAPRS::SelectBand(short int rptr_idx, unsigned short streamID)
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
void CAPRS::ProcessText(unsigned short streamID, unsigned char seq, unsigned char *buf)
{
	unsigned char aprs_data[200];
	char aprs_buf[1024];
	time_t tnow = 0;

	short int rptr_idx = -1;

	for (short int i = 0; i < 3; i++)
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

	sprintf(aprs_buf, "%s,qAR,%s:%s\r\n", hdr, m_rptr->mod[rptr_idx].call.c_str(), aud);
	// printf("GPS-A=%s", aprs_buf);
	int rc = aprs_sock.Write((unsigned char *)aprs_buf, strlen(aprs_buf));
	if (rc == -1)
	{
		if ((errno == EPIPE) ||
				(errno == ECONNRESET) ||
				(errno == ETIMEDOUT) ||
				(errno == ECONNABORTED) ||
				(errno == ESHUTDOWN) ||
				(errno == EHOSTUNREACH) ||
				(errno == ENETRESET) ||
				(errno == ENETDOWN) ||
				(errno == ENETUNREACH) ||
				(errno == EHOSTDOWN) ||
				(errno == ENOTCONN))
		{
			printf("CAPRS::ProcessText(): APRS_HOST closed connection, error=%d\n",errno);
			aprs_sock.Close();
		}
		else   /* if it is WOULDBLOCK, we will not go into a loop here */
			printf("CAPRS::ProcessText(): send error=%d\n", errno);
	}

	time(&aprs_streamID[rptr_idx].last_time);

	return;
}

void CAPRS::Init()
{
	/* Initialize the statistics on the APRS packets */
	for (short int rptr_idx = 0; rptr_idx < 3; rptr_idx++)
	{
		aprs_pack[rptr_idx].al = al_none;
		aprs_pack[rptr_idx].data[0] = '\0';
		aprs_pack[rptr_idx].len = 0;
		aprs_pack[rptr_idx].buf[0] = '\0';
		aprs_pack[rptr_idx].sl = sl_first;
		aprs_pack[rptr_idx].is_sent = false;
	}

	for (short int i = 0; i < 3; i++)
	{
		aprs_streamID[i].streamID = 0;
		aprs_streamID[i].last_time = 0;
	}

	return;
}

bool CAPRS::WriteData(short int rptr_idx, unsigned char *data)
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
	case sl_first:
		aprs_pack[rptr_idx].buf[0] = data[0] ^ 0x70;
		aprs_pack[rptr_idx].buf[1] = data[1] ^ 0x4f;
		aprs_pack[rptr_idx].buf[2] = data[2] ^ 0x93;
		aprs_pack[rptr_idx].sl = sl_second;
		return false;

	case sl_second:
		aprs_pack[rptr_idx].buf[3] = data[0] ^ 0x70;
		aprs_pack[rptr_idx].buf[4] = data[1] ^ 0x4f;
		aprs_pack[rptr_idx].buf[5] = data[2] ^ 0x93;
		aprs_pack[rptr_idx].sl = sl_first;
		break;
	}

	if ((aprs_pack[rptr_idx].buf[0] & 0xf0) != 0x30)
		return false;

	return AddData(rptr_idx, aprs_pack[rptr_idx].buf + 1);

}

void CAPRS::SyncIt(short int rptr_idx)
{
	if ((rptr_idx < 0) || (rptr_idx > 2))
	{
		printf("CAPRS::SyncIt(): rptr_idx %d is invalid\n", rptr_idx);
		return;
	}

	aprs_pack[rptr_idx].sl = sl_first;
	return;
}

void CAPRS::Reset(short int rptr_idx)
{
	if ((rptr_idx < 0) || (rptr_idx > 2))
	{
		printf("CAPRS::Reset(): rptr_idx %d is invalid\n", rptr_idx);
		return;
	}

	aprs_pack[rptr_idx].al = al_none;
	aprs_pack[rptr_idx].len = 0;
	aprs_pack[rptr_idx].sl = sl_first;
	aprs_pack[rptr_idx].is_sent = false;

	return;
}

unsigned int CAPRS::GetData(short int rptr_idx, unsigned char *data, unsigned int len)
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

	aprs_pack[rptr_idx].al = al_none;
	aprs_pack[rptr_idx].len = 0;
	aprs_pack[rptr_idx].is_sent = true;

	return l;
}

void CAPRS::Open(const std::string OWNER)
{
	char snd_buf[512];
	char rcv_buf[512];
	while (aprs_sock.Open(m_rptr->aprs.ip, AF_UNSPEC, std::to_string(m_rptr->aprs.port)))
	{
		fprintf(stderr, "Failed to open %s, retry in 10 seconds...\n", m_rptr->aprs.ip.c_str());
		std::this_thread::sleep_for(std::chrono::seconds(10));
	}

	/* login to aprs */
	//sprintf(snd_buf, "user %s pass %d vers QnetGateway 9 UDP 5 ", OWNER.c_str(), m_rptr->aprs_hash);
	sprintf(snd_buf, "user %s pass %d vers QnetGateway-9 ", OWNER.c_str(), m_rptr->aprs_hash);

	/* add the user's filter */
	if (m_rptr->aprs_filter.length())
	{
		strcat(snd_buf, "filter ");
		strcat(snd_buf, m_rptr->aprs_filter.c_str());
	}
	//printf("APRS Login command:[%s]\n", snd_buf);
	strcat(snd_buf, "\r\n");

	while (true)
	{
		int rc = aprs_sock.Write((unsigned char *)snd_buf, strlen(snd_buf));
		if (rc < 0)
		{
			if (errno == EWOULDBLOCK)
			{
				aprs_sock.Read((unsigned char *)rcv_buf, sizeof(rcv_buf));
				std::this_thread::sleep_for(std::chrono::milliseconds(100));
			}
			else
			{
				printf("APRS Login command failed, error=%d\n", errno);
				break;
			}
		}
		else
		{
			// printf("APRS Login command sent\n");
			break;
		}
	}
	aprs_sock.Read((unsigned char *)rcv_buf, sizeof(rcv_buf));
	//printf("APRS Login returned: %s", rcv_buf);
	return;
}

bool CAPRS::AddData(short int rptr_idx, unsigned char *data)
{
	if ((rptr_idx < 0) || (rptr_idx > 2))
	{
		printf("CAPRS::AddData(): rptr_idx %d is invalid\n", rptr_idx);
		return false;
	}

	for (unsigned int i = 0; i < 5; i++)
	{
		unsigned char c = data[i];

		if ((aprs_pack[rptr_idx].al == al_none) && (c == '$'))
		{
			aprs_pack[rptr_idx].data[aprs_pack[rptr_idx].len] = c;
			aprs_pack[rptr_idx].len++;
			aprs_pack[rptr_idx].al = al_$1;
		}
		else if ((aprs_pack[rptr_idx].al == al_$1) && (c == '$'))
		{
			aprs_pack[rptr_idx].data[aprs_pack[rptr_idx].len] = c;
			aprs_pack[rptr_idx].len++;
			aprs_pack[rptr_idx].al = al_$2;
		}
		else if ((aprs_pack[rptr_idx].al == al_$2) && (c == 'C'))
		{
			aprs_pack[rptr_idx].data[aprs_pack[rptr_idx].len] = c;
			aprs_pack[rptr_idx].len++;
			aprs_pack[rptr_idx].al = al_c1;
		}
		else if ((aprs_pack[rptr_idx].al == al_c1) && (c == 'R'))
		{
			aprs_pack[rptr_idx].data[aprs_pack[rptr_idx].len] = c;
			aprs_pack[rptr_idx].len++;
			aprs_pack[rptr_idx].al = al_r1;
		}
		else if ((aprs_pack[rptr_idx].al  == al_r1) && (c == 'C'))
		{
			aprs_pack[rptr_idx].data[aprs_pack[rptr_idx].len] = c;
			aprs_pack[rptr_idx].len++;
			aprs_pack[rptr_idx].al = al_c2;
		}
		else if (aprs_pack[rptr_idx].al == al_c2)
		{
			aprs_pack[rptr_idx].data[aprs_pack[rptr_idx].len] = c;
			aprs_pack[rptr_idx].len++;
			aprs_pack[rptr_idx].al = al_csum1;
		}
		else if (aprs_pack[rptr_idx].al == al_csum1)
		{
			aprs_pack[rptr_idx].data[aprs_pack[rptr_idx].len] = c;
			aprs_pack[rptr_idx].len++;
			aprs_pack[rptr_idx].al = al_csum2;
		}
		else if (aprs_pack[rptr_idx].al == al_csum2)
		{
			aprs_pack[rptr_idx].data[aprs_pack[rptr_idx].len] = c;
			aprs_pack[rptr_idx].len++;
			aprs_pack[rptr_idx].al = al_csum3;
		}
		else if (aprs_pack[rptr_idx].al == al_csum3)
		{
			aprs_pack[rptr_idx].data[aprs_pack[rptr_idx].len] = c;
			aprs_pack[rptr_idx].len++;
			aprs_pack[rptr_idx].al = al_csum4;
		}
		else if ((aprs_pack[rptr_idx].al == al_csum4) && (c == ','))
		{
			aprs_pack[rptr_idx].data[aprs_pack[rptr_idx].len] = c;
			aprs_pack[rptr_idx].len++;
			aprs_pack[rptr_idx].al = al_data;
		}
		else if ((aprs_pack[rptr_idx].al == al_data) && (c != '\r'))
		{
			aprs_pack[rptr_idx].data[aprs_pack[rptr_idx].len] = c;
			aprs_pack[rptr_idx].len++;

			if (aprs_pack[rptr_idx].len >= 300)
			{
				printf("ERROR in aprs_add_data: Expected END of APRS data\n");
				aprs_pack[rptr_idx].len = 0;
				aprs_pack[rptr_idx].al  = al_none;
			}
		}
		else if ((aprs_pack[rptr_idx].al == al_data) && (c == '\r'))
		{
			aprs_pack[rptr_idx].data[aprs_pack[rptr_idx].len] = c;
			aprs_pack[rptr_idx].len++;


			bool ok = CheckData(rptr_idx);
			if (ok)
			{
				aprs_pack[rptr_idx].al = al_end;
				return true;
			}
			else
			{
				printf("BAD checksum in APRS data\n");
				aprs_pack[rptr_idx].al  = al_none;
				aprs_pack[rptr_idx].len = 0;
			}
		}
		else
		{
			aprs_pack[rptr_idx].al  = al_none;
			aprs_pack[rptr_idx].len = 0;
		}
	}
	return false;
}

bool CAPRS::CheckData(short int rptr_idx)
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

unsigned int CAPRS::CalcCRC(unsigned char* buf, unsigned int len)
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

CAPRS::CAPRS(SRPTR *prptr)
{
	m_rptr = prptr;
}

CAPRS::~CAPRS()
{
	aprs_sock.Close();
}

void CAPRS::CloseSock()
{
	aprs_sock.Close();
}
