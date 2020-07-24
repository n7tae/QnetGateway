#pragma once

/*
 *   Copyright (C) 2016 by Thomas A. Early N7TAE
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

#include <string>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "TCPReaderWriterClient.h"
#include "IRCutils.h"

enum aprs_level { al_none, al_$1, al_$2, al_c1, al_r1, al_c2, al_csum1, al_csum2, al_csum3, al_csum4, al_data, al_end };

enum slow_level { sl_first, sl_second };

using SPORTIP = struct portip_tag
{
	std::string ip;
	int port;
};

using SMOD = struct aprs_module
{
	std::string call;   /* KJ4NHF-B */
	bool defined;
	std::string band;  /* 23cm ... */
	double frequency, offset, latitude, longitude, range, agl;
	std::string desc1, desc2, url, package_version;
};

using SRPTR = struct aprs_info
{
	SPORTIP aprs;
	std::string aprs_filter;
	int aprs_hash;
	int aprs_interval;

	/* 0=A, 1=B, 2=C */
	SMOD mod[3];
};

class CAPRS
{
public:
	// functions
	CAPRS(SRPTR *prptr);
	~CAPRS();
	SRPTR *m_rptr;
	void SelectBand(short int rptr_idx, unsigned short streamID);
	void ProcessText(unsigned short streamID, unsigned char seq, unsigned char *buf);
	void Open(const std::string OWNER);
	void Init();
	void CloseSock();
	CTCPReaderWriterClient aprs_sock;

private:
	// data
	struct
	{
		aprs_level al;
		unsigned char data[300];
		unsigned int len;
		unsigned char buf[6];
		slow_level sl;
		bool is_sent;
	} aprs_pack[3];
	// lock down a stream per band
	struct
	{
		unsigned short streamID;
		time_t last_time;
	} aprs_streamID[3];

	// functions
	bool WriteData(short int rptr_idx, unsigned char *data);
	void SyncIt(short int rptr_idx);
	void Reset(short int rptr_idx);
	unsigned int GetData(short int rptr_idx, unsigned char *data, unsigned int len);
	bool AddData(short int rptr_idx, unsigned char *data);
	bool CheckData(short int rptr_idx);
	unsigned int CalcCRC(unsigned char* buf, unsigned int len);
};
