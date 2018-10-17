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

#include "IRCutils.h"

enum aprs_level { al_none, al_$1, al_$2, al_c1, al_r1, al_c2, al_csum1, al_csum2, al_csum3, al_csum4, al_data, al_end };

enum slow_level { sl_first, sl_second };

typedef struct portip_tag {
	std::string ip;
	int port;
} SPORTIP;

typedef struct rptr_tag{
	SPORTIP aprs;
	std::string aprs_filter;
	int aprs_hash;
	int aprs_interval;

	/* 0=A, 1=B, 2=C */
	struct mod_tag {
		std::string call;   /* KJ4NHF-B */
		bool defined;
		std::string band;  /* 23cm ... */
		double frequency, offset, latitude, longitude, range, agl;
		std::string desc1, desc2, desc, url, package_version;
		SPORTIP portip;
	} mod[3];
} SRPTR;

class CAPRS {
public:
	// functions
	CAPRS(SRPTR *prptr);
	~CAPRS();
	SRPTR *m_rptr;
	void SelectBand(short int rptr_idx, unsigned short streamID);
	void ProcessText(unsigned short streamID, unsigned char seq, unsigned char *buf);
	ssize_t WriteSock(char *buffer, size_t n);
	void Open(const std::string OWNER);
	void Init();
	int GetSock();
	void SetSock(int value);

private:
	// data
	// the aprs TCP socket
	int aprs_sock = -1;
	struct sockaddr_in aprs_addr;
	socklen_t aprs_addr_len;
	struct {
		aprs_level al;
		unsigned char data[300];
		unsigned int len;
		unsigned char buf[6];
		slow_level sl;
		bool is_sent;
	} aprs_pack[3];
	// lock down a stream per band
	struct {
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
	bool ResolveRmt(const char *name, int type, struct sockaddr_in *addr);
};
