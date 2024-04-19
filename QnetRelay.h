/*
 *   Copyright (C) 2018 by Thomas A. Early N7TAE
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
#include <string>
#include <netinet/in.h>

#include "UnixDgramSocket.h"
#include "Base.h"

#define CALL_SIZE 8
#define IP_SIZE 15

class CQnetRelay : public CModem
{
public:
	// functions
	CQnetRelay(int mod) : CModem(mod), seed(time(NULL)), COUNTER(0) {}
	~CQnetRelay() {}
	bool Initialize(const std::string &cfgfile);
	void Run();
	void Close();

private:
	// functions
	bool ProcessGateway(const int len, const unsigned char *raw);
	bool ProcessMMDVM(const int len, const unsigned char *raw);
	int OpenSocket(const std::string &address, unsigned short port);
	int SendTo(const int fd, const unsigned char *buf, const int size, const std::string &address, const unsigned short port);

	// read configuration file
	bool ReadConfig(const std::string &);

	// Unix sockets
	CUnixDgramWriter ToGate;
	CUnixDgramReader FromGate;

	// config data
	char RPTR_MOD;
	std::string MMDVM_INTERNAL_IP, MMDVM_TARGET_IP;
	unsigned short MMDVM_IN_PORT, MMDVM_OUT_PORT;
	bool log_qso, IS_DSTARREPEATER;

	// parameters
	int msock;
	unsigned int seed;
	unsigned short COUNTER;
};
