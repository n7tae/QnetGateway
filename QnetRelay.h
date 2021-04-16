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

#include "UnixPacketSock.h"
#include "KRBase.h"

#define CALL_SIZE 8
#define IP_SIZE 15

class CQnetRelay : CKRBase
{
public:
	// functions
	CQnetRelay(int mod);
	~CQnetRelay();
	bool Run(const char *cfgfile);

private:
	// functions
	bool Initialize(const char *cfgfile);
	bool ProcessGateway(const int len, const unsigned char *raw);
	bool ProcessMMDVM(const int len, const unsigned char *raw);
	int OpenSocket(const std::string &address, unsigned short port);
	int SendTo(const int fd, const unsigned char *buf, const int size, const std::string &address, const unsigned short port);

	// read configuration file
	bool ReadConfig(const char *);

	// Unix sockets
	int assigned_module;
	std::string togate;
	CUnixPacketClient ToGate;

	// config data
	char RPTR_MOD;
	std::string MMDVM_IP;
	unsigned short MMDVM_IN_PORT, MMDVM_OUT_PORT;
	bool log_qso, IS_DSTARREPEATER;

	// parameters
	int msock;
	unsigned int seed;
	unsigned short COUNTER;
};
