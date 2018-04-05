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
#include <libconfig.h++>

using namespace libconfig;

#define CALL_SIZE 8
#define IP_SIZE 15

class CMMDVMModem
{
public:
	// functions
	CMMDVMModem();
	~CMMDVMModem();
	void Run(const char *cfgfile);

	// data
	static std::atomic<bool> keep_running;

private:
	// functions
	bool Initialize(const char *cfgfile);
	static void SignalCatch(int signum);
	void ProcessGateway();
	void ProcessMMDVM();

	// read configuration file
	bool ReadConfig(const char *);
	bool GetValue(const Config &cfg, const char *path, int &value, const int min, const int max, const int default_value);
	bool GetValue(const Config &cfg, const char *path, double &value, const double min, const double max, const double default_value);
	bool GetValue(const Config &cfg, const char *path, bool &value, const bool default_value);
	bool GetValue(const Config &cfg, const char *path, std::string &value, const int min, const int max, const char *default_value);

	// config data
	char RPTR_MOD;
	char RPTR[CALL_SIZE + 1];
	char OWNER[CALL_SIZE + 1];
	std::string MMDVM_IP, G2_INTERNAL_IP;
	unsigned short MMDVM_PORT, G2_PORT;
	int WAIT_FOR_PACKETS, DELAY_BEFORE, DELAY_BETWEEN;
	bool RPTR_ACK;

	// parameters
	int gateway_sock, mmdvm_sock;
};
