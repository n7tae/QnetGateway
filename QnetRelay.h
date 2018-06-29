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

#include <netinet/in.h>

using namespace libconfig;

#define CALL_SIZE 8
#define IP_SIZE 15

class CQnetRelay
{
public:
	// functions
	CQnetRelay();
	~CQnetRelay();
	void Run(const char *cfgfile);

	// data
	static std::atomic<bool> keep_running;

private:
	// functions
	bool Initialize(const char *cfgfile);
	static void SignalCatch(const int signum);
	bool ProcessGateway(const int len, const unsigned char *raw);
	bool ProcessMMDVM(const int len, const unsigned char *raw);
	int OpenSocket(const std::string &address, unsigned short port);
	int SendTo(const int fd, const unsigned char *buf, const int size, const std::string &address, const unsigned short port);

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
	unsigned short MMDVM_IN_PORT, MMDVM_OUT_PORT, G2_IN_PORT, G2_OUT_PORT;
	bool log_qso;

	// parameters
	int msock, gsock;
	unsigned int seed;
	unsigned short COUNTER;
};
