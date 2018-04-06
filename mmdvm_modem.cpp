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

#include <exception>
#include <cstdio>
#include <cctype>
#include <cstring>
#include <csignal>
#include <ctime>

#include "versions.h"
#include "mmdvm_modem.h"
#include "UDPSocket.h"
#include "g2_typedefs.h"

std::atomic<bool> CMMDVMModem::keep_running(true);

CMMDVMModem::CMMDVMModem()
{
}

CMMDVMModem::~CMMDVMModem()
{
}

bool CMMDVMModem::Initialize(const char *cfgfile)
{
	if (ReadConfig(cfgfile))
		return true;

	struct sigaction act;
	act.sa_handler = &CMMDVMModem::SignalCatch;
	sigemptyset(&act.sa_mask);
	if (sigaction(SIGTERM, &act, 0) != 0) {
		printf("sigaction-TERM failed, error=%d\n", errno);
		return true;
	}
	if (sigaction(SIGHUP, &act, 0) != 0) {
		printf("sigaction-HUP failed, error=%d\n", errno);
		return true;
	}
	if (sigaction(SIGINT, &act, 0) != 0) {
		printf("sigaction-INT failed, error=%d\n", errno);
		return true;
	}

	return false;
}

void CMMDVMModem::Run(const char *cfgfile)
{
	if (Initialize(cfgfile))
		return;

	CUDPSocket GatewaySock(G2_INTERNAL_IP, G2_INTERNAL_PORT);
	if (GatewaySock.open())
		return;

	CUDPSocket MMDVMSock(MMDVM_IP, MMDVM_PORT);
	if (MMDVMSock.open()) {
		GatewaySock.close();
		return;
	}

	keep_running = true;


	while (keep_running) {
		ProcessMMDVM(GatewaySock, MMDVMSock);
		if (keep_running)
			ProcessGateway(GatewaySock, MMDVMSock);
	}

	MMDVMSock.close();
	GatewaySock.close();
}

void CMMDVMModem::ProcessGateway(CUDPSocket &gsock, CUDPSocket &msock)
{
	SPKT buf;
	unsigned int port;

	// read from gateway
	int len = gsock.read(buf.pkt_id, 58, g2_internal_addr, port);

	if (0 == len)
		return;

	if (0 > len) {
		printf("ERROR: ProcessGateway: Can't read gateway packet\n");
		keep_running = false;
		return;
	}

	// if there is data, translate it and send it to the MMDVM Modem
	if (29==len || 58==len) { //here is dstar data
		SMMDVMPKT pkt;

		memcpy(pkt.title, "DSRP", 4);
		if (29 == len) {	// write an AMBE packet
			pkt.tag = 0x21U;
			pkt.voice.id = buf.vpkt.streamid;
			pkt.voice.seq = buf.vpkt.ctrl;
			if (pkt.voice.seq & 0x40)
				printf("INFO: ProcessGateway: sending voice end-of-stream\n");
			else if (pkt.voice.seq > 20)
				printf("DEBUG: ProcessGateway: unexpected voice sequence number %d\n", pkt.voice.seq);

			memcpy(pkt.voice.ambe, buf.vpkt.vasd.text, 12);
			if (false == msock.write(pkt.title, 21, mmdvm_addr, MMDVM_PORT)) {
				printf("ERROR: ProcessGateway: Could not write AMBE mmdvm packet\n");
				keep_running = false;
				return;
			}
		} else {			// write a Header packet
			pkt.tag = 0x20U;
			pkt.header.id = buf.vpkt.streamid;
			pkt.header.seq = buf.vpkt.ctrl;
			if (pkt.header.seq) {
				printf("DEBUG: ProcessGateway: unexpected .header.seq %d, resetting to 0\n", pkt.header.seq);
				pkt.header.seq = 0;
			}

			memcpy(pkt.header.flag, buf.vpkt.hdr.flag, 41);
			if (false == msock.write(pkt.title, 49, mmdvm_addr, MMDVM_PORT)) {
				printf("ERROR: ProcessGateway: Could not write Header mmdvm packet\n");
				keep_running = false;
			}
		}
	} else
		printf("DEBUG: ProcessGateway: unusual packet size read len=%d\n", len);
}

void CMMDVMModem::ProcessMMDVM(CUDPSocket &gsock, CUDPSocket &msock)
{
	SMMDVMPKT mpkt;
	unsigned int mmdvm_port = MMDVM_PORT;
	in_addr addr;
	addr.s_addr = mmdvm_addr.s_addr;

	// read from the MMDVM modem
	int len = msock.read(mpkt.title, 64, addr, mmdvm_port);

	if (0 == len)	// no data available
		return;

	if (0 > len) {
		printf("ERROR: ProcessMMDVM: Could not read mmdvm packet\n");
		keep_running = false;
		return;
	}

	// if there is data, translate it and send it to the Gateway
	if (21==len || 49==len) {
		unsigned int g2_internal_port = G2_INTERNAL_PORT;

		SPKT gpkt;
		memcpy(gpkt.pkt_id, "DSTR", 4);
		gpkt.counter = 0;
		gpkt.flag[0] = 0x72;
		gpkt.flag[1] = 0x12;
		gpkt.flag[2] = 0x0;
		gpkt.remaining = (21 == len) ? 0x16 : 0x30;
		gpkt.vpkt.icm_id = 0x20;
		gpkt.vpkt.dst_rptr_id = 0x0;
		gpkt.vpkt.snd_rptr_id = 0x1;
		gpkt.vpkt.snd_term_id = ('B'==RPTR_MOD) ? 0x1 : (('C'==RPTR_MOD) ? 0x2 : 0x3);

		if (false == gsock.write(gpkt.pkt_id, (21==len) ? 29 : 58, g2_internal_addr, g2_internal_port)) {
			printf("ERROR: ProcessMMDVM: Could not write gateway packet\n");
			keep_running = false;
		}
	} else
		printf("DEBUG: ProcessMMDVM: unusual packet size read len=%d\n", len);
}

bool CMMDVMModem::GetValue(const Config &cfg, const char *path, int &value, const int min, const int max, const int default_value)
{
	if (cfg.lookupValue(path, value)) {
		if (value < min || value > max)
			value = default_value;
	} else
		value = default_value;
	printf("%s = [%d]\n", path, value);
	return true;
}

bool CMMDVMModem::GetValue(const Config &cfg, const char *path, double &value, const double min, const double max, const double default_value)
{
	if (cfg.lookupValue(path, value)) {
		if (value < min || value > max)
			value = default_value;
	} else
		value = default_value;
	printf("%s = [%lg]\n", path, value);
	return true;
}

bool CMMDVMModem::GetValue(const Config &cfg, const char *path, bool &value, const bool default_value)
{
	if (! cfg.lookupValue(path, value))
		value = default_value;
	printf("%s = [%s]\n", path, value ? "true" : "false");
	return true;
}

bool CMMDVMModem::GetValue(const Config &cfg, const char *path, std::string &value, int min, int max, const char *default_value)
{
	if (cfg.lookupValue(path, value)) {
		int l = value.length();
		if (l<min || l>max) {
			printf("%s value '%s' is wrong size\n", path, value.c_str());
			return false;
		}
	} else
		value = default_value;
	printf("%s = [%s]\n", path, value.c_str());
	return true;
}

// process configuration file and return true if there was a problem
bool CMMDVMModem::ReadConfig(const char *cfgFile)
{
	Config cfg;

	printf("Reading file %s\n", cfgFile);
	// Read the file. If there is an error, report it and exit.
	try {
		cfg.readFile(cfgFile);
	}
	catch(const FileIOException &fioex) {
		printf("Can't read %s\n", cfgFile);
		return true;
	}
	catch(const ParseException &pex) {
		printf("Parse error at %s:%d - %s\n", pex.getFile(), pex.getLine(), pex.getError());
		return true;
	}

	std::string mmdvm_path, value;
	int i;
	for (i=0; i<3; i++) {
		mmdvm_path = "module.";
		mmdvm_path += ('a' + i);
		if (cfg.lookupValue(mmdvm_path + ".type", value)) {
			if (0 == strcasecmp(value.c_str(), "mmdvm"))
				break;
		}
	}
	if (i >= 3) {
		printf("mmdvm not defined in any module!\n");
		return true;
	}
	RPTR_MOD = 'A' + i;

	if (cfg.lookupValue(std::string(mmdvm_path+".callsign").c_str(), value) || cfg.lookupValue("ircddb.login", value)) {
		int l = value.length();
		if (l<3 || l>CALL_SIZE-2) {
			printf("Call '%s' is invalid length!\n", value.c_str());
			return true;
		} else {
			for (i=0; i<l; i++) {
				if (islower(value[i]))
					value[i] = toupper(value[i]);
			}
			value.resize(CALL_SIZE, ' ');
		}
		strcpy(RPTR, value.c_str());
	} else {
		printf("%s.login is not defined!\n", mmdvm_path.c_str());
		return true;
	}

	if (cfg.lookupValue("ircddb.login", value)) {
		int l = value.length();
		if (l<3 || l>CALL_SIZE-2) {
			printf("Call '%s' is invalid length!\n", value.c_str());
			return true;
		} else {
			for (i=0; i<l; i++) {
				if (islower(value[i]))
					value[i] = toupper(value[i]);
			}
			value.resize(CALL_SIZE, ' ');
		}
		strcpy(OWNER, value.c_str());
		printf("ircddb.login = [%s]\n", OWNER);
	} else {
		printf("ircddb.login is not defined!\n");
		return true;
	}

	if (GetValue(cfg, std::string(mmdvm_path+".internal_ip").c_str(), value, 7, IP_SIZE, "0.0.0.0")) {
		MMDVM_IP = value;
		inet_aton(MMDVM_IP.c_str(), &mmdvm_addr);
	} else
		return true;

	GetValue(cfg, std::string(mmdvm_path+".port").c_str(), i, 10000, 65535, 20010);
	MMDVM_PORT = (unsigned short)i;

	if (GetValue(cfg, "gateway.ip", value, 7, IP_SIZE, "127.0.0.1")) {
		G2_INTERNAL_IP = value;
		inet_aton(G2_INTERNAL_IP.c_str(), &g2_internal_addr);
	} else
		return true;

	GetValue(cfg, "gateway.internal.port", i, 10000, 65535, 20010);
	G2_INTERNAL_PORT = (unsigned short)i;

	GetValue(cfg, "timing.play.delay", DELAY_BETWEEN, 9, 25, 19);

	GetValue(cfg, "timing.play.wait", DELAY_BEFORE, 1, 10, 2);

	GetValue(cfg, std::string(mmdvm_path+".acknowledge").c_str(), RPTR_ACK, false);

	GetValue(cfg, std::string(mmdvm_path+".packet_wait").c_str(), WAIT_FOR_PACKETS, 6, 100, 25);

	return false;
}

void CMMDVMModem::SignalCatch(int signum)
{
	if ((signum == SIGTERM) || (signum == SIGINT)  || (signum == SIGHUP))
		keep_running = false;
	exit(0);
}

int main(int argc, const char **argv)
{
	setbuf(stdout, NULL);
	if (2 != argc) {
		printf("usage: %s path_to_config_file\n", argv[0]);
		printf("       %s --version\n", argv[0]);
		return 1;
	}

	if ('-' == argv[1][0]) {
		printf("\nMMDVM Modem Version #%s Copyright (C) 2018 by Thomas A. Early N7TAE\n", MMDVM_VERSION);
		printf("MMDVM Modem comes with ABSOLUTELY NO WARRANTY; see the LICENSE for details.\n");
		printf("This is free software, and you are welcome to distribute it\nunder certain conditions that are discussed in the LICENSE file.\n\n");
		return 0;
	}

	CMMDVMModem mmdvm;

	mmdvm.Run(argv[1]);

	printf("%s is closing.\n", argv[0]);

	return 0;
}
