
/*
 *   Copyright (C) 2010 by Scott Lawson KI4LKF
 *   Copyright (C) 2015,2018,2019 by Thomas A. Early N7TAE
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


/* by KI4LKF and N7TAE*/

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <regex.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>
#include <netdb.h>

#include <iostream>
#include <fstream>
#include <future>
#include <exception>
#include <utility>
#include <thread>
#include <chrono>

#include "versions.h"
#include "DPlusAuthenticator.h"
#include "QnetConfigure.h"
#include "QnetLink.h"

std::atomic<bool> CQnetLink::keep_running(true);

CQnetLink::CQnetLink()
{
	memset(tracing, 0, 3 * sizeof(struct tracing_tag));
	memset(dtmf_mycall, 0, 3 * (CALL_SIZE+1));
	memset(old_sid, 0, 6);
}

CQnetLink::~CQnetLink()
{
	speak.clear();
}

bool CQnetLink::resolve_rmt(char *name, int type, struct sockaddr_in *addr)
{
	struct addrinfo hints;
	struct addrinfo *res;
	struct addrinfo *rp;
	bool found = false;

	memset(&hints, 0x00, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = type;

	int rc = getaddrinfo(name, NULL, &hints, &res);
	if (rc != 0) {
		printf("getaddrinfo return error code %d for [%s]\n", rc, name);
		return false;
	}

	for (rp = res; rp != NULL; rp = rp->ai_next) {
		if ((rp->ai_family == AF_INET) &&
		        (rp->ai_socktype == type)) {
			memcpy(addr, rp->ai_addr, sizeof(struct sockaddr_in));
			found = true;
			break;
		}
	}
	freeaddrinfo(res);
	return found;
}

/* send keepalive to donglers */
void CQnetLink::send_heartbeat()
{
	bool removed = false;

	for (auto pos = inbound_list.begin(); pos != inbound_list.end(); pos++) {
		SINBOUND *inbound = (SINBOUND *)pos->second;
		sendto(ref_g2_sock, REF_ACK, 3, 0, (struct sockaddr *)&(inbound->sin), sizeof(struct sockaddr_in));

		if (inbound->countdown >= 0)
			inbound->countdown --;

		if (inbound->countdown < 0) {
			removed = true;
			printf("call=%s timeout, removing %s, users=%d\n", inbound->call, pos->first.c_str(), (int)inbound_list.size() - 1);

			free(pos->second);
			pos->second = NULL;
			inbound_list.erase(pos);
		}
	}
	if (removed)
		print_status_file();
}

void CQnetLink::rptr_ack(short i)
{
	static char mod_and_RADIO_ID[3][22];

	memset(mod_and_RADIO_ID[i], ' ', 21);
	mod_and_RADIO_ID[i][21] = '\0';

	if (i == 0)
		mod_and_RADIO_ID[i][0] = 'A';
	else if (i == 1)
		mod_and_RADIO_ID[i][0] = 'B';
	else if (i == 2)
		mod_and_RADIO_ID[i][0] = 'C';

	if (to_remote_g2[i].is_connected) {
		memcpy(mod_and_RADIO_ID[i] + 1, "LINKED TO ", 10);
		memcpy(mod_and_RADIO_ID[i] + 11, to_remote_g2[i].to_call, CALL_SIZE);
		mod_and_RADIO_ID[i][11 + CALL_SIZE] = to_remote_g2[i].to_mod;
	} else if (to_remote_g2[i].to_call[0] != '\0') {
		memcpy(mod_and_RADIO_ID[i] + 1, "TRYING    ", 10);
		memcpy(mod_and_RADIO_ID[i] + 11, to_remote_g2[i].to_call, CALL_SIZE);
		mod_and_RADIO_ID[i][11 + CALL_SIZE] = to_remote_g2[i].to_mod;
	} else {
		memcpy(mod_and_RADIO_ID[i] + 1, "NOT LINKED", 10);
	}
	try {
		std::async(std::launch::async, &CQnetLink::RptrAckThread, this, mod_and_RADIO_ID[i]);
	} catch (const std::exception &e) {
		printf("Failed to start RptrAckThread(). Exception: %s\n", e.what());
	}
	return;
}

void CQnetLink::RptrAckThread(char *arg)
{
	char from_mod = arg[0];
	char RADIO_ID[21];
	memcpy(RADIO_ID, arg + 1, 21);
	unsigned char silence[12] = { 0x9E, 0x8D, 0x32, 0x88, 0x26, 0x1A, 0x3F, 0x61, 0xE8, 0x16, 0x29, 0xf5 };
	struct sigaction act;

	act.sa_handler = sigCatch;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	if (sigaction(SIGTERM, &act, 0) != 0) {
		printf("sigaction-TERM failed, error=%d\n", errno);
		return;
	}
	if (sigaction(SIGINT, &act, 0) != 0) {
		printf("sigaction-INT failed, error=%d\n", errno);
		return;
	}

	short int streamid_raw = Random.NewStreamID();

	sleep(delay_before);

	printf("sending ACK+text, mod:[%c], RADIO_ID=[%s]\n", from_mod, RADIO_ID);

	SDSVT dsvt;

	memcpy(dsvt.title, "DSVT", 4);
	dsvt.config  = 0x10;
	dsvt.flaga[0] = dsvt.flaga[1] = dsvt.flaga[2]  = 0x0;

	dsvt.id  = 0x20;
	dsvt.flagb[0] =dsvt.flagb[2]  = 0x0;
	dsvt.flagb[1] = 0x1;

	dsvt.streamid = htons(streamid_raw);
	dsvt.ctrl = 0x80;
	dsvt.hdr.flag[0] = 0x1;
	dsvt.hdr.flag[1] = dsvt.hdr.flag[2] = 0x0;

	memcpy(dsvt.hdr.rpt1, owner.c_str(), CALL_SIZE);
	dsvt.hdr.rpt1[7] = from_mod;

	memcpy(dsvt.hdr.rpt2,  owner.c_str(), CALL_SIZE);
	dsvt.hdr.rpt2[7] = 'G';

	memcpy(dsvt.hdr.urcall, "CQCQCQ  ", CALL_SIZE);

	memcpy(dsvt.hdr.mycall, owner.c_str(), CALL_SIZE);
	dsvt.hdr.mycall[7] = from_mod;

	memcpy(dsvt.hdr.sfx, "RPTR", 4);
	calcPFCS(dsvt.title,56);
	Link2Gate.Write(dsvt.title, 56);
	//std::this_thread::sleep_for(std::chrono::milliseconds(delay_between))

	dsvt.config = 0x20;
	memcpy(dsvt.vasd.voice, silence, 9);

	/* start sending silence + announcement text */

	for (int i=0; i<10; i++) {
		dsvt.ctrl = (unsigned char)i;
		switch (i) {
			case 0:
				dsvt.vasd.text[0] = 0x55;
				dsvt.vasd.text[1] = 0x2d;
				dsvt.vasd.text[2] = 0x16;
				break;
			case 1:
				dsvt.vasd.text[0] = '@' ^ 0x70;
				dsvt.vasd.text[1] = RADIO_ID[0] ^ 0x4f;
				dsvt.vasd.text[2] = RADIO_ID[1] ^ 0x93;
				break;
			case 2:
				dsvt.vasd.text[0] = RADIO_ID[2] ^ 0x70;
				dsvt.vasd.text[1] = RADIO_ID[3] ^ 0x4f;
				dsvt.vasd.text[2] = RADIO_ID[4] ^ 0x93;
				break;
			case 3:
				dsvt.vasd.text[0] = 'A' ^ 0x70;
				dsvt.vasd.text[1] = RADIO_ID[5] ^ 0x4f;
				dsvt.vasd.text[2] = RADIO_ID[6] ^ 0x93;
				break;
			case 4:
				dsvt.vasd.text[0] = RADIO_ID[7] ^ 0x70;
				dsvt.vasd.text[1] = RADIO_ID[8] ^ 0x4f;
				dsvt.vasd.text[2] = RADIO_ID[9] ^ 0x93;
				break;
			case 5:
				dsvt.vasd.text[0] = 'B' ^ 0x70;
				dsvt.vasd.text[1] = RADIO_ID[10] ^ 0x4f;
				dsvt.vasd.text[2] = RADIO_ID[11] ^ 0x93;
				break;
			case 6:
				dsvt.vasd.text[0] = RADIO_ID[12] ^ 0x70;
				dsvt.vasd.text[1] = RADIO_ID[13] ^ 0x4f;
				dsvt.vasd.text[2] = RADIO_ID[14] ^ 0x93;
				break;
			case 7:
				dsvt.vasd.text[0] = 'C' ^ 0x70;
				dsvt.vasd.text[1] = RADIO_ID[15] ^ 0x4f;
				dsvt.vasd.text[2] = RADIO_ID[16] ^ 0x93;
				break;
			case 8:
				dsvt.vasd.text[0] = RADIO_ID[17] ^ 0x70;
				dsvt.vasd.text[1] = RADIO_ID[18] ^ 0x4f;
				dsvt.vasd.text[2] = RADIO_ID[19] ^ 0x93;
				break;
			case 9:
				dsvt.ctrl |= 0x40;
				dsvt.vasd.text[0] = 0x16;
				dsvt.vasd.text[1] = 0x29;
				dsvt.vasd.text[2] = 0xf5;
				break;
		}
		Link2Gate.Write(dsvt.title, 27);
		if (i < 9)
			std::this_thread::sleep_for(std::chrono::milliseconds(delay_between));
	}
}

void CQnetLink::print_status_file()
{
	FILE *statusfp = fopen(status_file.c_str(), "w");
	if (!statusfp)
		printf("Failed to create status file %s\n", status_file.c_str());
	else {
		setvbuf(statusfp, (char *)NULL, _IOLBF, 0);
		struct tm tm1;
		time_t tnow;
		const char *fstr = "%c,%s,%c,%s,%02d%02d%02d,%02d:%02d:%02d\n";
		time(&tnow);
		localtime_r(&tnow, &tm1);

		/* print connected donglers */
		for (auto pos = inbound_list.begin(); pos != inbound_list.end(); pos++) {
			SINBOUND *inbound = (SINBOUND *)pos->second;
			fprintf(statusfp, fstr, 'p', inbound->call, 'p', pos->first.c_str(), tm1.tm_mon+1,tm1.tm_mday,tm1.tm_year % 100, tm1.tm_hour,tm1.tm_min,tm1.tm_sec);
		}

		/* print linked repeaters-reflectors */
		for (int i=0; i<3;i++) {
			if (to_remote_g2[i].is_connected) {
				fprintf(statusfp, fstr, to_remote_g2[i].from_mod, to_remote_g2[i].to_call, to_remote_g2[i].to_mod, inet_ntoa(to_remote_g2[i].toDst4.sin_addr),
					tm1.tm_mon+1, tm1.tm_mday ,tm1.tm_year % 100, tm1.tm_hour, tm1.tm_min, tm1.tm_sec);
			}
		}
		fclose(statusfp);
	}
}

/* Open text file of repeaters, reflectors */
bool CQnetLink::load_gwys(const std::string &filename)
{
	// DPlus Authenticate
	if (dplus_authorize && !dplus_priority) {
		CDPlusAuthenticator auth(login_call, std::string("auth.dstargateway.org"));
		if (auth.Process(gwy_list, dplus_reflectors, dplus_repeaters))
			fprintf(stdout, "DPlus Authorization complete.\n");
		else
			fprintf(stderr, "DPlus Authorization failed!\n");
	}

	char inbuf[1024];
	const char *delim = " ";

	char call[CALL_SIZE + 1];
	char host[MAXHOSTNAMELEN + 1];
	char port[5 + 1];

	/* host + space + port + NULL */
	char payload[MAXHOSTNAMELEN + 1 + 5 + 1];
	unsigned short j;

	printf("Trying to open file %s\n", filename.c_str());
	FILE *fp = fopen(filename.c_str(), "r");
	if (fp == NULL) {
		printf("Failed to open file %s\n", filename.c_str());
		return false;
	}
	printf("Opened file %s OK\n", filename.c_str());

	while (fgets(inbuf, 1020, fp) != NULL) {
		char *p = strchr(inbuf, '\r');
		if (p)
			*p = '\0';

		p = strchr(inbuf, '\n');
		if (p)
			*p = '\0';

		p = strchr(inbuf, '#');
		if (p) {
			printf("Comment line:[%s]\n", inbuf);
			continue;
		}

		/* get the call */
		char *tok = strtok(inbuf, delim);
		if (!tok)
			continue;
		if ((strlen(tok) > CALL_SIZE) || (strlen(tok) < 3)) {
			printf("Invalid call [%s]\n", tok);
			continue;
		}
		memset(call, ' ', CALL_SIZE);
		call[CALL_SIZE] = '\0';
		memcpy(call, tok, strlen(tok));
		for (j = 0; j < strlen(call); j++)
			call[j] = toupper(call[j]);
		if (strcmp(call, owner.c_str()) == 0) {
			printf("Call [%s] will not be loaded\n", call);
			continue;
		}

		/* get the host */
		tok = strtok(NULL, delim);
		if (!tok) {
			printf("Call [%s] has no host\n", call);
			continue;
		}
		strncpy(host,tok,MAXHOSTNAMELEN);
		host[MAXHOSTNAMELEN] = '\0';
		if (strcmp(host, "0.0.0.0") == 0) {
			printf("call %s has invalid host %s\n", call, host);
			continue;
		}

		/* get the port */
		tok = strtok(NULL, delim);
		if (!tok) {
			printf("Call [%s] has no port\n", call);
			continue;
		}
		if (strlen(tok) > 5) {
			printf("call %s has invalid port [%s]\n", call, tok);
			continue;
		}
		strcpy(port, tok);

		/* at this point, we have: call host port */
		/* copy the payload(host port) */
		sprintf(payload, "%s %s", host, port);

		auto gwy_pos = gwy_list.find(call);
		if (gwy_pos != gwy_list.end())
			printf("%s %s has been redefined!\n", call, payload);
		gwy_list[call] = payload;
	}
	fclose(fp);
	// DPlus Authenticate
	if (dplus_authorize && dplus_priority) {
		CDPlusAuthenticator auth(login_call, std::string("auth.dstargateway.org"));
		if (auth.Process(gwy_list, dplus_reflectors, dplus_repeaters))
			fprintf(stdout, "DPlus Authorization complete.\n");
		else
			fprintf(stderr, "DPlus Authorization failed!\n");
	}

	for (auto it=gwy_list.begin(); it!=gwy_list.end(); it++)
		printf("%s %s\n", it->first.c_str(), it->second.c_str());
	printf("Added %d gateways\n", (int)gwy_list.size());
	return true;
}

/* compute checksum */
void CQnetLink::calcPFCS(unsigned char *packet, int len)
{
	unsigned short crc_tabccitt[256] = {
		0x0000,0x1189,0x2312,0x329b,0x4624,0x57ad,0x6536,0x74bf,0x8c48,0x9dc1,0xaf5a,0xbed3,0xca6c,0xdbe5,0xe97e,0xf8f7,
		0x1081,0x0108,0x3393,0x221a,0x56a5,0x472c,0x75b7,0x643e,0x9cc9,0x8d40,0xbfdb,0xae52,0xdaed,0xcb64,0xf9ff,0xe876,
		0x2102,0x308b,0x0210,0x1399,0x6726,0x76af,0x4434,0x55bd,0xad4a,0xbcc3,0x8e58,0x9fd1,0xeb6e,0xfae7,0xc87c,0xd9f5,
		0x3183,0x200a,0x1291,0x0318,0x77a7,0x662e,0x54b5,0x453c,0xbdcb,0xac42,0x9ed9,0x8f50,0xfbef,0xea66,0xd8fd,0xc974,
		0x4204,0x538d,0x6116,0x709f,0x0420,0x15a9,0x2732,0x36bb,0xce4c,0xdfc5,0xed5e,0xfcd7,0x8868,0x99e1,0xab7a,0xbaf3,
		0x5285,0x430c,0x7197,0x601e,0x14a1,0x0528,0x37b3,0x263a,0xdecd,0xcf44,0xfddf,0xec56,0x98e9,0x8960,0xbbfb,0xaa72,
		0x6306,0x728f,0x4014,0x519d,0x2522,0x34ab,0x0630,0x17b9,0xef4e,0xfec7,0xcc5c,0xddd5,0xa96a,0xb8e3,0x8a78,0x9bf1,
		0x7387,0x620e,0x5095,0x411c,0x35a3,0x242a,0x16b1,0x0738,0xffcf,0xee46,0xdcdd,0xcd54,0xb9eb,0xa862,0x9af9,0x8b70,
		0x8408,0x9581,0xa71a,0xb693,0xc22c,0xd3a5,0xe13e,0xf0b7,0x0840,0x19c9,0x2b52,0x3adb,0x4e64,0x5fed,0x6d76,0x7cff,
		0x9489,0x8500,0xb79b,0xa612,0xd2ad,0xc324,0xf1bf,0xe036,0x18c1,0x0948,0x3bd3,0x2a5a,0x5ee5,0x4f6c,0x7df7,0x6c7e,
		0xa50a,0xb483,0x8618,0x9791,0xe32e,0xf2a7,0xc03c,0xd1b5,0x2942,0x38cb,0x0a50,0x1bd9,0x6f66,0x7eef,0x4c74,0x5dfd,
		0xb58b,0xa402,0x9699,0x8710,0xf3af,0xe226,0xd0bd,0xc134,0x39c3,0x284a,0x1ad1,0x0b58,0x7fe7,0x6e6e,0x5cf5,0x4d7c,
		0xc60c,0xd785,0xe51e,0xf497,0x8028,0x91a1,0xa33a,0xb2b3,0x4a44,0x5bcd,0x6956,0x78df,0x0c60,0x1de9,0x2f72,0x3efb,
		0xd68d,0xc704,0xf59f,0xe416,0x90a9,0x8120,0xb3bb,0xa232,0x5ac5,0x4b4c,0x79d7,0x685e,0x1ce1,0x0d68,0x3ff3,0x2e7a,
		0xe70e,0xf687,0xc41c,0xd595,0xa12a,0xb0a3,0x8238,0x93b1,0x6b46,0x7acf,0x4854,0x59dd,0x2d62,0x3ceb,0x0e70,0x1ff9,
		0xf78f,0xe606,0xd49d,0xc514,0xb1ab,0xa022,0x92b9,0x8330,0x7bc7,0x6a4e,0x58d5,0x495c,0x3de3,0x2c6a,0x1ef1,0x0f78
	};

	unsigned short crc_dstar_ffff = 0xffff;
	unsigned short tmp;
	short int low, high;

	if (len == 56) {
		low = 15;
		high = 54;
	} else if (len == 58) {
		low = 17;
		high = 56;
	} else
		return;

	for (short int i=low; i<high ; i++) {
		unsigned short short_c = 0x00ff & (unsigned short)packet[i];
		tmp = (crc_dstar_ffff & 0x00ff) ^ short_c;
		crc_dstar_ffff = (crc_dstar_ffff >> 8) ^ crc_tabccitt[tmp];
	}
	crc_dstar_ffff =  ~crc_dstar_ffff;
	tmp = crc_dstar_ffff;

	if (len == 56) {
		packet[54] = (unsigned char)(crc_dstar_ffff & 0xff);
		packet[55] = (unsigned char)((tmp >> 8) & 0xff);
	} else {
		packet[56] = (unsigned char)(crc_dstar_ffff & 0xff);
		packet[57] = (unsigned char)((tmp >> 8) & 0xff);
	}
	return;
}

void CQnetLink::ToUpper(std::string &s)
{
	for (auto it=s.begin(); it!=s.end(); it++)
		if (islower(*it))
			*it = toupper(*it);
}

void CQnetLink::UnpackCallsigns(const std::string &str, std::set<std::string> &set, const std::string &delimiters)
{
	std::string::size_type lastPos = str.find_first_not_of(delimiters, 0);	// Skip delimiters at beginning.
	std::string::size_type pos = str.find_first_of(delimiters, lastPos);	// Find first non-delimiter.

	while (std::string::npos != pos || std::string::npos != lastPos) {
		std::string element = str.substr(lastPos, pos-lastPos);
		if (element.length()>=3 && element.length()<=6) {
			ToUpper(element);
			element.resize(CALL_SIZE, ' ');
			set.insert(element);	// Found a token, add it to the list.
		} else
			fprintf(stderr, "found bad callsign in list: %s\n", str.c_str());
		lastPos = str.find_first_not_of(delimiters, pos);	// Skip delimiters.
		pos = str.find_first_of(delimiters, lastPos);	// Find next non-delimiter.
	}
}

void CQnetLink::PrintCallsigns(const std::string &key, const std::set<std::string> &set)
{
	printf("%s = [ ", key.c_str());
	for (auto it=set.begin(); it!=set.end(); it++) {
		if (it != set.begin())
			printf(", ");
		printf("%s", (*it).c_str());
	}
	printf(" ]");
}

/* process configuration file */
bool CQnetLink::read_config(const char *cfgFile)
{
	CQnetConfigure cfg;
	const std::string estr;	// an empty string

	printf("Reading file %s\n", cfgFile);
	if (cfg.Initialize(cfgFile))
		return true;

	std::string key("ircddb_login");
	if (cfg.GetValue(key, estr, owner, 3, 6))
		return true;
	ToUpper(owner);
	owner.resize(CALL_SIZE, ' ');

	int modules = 0;
	for (int i=0; i<3; i++) {
		key.assign("module_");
		key.append(1, 'a'+i);
		if (cfg.KeyExists(key)) {
			std::string modem_type;
			cfg.GetValue(key, estr, modem_type, 1, 16);
			modules++;
			cfg.GetValue(key+"_inactivity", modem_type, rf_inactivity_timer[i], 0, 300);
			rf_inactivity_timer[i] *= 60;
			cfg.GetValue(key+"_link_at_start", modem_type, link_at_startup[i], 8, 8);
		}
	}
	if (0 == modules) {
		fprintf(stderr, "no rf modules defined!\n");
		return true;
	}

	std::string csv;
	key.assign("link_admin");
	if (cfg.KeyExists(key)) {
		cfg.GetValue(key, estr, csv, 0, 10240);
		UnpackCallsigns(csv, admin);
		PrintCallsigns(key, admin);
	}

	csv.clear();
	key.assign("link_no_link_unlink");
	if (cfg.KeyExists(key)) {
		cfg.GetValue(key, estr, csv, 0, 10240);
		UnpackCallsigns(csv, link_blacklist);
		PrintCallsigns(key, link_blacklist);
	} else {
		csv.clear();
		key.assign("link_link_unlink");
		if (cfg.KeyExists(key)) {
			cfg.GetValue(key, estr, csv, 0, 10240);
			UnpackCallsigns(csv, link_unlink_user);
			PrintCallsigns(key, link_unlink_user);
		}
	}

	key.assign("link_");
	cfg.GetValue(key+"incoming_ip", estr, my_g2_link_ip, 7, IP_SIZE);
	cfg.GetValue(key+"ref_port", estr, rmt_ref_port, 10000, 65535);
	cfg.GetValue(key+"xrf_port", estr, rmt_xrf_port, 10000, 65535);
	cfg.GetValue(key+"dcs_port", estr, rmt_dcs_port, 10000, 65535);
	cfg.GetValue(key+"acknowledge", estr, bool_rptr_ack);
	cfg.GetValue(key+"announce", estr, announce);
	int maxdongle;
	cfg.GetValue(key+"max_dongles", estr, maxdongle, 0, 10);
	saved_max_dongles = max_dongles = (unsigned int)maxdongle;

	key.assign("gateway_");
	cfg.GetValue(key+"gate2link", estr, gate2link, 1, FILENAME_MAX);
	cfg.GetValue(key+"link2gate", estr, link2gate, 1, FILENAME_MAX);

	cfg.GetValue("log_qso", estr, qso_details);

	key.assign("file_");
	cfg.GetValue(key+"gwys", estr, gwys, 2, FILENAME_MAX);
	cfg.GetValue(key+"status", estr, status_file, 2, FILENAME_MAX);
	cfg.GetValue(key+"qnvoice_file", estr, qnvoice_file, 2, FILENAME_MAX);
	cfg.GetValue(key+"announce_dir", estr, announce_dir, 2, FILENAME_MAX);

	key.assign("timing_play_");
	cfg.GetValue(key+"wait", estr, delay_before, 1, 10);
	cfg.GetValue(key+"delay", estr, delay_between, 9, 25);

	key.assign("dplus_");
	cfg.GetValue(key+"authorize", estr, dplus_authorize);
	cfg.GetValue(key+"use_reflectors", estr, dplus_reflectors);
	cfg.GetValue(key+"use_repeaters", estr, dplus_repeaters);
	cfg.GetValue(key+"ref_login", estr, login_call, 0, 6);
	if (login_call.length() < 4) {
		login_call.assign(owner);
	} else {
		ToUpper(login_call);
		login_call.resize(CALL_SIZE, ' ');
	}
	cfg.GetValue(key+"priority", estr, dplus_priority);

	return false;
}

/* create our server */
bool CQnetLink::srv_open()
{
	struct sockaddr_in sin;
	short i;

	/* create our XRF gateway socket */
	xrf_g2_sock = socket(PF_INET,SOCK_DGRAM,0);
	if (xrf_g2_sock == -1) {
		printf("Failed to create gateway socket for XRF,errno=%d\n",errno);
		return false;
	}
	fcntl(xrf_g2_sock,F_SETFL,O_NONBLOCK);

	memset(&sin,0,sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(my_g2_link_ip.c_str());
	sin.sin_port = htons(rmt_xrf_port);
	if (bind(xrf_g2_sock,(struct sockaddr *)&sin,sizeof(struct sockaddr_in)) != 0) {
		printf("Failed to bind gateway socket on port %d for XRF, errno=%d\n", rmt_xrf_port ,errno);
		close(xrf_g2_sock);
		xrf_g2_sock = -1;
		return false;
	}

	/* create the dcs socket */
	dcs_g2_sock = socket(PF_INET,SOCK_DGRAM,0);
	if (dcs_g2_sock == -1) {
		printf("Failed to create gateway socket for DCS,errno=%d\n",errno);
		close(xrf_g2_sock);
		xrf_g2_sock = -1;
		return false;
	}
	fcntl(dcs_g2_sock,F_SETFL,O_NONBLOCK);

	/* socket for REF */
	ref_g2_sock = socket(PF_INET,SOCK_DGRAM,0);
	if (ref_g2_sock == -1) {
		printf("Failed to create gateway socket for REF, errno=%d\n",errno);
		close(dcs_g2_sock);
		dcs_g2_sock = -1;
		close(xrf_g2_sock);
		xrf_g2_sock = -1;
		return false;
	}
	fcntl(ref_g2_sock,F_SETFL,O_NONBLOCK);

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(my_g2_link_ip.c_str());
	sin.sin_port = htons(rmt_ref_port);
	if (bind(ref_g2_sock,(struct sockaddr *)&sin,sizeof(struct sockaddr_in)) != 0) {
		printf("Failed to bind gateway socket on port %d for REF, errno=%d\n",
		        rmt_ref_port ,errno);
		close(dcs_g2_sock);
		dcs_g2_sock = -1;
		close(xrf_g2_sock);
		xrf_g2_sock = -1;
		close(ref_g2_sock);
		ref_g2_sock = -1;
		return false;
	}

	/* create our gateway unix sockets */
	Link2Gate.SetUp(link2gate.c_str());
	if (Gate2Link.Open(gate2link.c_str())) {
		close(dcs_g2_sock);
		dcs_g2_sock = -1;
		close(xrf_g2_sock);
		xrf_g2_sock = -1;
		close(ref_g2_sock);
		ref_g2_sock = -1;
		Gate2Link.Close();
		return false;
	}

	/* initialize all remote links */
	for (i = 0; i < 3; i++) {
		to_remote_g2[i].to_call[0] = '\0';
		memset(&(to_remote_g2[i].toDst4),0,sizeof(struct sockaddr_in));
		to_remote_g2[i].from_mod = ' ';
		to_remote_g2[i].to_mod = ' ';
		to_remote_g2[i].countdown = 0;
		to_remote_g2[i].is_connected = false;
		to_remote_g2[i].in_streamid = 0x0;
		to_remote_g2[i].out_streamid = 0x0;
	}
	return true;
}

/* destroy our server */
void CQnetLink::srv_close()
{
	if (xrf_g2_sock != -1) {
		close(xrf_g2_sock);
		printf("Closed rmt_xrf_port\n");
	}

	if (dcs_g2_sock != -1) {
		close(dcs_g2_sock);
		printf("Closed rmt_dcs_port\n");
	}

	Gate2Link.Close();

	if (ref_g2_sock != -1) {
		close(ref_g2_sock);
		printf("Closed rmt_ref_port\n");
	}

	return;
}

/* find the repeater IP by callsign and link to it */
void CQnetLink::g2link(const char from_mod, const char *call, const char to_mod)
{
	short i,j, counter;

	char linked_remote_system[CALL_SIZE + 1];
	char *space_p = 0;

	char host[MAXHOSTNAMELEN + 1];
	char port_s[5 + 1];
	int port_i;

	/* host + space + port + NULL */
	char payload[MAXHOSTNAMELEN + 1 + 5 + 1];
	char *p = NULL;

	char link_request[519];

	bool ok = false;

	memset(link_request, 0, sizeof(link_request));

	host[0] = '\0';
	port_s[0] = '\0';
	payload[0] = '\0';

	if (from_mod == 'A')
		i = 0;
	else if (from_mod == 'B')
		i = 1;
	else if (from_mod == 'C')
		i = 2;
	else {
		printf("from_mod %c invalid\n", from_mod);
		return;
	}

	memset(&to_remote_g2[i], 0, sizeof(to_remote_g2[i]));

	strcpy(to_remote_g2[i].to_call, call);
	to_remote_g2[i].to_mod = to_mod;

	if ((memcmp(call, "REF", 3) == 0) || (memcmp(call, "DCS", 3) == 0)) {
		for (counter = 0; counter < 3; counter++) {
			if (counter != i) {
				if ('\0'!=to_remote_g2[counter].to_call[0] && !strcmp(to_remote_g2[counter].to_call,to_remote_g2[i].to_call) && to_remote_g2[counter].to_mod==to_remote_g2[i].to_mod)
					break;
			}
		}
		to_remote_g2[i].to_call[0] = '\0';
		to_remote_g2[i].to_mod = ' ';

		if (counter < 3) {
			printf("Another mod(%c) is already linked to %s %c\n", to_remote_g2[counter].from_mod, to_remote_g2[counter].to_call, to_remote_g2[counter].to_mod);
			return;
		}
	}

	auto gwy_pos = gwy_list.find(call);
	if (gwy_pos == gwy_list.end()) {
		sprintf(notify_msg[i], "%c_gatewaynotfound.dat_GATEWAY_NOT_FOUND", from_mod);
		printf("%s not found in gwy list\n", call);
		return;
	}

	strcpy(payload, gwy_pos->second.c_str());

	/* extract host and port */
	p = strchr(payload, ' ');
	if (!p) {
		printf("Invalid payload [%s] for call [%s]\n", payload, call);
		return;
	}
	*p = '\0';

	strcpy(host, payload);
	strcpy(port_s, p + 1);
	port_i = atoi(port_s);

	if (host[0] != '\0') {
		ok = resolve_rmt(host, SOCK_DGRAM, &(to_remote_g2[i].toDst4));
		if (!ok) {
			printf("Call %s is host %s but could not resolve to IP\n", call, host);
			memset(&to_remote_g2[i], 0, sizeof(to_remote_g2[i]));
			return;
		}

		strcpy(to_remote_g2[i].to_call, call);
		to_remote_g2[i].toDst4.sin_family = AF_INET;
		to_remote_g2[i].toDst4.sin_port = htons(port_i);
		to_remote_g2[i].from_mod = from_mod;
		to_remote_g2[i].to_mod = to_mod;
		to_remote_g2[i].countdown = TIMEOUT;
		to_remote_g2[i].is_connected = false;
		to_remote_g2[i].in_streamid= 0x0;

		/* is it XRF? */
		if (port_i == rmt_xrf_port) {
			strcpy(link_request, owner.c_str());
			link_request[8] = from_mod;
			link_request[9] = to_mod;
			link_request[10] = '\0';

			printf("sending link request from mod %c to link with: [%s] mod %c [%s]\n", to_remote_g2[i].from_mod, to_remote_g2[i].to_call, to_remote_g2[i].to_mod, payload);

			for (j=0; j<5; j++)
				sendto(xrf_g2_sock, link_request, CALL_SIZE + 3, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));
		} else if (port_i == rmt_dcs_port) {
			strcpy(link_request, owner.c_str());
			link_request[8] = from_mod;
			link_request[9] = to_mod;
			link_request[10] = '\0';
			memcpy(link_request + 11, to_remote_g2[i].to_call, 8);
			strcpy(link_request + 19, "<table border=\"0\" width=\"95%\"><tr><td width=\"4%\"><img border=\"0\" src=g2ircddb.jpg></td><td width=\"96%\"><font size=\"2\"><b>REPEATER</b> QnetGateway v1.0+</font></td></tr></table>");

			printf("sending link request from mod %c to link with: [%s] mod %c [%s]\n", to_remote_g2[i].from_mod, to_remote_g2[i].to_call, to_remote_g2[i].to_mod, payload);
			sendto(dcs_g2_sock, link_request, 519, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));
		} else if (port_i == rmt_ref_port) {
			for (counter = 0; counter < 3; counter++) {
				if (counter != i) {
					if ( (to_remote_g2[counter].to_call[0] != '\0') &&
					        (strcmp(to_remote_g2[counter].to_call,to_remote_g2[i].to_call) == 0) )
						break;
				}
			}
			if (counter > 2) {
				printf("sending link command from mod %c to: [%s] mod %c [%s]\n", to_remote_g2[i].from_mod, to_remote_g2[i].to_call, to_remote_g2[i].to_mod, payload);

				queryCommand[0] = 5;
				queryCommand[1] = 0;
				queryCommand[2] = 24;
				queryCommand[3] = 0;
				queryCommand[4] = 1;

				sendto(ref_g2_sock, queryCommand, 5, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));
			} else {
				if (to_remote_g2[counter].is_connected) {
					to_remote_g2[i].is_connected = true;
					printf("Local module %c is also connected to %s %c\n", from_mod, call, to_mod);

					print_status_file();
					tracing[i].last_time = time(NULL);

					// announce it here
					strcpy(linked_remote_system, to_remote_g2[i].to_call);
					space_p = strchr(linked_remote_system, ' ');
					if (space_p)
						*space_p = '\0';
					sprintf(notify_msg[i], "%c_linked.dat_LINKED_%s_%c", to_remote_g2[i].from_mod, linked_remote_system, to_remote_g2[i].to_mod);
				} else
					printf("status from %s %c pending\n", to_remote_g2[i].to_call, to_remote_g2[i].to_mod);
			}
		}
	}
	return;
}

/* signal catching function */
void CQnetLink::sigCatch(int signum)
{
	/* do NOT do any serious work here */
	if ((signum == SIGTERM) || (signum == SIGINT))
		keep_running = false;
	return;
}

void CQnetLink::Process()
{
	time_t tnow = 0, hb = 0;

	char *p = NULL;

	char *space_p = 0;
	char linked_remote_system[CALL_SIZE + 1];
	char unlink_request[CALL_SIZE + 3];

	char system_cmd[FILENAME_MAX + 1];
	int max_nfds = 0;

	char tmp1[CALL_SIZE + 1];
	char tmp2[36]; // 8 for rpt1 + 24 for time_t in std::string format
	unsigned char dcs_buf[1000];;

	char call[CALL_SIZE + 1];
	char ip[IP_SIZE + 1];
	bool found = false;

	char cmd_2_dcs[23];
	unsigned char dcs_seq[3] = { 0x00, 0x00, 0x00 };
	struct {
		char mycall[9];
		char sfx[5];
		unsigned int dcs_rptr_seq;
	} rptr_2_dcs[3] = {
		{"        ", "    ", 0},
		{"        ", "    ", 0},
		{"        ", "    ", 0}
	};
	struct {
		char mycall[9];
		char sfx[5];
		unsigned int dcs_rptr_seq;
	} ref_2_dcs[3] = {
		{"        ", "    ", 0},
		{"        ", "    ", 0},
		{"        ", "    ", 0}
	};
	struct {
		char mycall[9];
		char sfx[5];
		unsigned int dcs_rptr_seq;
	} xrf_2_dcs[3] = {
		{"        ", "    ", 0},
		{"        ", "    ", 0},
		{"        ", "    ", 0}
	};

	u_int16_t streamid_raw;

	char source_stn[9];

	time(&hb);

	if (xrf_g2_sock > max_nfds)
		max_nfds = xrf_g2_sock;
	if (ref_g2_sock > max_nfds)
		max_nfds = ref_g2_sock;
	if (dcs_g2_sock > max_nfds)
		max_nfds = dcs_g2_sock;
	if (Gate2Link.GetFD() > max_nfds)
		max_nfds = Gate2Link.GetFD();

	printf("xrf=%d, dcs=%d, ref=%d, gateway=%d, MAX+1=%d\n", xrf_g2_sock, dcs_g2_sock, ref_g2_sock, Gate2Link.GetFD(), max_nfds + 1);

	// initialize all request links
	bool first = true;
	for (int i=0; i<3; i++) {
		if (8 == link_at_startup[i].length()) {
			if (first) {
				printf("sleep for 15 sec before link at startup\n");
				sleep(15);
				first = false;
			}
			std::string node(link_at_startup[i].substr(0, 6));
			node.resize(CALL_SIZE, ' ');
			g2link('A'+i, node.c_str(), link_at_startup[i].at(7));
		}
	}

	while (keep_running) {
		time(&tnow);
		if (keep_running && (tnow - hb) > 0) {
			/* send heartbeat to connected donglers */
			send_heartbeat();

			/* send heartbeat to linked XRF repeaters/reflectors */
			if (to_remote_g2[0].toDst4.sin_port == htons(rmt_xrf_port))
				sendto(xrf_g2_sock, owner.c_str(), CALL_SIZE+1, 0, (struct sockaddr *)&(to_remote_g2[0].toDst4), sizeof(to_remote_g2[0].toDst4));

			if ((to_remote_g2[1].toDst4.sin_port == htons(rmt_xrf_port)) && (strcmp(to_remote_g2[1].to_call, to_remote_g2[0].to_call) != 0))
				sendto(xrf_g2_sock, owner.c_str(), CALL_SIZE+1, 0, (struct sockaddr *)&(to_remote_g2[1].toDst4), sizeof(to_remote_g2[1].toDst4));

			if ((to_remote_g2[2].toDst4.sin_port == htons(rmt_xrf_port)) && (strcmp(to_remote_g2[2].to_call, to_remote_g2[0].to_call) != 0) && (strcmp(to_remote_g2[2].to_call, to_remote_g2[1].to_call) != 0))
				sendto(xrf_g2_sock, owner.c_str(), CALL_SIZE+1, 0, (struct sockaddr *)&(to_remote_g2[2].toDst4), sizeof(to_remote_g2[2].toDst4));

			/* send heartbeat to linked DCS reflectors */
			if (to_remote_g2[0].toDst4.sin_port == htons(rmt_dcs_port)) {
				strcpy(cmd_2_dcs, owner.c_str());
				cmd_2_dcs[7] = to_remote_g2[0].from_mod;
				memcpy(cmd_2_dcs + 9, to_remote_g2[0].to_call, 8);
				cmd_2_dcs[16] = to_remote_g2[0].to_mod;
				sendto(dcs_g2_sock, cmd_2_dcs, 17, 0, (struct sockaddr *)&(to_remote_g2[0].toDst4), sizeof(to_remote_g2[0].toDst4));
			}
			if (to_remote_g2[1].toDst4.sin_port == htons(rmt_dcs_port)) {
				strcpy(cmd_2_dcs, owner.c_str());
				cmd_2_dcs[7] = to_remote_g2[1].from_mod;
				memcpy(cmd_2_dcs + 9, to_remote_g2[1].to_call, 8);
				cmd_2_dcs[16] = to_remote_g2[1].to_mod;
				sendto(dcs_g2_sock, cmd_2_dcs, 17, 0, (struct sockaddr *)&(to_remote_g2[1].toDst4), sizeof(to_remote_g2[1].toDst4));
			}
			if (to_remote_g2[2].toDst4.sin_port == htons(rmt_dcs_port)) {
				strcpy(cmd_2_dcs, owner.c_str());
				cmd_2_dcs[7] = to_remote_g2[2].from_mod;
				memcpy(cmd_2_dcs + 9, to_remote_g2[2].to_call, 8);
				cmd_2_dcs[16] = to_remote_g2[2].to_mod;
				sendto(dcs_g2_sock, cmd_2_dcs, 17, 0, (struct sockaddr *)&(to_remote_g2[2].toDst4), sizeof(to_remote_g2[2].toDst4));
			}

			/* send heartbeat to linked REF reflectors */
			if (to_remote_g2[0].is_connected && (to_remote_g2[0].toDst4.sin_port == htons(rmt_ref_port)))
				sendto(ref_g2_sock, REF_ACK, 3, 0, (struct sockaddr *)&(to_remote_g2[0].toDst4), sizeof(to_remote_g2[0].toDst4));

			if (to_remote_g2[1].is_connected && (to_remote_g2[1].toDst4.sin_port == htons(rmt_ref_port)) && (strcmp(to_remote_g2[1].to_call, to_remote_g2[0].to_call) != 0))
				sendto(ref_g2_sock, REF_ACK, 3, 0, (struct sockaddr *)&(to_remote_g2[1].toDst4), sizeof(to_remote_g2[1].toDst4));

			if (to_remote_g2[2].is_connected && (to_remote_g2[2].toDst4.sin_port == htons(rmt_ref_port)) && (strcmp(to_remote_g2[2].to_call, to_remote_g2[0].to_call) != 0) && (strcmp(to_remote_g2[2].to_call, to_remote_g2[1].to_call) != 0))
				sendto(ref_g2_sock, REF_ACK, 3, 0, (struct sockaddr *)&(to_remote_g2[2].toDst4), sizeof(to_remote_g2[2].toDst4));

			for (int i=0; i<3; i++) {
				/* check for timeouts from remote */
				if (to_remote_g2[i].to_call[0] != '\0') {
					if (to_remote_g2[i].countdown >= 0)
						to_remote_g2[i].countdown--;

					if (to_remote_g2[i].countdown < 0) {
						/* maybe remote system has changed IP */
						printf("Unlinked from [%s] mod %c, TIMEOUT...\n", to_remote_g2[i].to_call, to_remote_g2[i].to_mod);

						sprintf(notify_msg[i], "%c_unlinked.dat_UNLINKED_TIMEOUT", to_remote_g2[i].from_mod);

						to_remote_g2[i].to_call[0] = '\0';
						memset(&(to_remote_g2[i].toDst4),0,sizeof(struct sockaddr_in));
						to_remote_g2[i].from_mod = to_remote_g2[i].to_mod = ' ';
						to_remote_g2[i].countdown = 0;
						to_remote_g2[i].is_connected = false;
						to_remote_g2[i].in_streamid = 0x0;

						print_status_file();

					}
				}

				/*** check for RF inactivity ***/
				if (to_remote_g2[i].is_connected) {
					if (((tnow - tracing[i].last_time) > rf_inactivity_timer[i]) && (rf_inactivity_timer[i] > 0)) {
						tracing[i].last_time = 0;

						printf("Unlinked from [%s] mod %c, local RF inactivity...\n", to_remote_g2[i].to_call, to_remote_g2[i].to_mod);

						if (to_remote_g2[i].toDst4.sin_port == htons(rmt_ref_port)) {
							queryCommand[0] = 5;
							queryCommand[1] = 0;
							queryCommand[2] = 24;
							queryCommand[3] = 0;
							queryCommand[4] = 0;
							sendto(ref_g2_sock, queryCommand, 5, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));

							/* zero out any other entries here that match that system */
							for (int j=0; j<3; j++) {
								if (j != i) {
									if ((to_remote_g2[j].toDst4.sin_addr.s_addr == to_remote_g2[i].toDst4.sin_addr.s_addr) &&
									        (to_remote_g2[j].toDst4.sin_port == htons(rmt_ref_port))) {
										to_remote_g2[j].to_call[0] = '\0';
										memset(&(to_remote_g2[j].toDst4),0,sizeof(struct sockaddr_in));
										to_remote_g2[j].from_mod = ' ';
										to_remote_g2[j].to_mod = ' ';
										to_remote_g2[j].countdown = 0;
										to_remote_g2[j].is_connected = false;
										to_remote_g2[j].in_streamid = 0x0;
									}
								}
							}
						} else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port)) {
							strcpy(unlink_request, owner.c_str());
							unlink_request[8] = to_remote_g2[i].from_mod;
							unlink_request[9] = ' ';
							unlink_request[10] = '\0';

							for (int j=0; j<5; j++)
								sendto(xrf_g2_sock, unlink_request, CALL_SIZE+3, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));
						} else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_dcs_port)) {
							strcpy(cmd_2_dcs, owner.c_str());
							cmd_2_dcs[8] = to_remote_g2[i].from_mod;
							cmd_2_dcs[9] = ' ';
							cmd_2_dcs[10] = '\0';
							memcpy(cmd_2_dcs + 11, to_remote_g2[i].to_call, 8);

							for (int j=0; j<2; j++)
								sendto(dcs_g2_sock, cmd_2_dcs, 19 ,0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));
						}

						sprintf(notify_msg[i], "%c_unlinked.dat_UNLINKED_TIMEOUT", to_remote_g2[i].from_mod);

						to_remote_g2[i].to_call[0] = '\0';
						memset(&(to_remote_g2[i].toDst4),0,sizeof(struct sockaddr_in));
						to_remote_g2[i].from_mod = to_remote_g2[i].to_mod = ' ';
						to_remote_g2[i].countdown = 0;
						to_remote_g2[i].is_connected = false;
						to_remote_g2[i].in_streamid = 0x0;

						print_status_file();
					}
				}
			}
			time(&hb);
		}

		// play a qnvoice file if it is specified
		// this could be coming from qnvoice or qngateway (connected2network or notincache)
		std::ifstream voicefile(qnvoice_file.c_str(), std::ifstream::in);
		if (voicefile) {
			if (keep_running) {
				char line[FILENAME_MAX];
				voicefile.getline(line, FILENAME_MAX);
				// trim whitespace
				char *start = line;
				while (isspace(*start))
					start++;
				char *end = start + strlen(start) - 1;
				while (isspace(*end))
					*end-- = (char)0;
				// anthing reasonable left?
				if (strlen(start) > 2)
					PlayAudioNotifyThread(start);
			}
			//clean-up
			voicefile.close();
			remove(qnvoice_file.c_str());
		}

		FD_ZERO(&fdset);
		FD_SET(xrf_g2_sock, &fdset);
		FD_SET(dcs_g2_sock, &fdset);
		FD_SET(ref_g2_sock, &fdset);
		FD_SET(Gate2Link.GetFD(), &fdset);
		tv.tv_sec = 0;
		tv.tv_usec = 20000;
		(void)select(max_nfds + 1, &fdset, 0, 0, &tv);

		if (keep_running && FD_ISSET(xrf_g2_sock, &fdset)) {
			socklen_t fromlen = sizeof(struct sockaddr_in);
			unsigned char buf[100];
			int length = recvfrom(xrf_g2_sock, buf, 100, 0, (struct sockaddr *)&fromDst4, &fromlen);

			strncpy(ip, inet_ntoa(fromDst4.sin_addr), IP_SIZE);
			ip[IP_SIZE] = '\0';
			memcpy(call, buf, CALL_SIZE);
			call[CALL_SIZE] = '\0';

			/* A packet of length (CALL_SIZE + 1) is a keepalive from a repeater/reflector */
			/* If it is from a dongle, it is either a keepalive or a request to connect */

			if (length == (CALL_SIZE + 1)) {
				found = false;
				/* Find out if it is a keepalive from a repeater */
				for (int i=0; i<3; i++) {
					if (fromDst4.sin_addr.s_addr==to_remote_g2[i].toDst4.sin_addr.s_addr && to_remote_g2[i].toDst4.sin_port==htons(rmt_xrf_port)) {
						found = true;
						if (!to_remote_g2[i].is_connected) {
							tracing[i].last_time = time(NULL);

							to_remote_g2[i].is_connected = true;
							printf("Connected from: %.*s\n", length - 1, buf);
							print_status_file();

							strcpy(linked_remote_system, to_remote_g2[i].to_call);
							space_p = strchr(linked_remote_system, ' ');
							if (space_p)
								*space_p = '\0';
							sprintf(notify_msg[i], "%c_linked.dat_LINKED_%s_%c", to_remote_g2[i].from_mod, linked_remote_system, to_remote_g2[i].to_mod);

						}
						to_remote_g2[i].countdown = TIMEOUT;
					}
				}
			} else if (length == (CALL_SIZE + 6)) {
				/* A packet of length (CALL_SIZE + 6) is either an ACK or a NAK from repeater-reflector */
				/* Because we sent a request before asking to link */

				for (int i=0; i<3; i++) {
					if ((fromDst4.sin_addr.s_addr == to_remote_g2[i].toDst4.sin_addr.s_addr) && (to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port))) {
						if (0==memcmp(buf + 10, "ACK", 3) && to_remote_g2[i].from_mod==buf[8]) {
							if (!to_remote_g2[i].is_connected) {
								tracing[i].last_time = time(NULL);

								to_remote_g2[i].is_connected = true;
								printf("Connected from: [%s] %c\n", to_remote_g2[i].to_call, to_remote_g2[i].to_mod);
								print_status_file();

								strcpy(linked_remote_system, to_remote_g2[i].to_call);
								space_p = strchr(linked_remote_system, ' ');
								if (space_p)
									*space_p = '\0';
								sprintf(notify_msg[i], "%c_linked.dat_LINKED_%s_%c", to_remote_g2[i].from_mod, linked_remote_system, to_remote_g2[i].to_mod);
							}
						} else if (0==memcmp(buf + 10, "NAK", 3) && to_remote_g2[i].from_mod==buf[8]) {
							printf("Link module %c to [%s] %c is rejected\n", to_remote_g2[i].from_mod, to_remote_g2[i].to_call, to_remote_g2[i].to_mod);

							sprintf(notify_msg[i], "%c_failed_link.dat_FAILED_TO_LINK", to_remote_g2[i].from_mod);

							to_remote_g2[i].to_call[0] = '\0';
							memset(&(to_remote_g2[i].toDst4),0,sizeof(struct sockaddr_in));
							to_remote_g2[i].from_mod = to_remote_g2[i].to_mod = ' ';
							to_remote_g2[i].countdown = 0;
							to_remote_g2[i].is_connected = false;
							to_remote_g2[i].in_streamid = 0x0;

							print_status_file();
						}
					}
				}
			} else if (length == CALL_SIZE + 3) {
				// A packet of length (CALL_SIZE + 3) is a request
				// from a remote repeater to link-unlink with our repeater

				/* Check our linked repeaters/reflectors */
				for (int i=0; i<3; i++) {
					if (fromDst4.sin_addr.s_addr==to_remote_g2[i].toDst4.sin_addr.s_addr && to_remote_g2[i].toDst4.sin_port==htons(rmt_xrf_port)) {
						if (to_remote_g2[i].to_mod == buf[8]) {
							/* unlink request from remote repeater that we know */
							if (buf[9] == ' ') {
								printf("Received: %.*s\n", length - 1, buf);
								printf("Module %c to [%s] %c is unlinked\n", to_remote_g2[i].from_mod, to_remote_g2[i].to_call, to_remote_g2[i].to_mod);

								sprintf(notify_msg[i], "%c_unlinked.dat_UNLINKED", to_remote_g2[i].from_mod);

								to_remote_g2[i].to_call[0] = '\0';
								memset(&(to_remote_g2[i].toDst4),0,sizeof(struct sockaddr_in));
								to_remote_g2[i].from_mod = to_remote_g2[i].to_mod = ' ';
								to_remote_g2[i].countdown = 0;
								to_remote_g2[i].is_connected = false;
								to_remote_g2[i].in_streamid = 0x0;

								print_status_file();
							} else
								/* link request from a remote repeater that we know */
								if ((i==0 && buf[9]=='A') || (i==1 && buf[9]=='B') || (i==2 && buf[9]=='C')) {

									/*
									   I HAVE TO ADD CODE here to PREVENT the REMOTE NODE
									   from LINKING one of their remote modules to
									   more than one of our local modules
									*/

									printf("Received: %.*s\n", length - 1, buf);

									memcpy(to_remote_g2[i].to_call, buf, CALL_SIZE);
									to_remote_g2[i].to_call[CALL_SIZE] = '\0';
									memcpy(&(to_remote_g2[i].toDst4), &fromDst4, sizeof(struct sockaddr_in));
									to_remote_g2[i].toDst4.sin_port = htons(rmt_xrf_port);
									to_remote_g2[i].to_mod = buf[8];
									to_remote_g2[i].countdown = TIMEOUT;
									to_remote_g2[i].is_connected = true;
									to_remote_g2[i].in_streamid = 0x0;

									printf("Module %c to [%s] %c linked\n", buf[9], to_remote_g2[i].to_call, to_remote_g2[i].to_mod);

									tracing[i].last_time = time(NULL);

									print_status_file();

									/* send back an ACK */
									memcpy(buf + 10, "ACK", 4);
									sendto(xrf_g2_sock, buf, CALL_SIZE+6, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));

									if (to_remote_g2[i].from_mod != buf[9]) {
										to_remote_g2[i].from_mod = buf[9];

										strcpy(linked_remote_system, to_remote_g2[i].to_call);
										space_p = strchr(linked_remote_system, ' ');
										if (space_p)
											*space_p = '\0';
										sprintf(notify_msg[i], "%c_linked.dat_LINKED_%s_%c", to_remote_g2[i].from_mod, linked_remote_system, to_remote_g2[i].to_mod);
									}
								}
						}
					}
				}

				/* link request from remote repeater that is not yet linked to our system */
				/* find out which of our local modules the remote repeater is interested in */
				int i = -1;
				if (buf[9] == 'A')
					i = 0;
				else if (buf[9] == 'B')
					i = 1;
				else if (buf[9] == 'C')
					i = 2;

				/* Is this repeater listed in gwys.txt? */
				auto gwy_pos = gwy_list.find(call);
				if (gwy_pos == gwy_list.end()) {
					/* We did NOT find this repeater in gwys.txt, reject the incoming link request */
					printf("Incoming link from %s,%s but not found in gwys.txt\n", call, ip);
					i = -1;
				} else {
					int rc = regexec(&preg, call, 0, NULL, 0);
					if (rc != 0) {
						printf("Invalid repeater %s,%s requesting to link\n", call, ip);
						i = -1;
					}
				}

				if (i >= 0) {
					/* Is the local repeater module linked to anything ? */
					if (to_remote_g2[i].to_mod == ' ') {
						if (buf[8]>='A' && buf[8]<='E') {
							/*
							   I HAVE TO ADD CODE here to PREVENT the REMOTE NODE
							   from LINKING one of their remote modules to
							   more than one of our local modules
							*/

							/* now it can be added as a repeater */
							strcpy(to_remote_g2[i].to_call, call);
							to_remote_g2[i].to_call[CALL_SIZE] = '\0';
							memcpy(&(to_remote_g2[i].toDst4), &fromDst4, sizeof(struct sockaddr_in));
							to_remote_g2[i].toDst4.sin_port = htons(rmt_xrf_port);
							to_remote_g2[i].from_mod = buf[9];
							to_remote_g2[i].to_mod = buf[8];
							to_remote_g2[i].countdown = TIMEOUT;
							to_remote_g2[i].is_connected = true;
							to_remote_g2[i].in_streamid = 0x0;

							print_status_file();

							tracing[i].last_time = time(NULL);

							printf("Received: %.*s\n", length - 1, buf);
							printf("Module %c to [%s] %c linked\n", to_remote_g2[i].from_mod, to_remote_g2[i].to_call, to_remote_g2[i].to_mod);

							strcpy(linked_remote_system, to_remote_g2[i].to_call);
							space_p = strchr(linked_remote_system, ' ');
							if (space_p)
								*space_p = '\0';
							sprintf(notify_msg[i], "%c_linked.dat_LINKED_%s_%c", to_remote_g2[i].from_mod, linked_remote_system, to_remote_g2[i].to_mod);

							/* send back an ACK */
							memcpy(buf + 10, "ACK", 4);
							sendto(xrf_g2_sock, buf, CALL_SIZE+6, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));
						}
					} else {
						if (fromDst4.sin_addr.s_addr != to_remote_g2[i].toDst4.sin_addr.s_addr) {
							/* Our repeater module is linked to another repeater-reflector */
							memcpy(buf + 10, "NAK", 4);
							fromDst4.sin_port = htons(rmt_xrf_port);
							sendto(xrf_g2_sock, buf, CALL_SIZE+6, 0, (struct sockaddr *)&fromDst4, sizeof(struct sockaddr_in));
						}
					}
				}
			} else if ((length==56 || length==27) && 0==memcmp(buf, "DSVT", 4) && (buf[4]==0x10 || buf[4]==0x20) && buf[8]==0x20) {
				/* reset countdown and protect against hackers */

				found = false;
				for (int i=0; i<3; i++) {
					if ((fromDst4.sin_addr.s_addr == to_remote_g2[i].toDst4.sin_addr.s_addr) && (to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port))) {
						to_remote_g2[i].countdown = TIMEOUT;
						found = true;
					}
				}

				SDSVT dsvt; memcpy(dsvt.title, buf, length);	// copy to struct

				/* process header */
				if ((length == 56) && found) {
					memset(source_stn, ' ', 9);
					source_stn[8] = '\0';

					/* some bad hotspot programs out there using INCORRECT flag */
					if (dsvt.hdr.flag[0]==0x40U || dsvt.hdr.flag[0]==0x48U || dsvt.hdr.flag[0]==0x60U || dsvt.hdr.flag[0]==0x68U) dsvt.hdr.flag[0] -= 0x40;

					/* A reflector will send to us its own RPT1 */
					/* A repeater will send to us our RPT1 */

					for (int i=0; i<3; i++) {
						if (fromDst4.sin_addr.s_addr==to_remote_g2[i].toDst4.sin_addr.s_addr && to_remote_g2[i].toDst4.sin_port==htons(rmt_xrf_port)) {
							/* it is a reflector, reflector's rpt1 */
							if (0==memcmp(dsvt.hdr.rpt1, to_remote_g2[i].to_call, 7) && dsvt.hdr.rpt1[7]==to_remote_g2[i].to_mod) {
								memcpy(dsvt.hdr.rpt1, owner.c_str(), CALL_SIZE);
								dsvt.hdr.rpt1[7] = to_remote_g2[i].from_mod;
								memcpy(dsvt.hdr.urcall, "CQCQCQ  ", 8);

								memcpy(source_stn, to_remote_g2[i].to_call, 8);
								source_stn[7] = to_remote_g2[i].to_mod;
								break;
							} else
								/* it is a repeater, our rpt1 */
								if (memcmp(dsvt.hdr.rpt1, owner.c_str(), CALL_SIZE-1) && dsvt.hdr.rpt1[7]==to_remote_g2[i].from_mod) {
									memcpy(source_stn, to_remote_g2[i].to_call, 8);
									source_stn[7] = to_remote_g2[i].to_mod;
									break;
								}
						}
					}

					/* somebody's crazy idea of having a personal callsign in RPT2 */
					/* we must set it to our gateway callsign */
					memcpy(dsvt.hdr.rpt2, owner.c_str(), CALL_SIZE);
					dsvt.hdr.rpt2[7] = 'G';
					calcPFCS(dsvt.title, 56);

					/* At this point, all data have our RPT1 and RPT2 */

					/* send the data to the repeater/reflector that is linked to our RPT1 */
					int i = -1;
					if (dsvt.hdr.rpt1[7] == 'A')
						i = 0;
					else if (dsvt.hdr.rpt1[7] == 'B')
						i = 1;
					else if (dsvt.hdr.rpt1[7] == 'C')
						i = 2;

					/* are we sure that RPT1 is our system? */
					if (0==memcmp(dsvt.hdr.rpt1, owner.c_str(), CALL_SIZE-1) && i>=0) {
						/* Last Heard */
						if (old_sid[i].sid != dsvt.streamid) {
							if (qso_details)
								printf("START from remote g2: streamID=%04x, flags=%02x:%02x:%02x, my=%.8s, sfx=%.4s, ur=%.8s, rpt1=%.8s, rpt2=%.8s, %d bytes fromIP=%s, source=%.8s\n", ntohs(dsvt.streamid), dsvt.hdr.flag[0], dsvt.hdr.flag[1], dsvt.hdr.flag[2], dsvt.hdr.mycall, dsvt.hdr.sfx, dsvt.hdr.urcall, dsvt.hdr.rpt1, dsvt.hdr.rpt2, length, inet_ntoa(fromDst4.sin_addr), source_stn);

							// put user into tmp1
							memcpy(tmp1, dsvt.hdr.mycall, 8);
							tmp1[8] = '\0';

							// delete the user if exists
							for (auto dt_lh_pos = dt_lh_list.begin(); dt_lh_pos != dt_lh_list.end();  dt_lh_pos++) {
								if (0 == strcmp((char *)dt_lh_pos->second.c_str(), tmp1)) {
									dt_lh_list.erase(dt_lh_pos);
									break;
								}
							}
							/* Limit?, delete oldest user */
							if (dt_lh_list.size() == LH_MAX_SIZE) {
								auto dt_lh_pos = dt_lh_list.begin();
								dt_lh_list.erase(dt_lh_pos);
							}
							// add user
							time(&tnow);
							sprintf(tmp2, "%ld=r%.6s%c%c", tnow, source_stn, source_stn[7], dsvt.hdr.rpt1[7]);
							dt_lh_list[tmp2] = tmp1;

							old_sid[i].sid = dsvt.streamid;
						}

						/* relay data to our local G2 */
						Link2Gate.Write(dsvt.title, 56);

						/* send data to donglers */
						/* no changes here */
						for (auto pos = inbound_list.begin(); pos != inbound_list.end(); pos++) {
							SINBOUND *inbound = (SINBOUND *)pos->second;
							if (fromDst4.sin_addr.s_addr != inbound->sin.sin_addr.s_addr) {
								SREFDSVT rdsvt;
								rdsvt.head[0] = (unsigned char)(58 & 0xFF);
								rdsvt.head[1] = (unsigned char)(58 >> 8 & 0x1F);
								rdsvt.head[1] = (unsigned char)(rdsvt.head[1] | 0xFFFFFF80);
								memcpy(rdsvt.dsvt.title, dsvt.title, 56);

								sendto(ref_g2_sock, rdsvt.head, 58, 0, (struct sockaddr *)&(inbound->sin), sizeof(struct sockaddr_in));
							} else
								inbound->mod = dsvt.hdr.rpt1[7];
						}

						/* send the data to the repeater/reflector that is linked to our RPT1 */

						/* Is there another local module linked to the remote same xrf mod ? */
						/* If Yes, then broadcast */
						int k = i + 1;

						if (k < 3) {
							brd_from_xrf_idx = 0;
							streamid_raw = ntohs(dsvt.streamid);

							/* We can only enter this loop up to 2 times max */
							for (int j=k; j<3; j++) {
								/* it is a remote gateway, not a dongle user */
								if (fromDst4.sin_addr.s_addr==to_remote_g2[j].toDst4.sin_addr.s_addr &&
										/* it is xrf */
										to_remote_g2[j].toDst4.sin_port==htons(rmt_xrf_port) &&
										0==memcmp(to_remote_g2[j].to_call, "XRF", 3) &&
										/* it is the same xrf and xrf module */
										0==memcmp(to_remote_g2[j].to_call, to_remote_g2[i].to_call, 8) &&
										to_remote_g2[j].to_mod==to_remote_g2[i].to_mod) {
									/* send the packet to another module of our local repeater: this is multi-link */

									/* generate new packet */
									memcpy(from_xrf_torptr_brd.title, dsvt.title, 56);

									/* different repeater module */
									from_xrf_torptr_brd.hdr.rpt1[7] = to_remote_g2[j].from_mod;

									/* assign new streamid */
									streamid_raw++;
									if (streamid_raw == 0)
										streamid_raw++;
									from_xrf_torptr_brd.streamid = htons(streamid_raw);

									calcPFCS(from_xrf_torptr_brd.title, 56);

									/* send the data to the local gateway/repeater */
									Link2Gate.Write(from_xrf_torptr_brd.title, 56);

									/* save streamid for use with the audio packets that will arrive after this header */

									brd_from_xrf.xrf_streamid = dsvt.streamid;
									brd_from_xrf.rptr_streamid[brd_from_xrf_idx] = from_xrf_torptr_brd.streamid;
									brd_from_xrf_idx++;
								}
							}
						}

						if (to_remote_g2[i].toDst4.sin_addr.s_addr!=fromDst4.sin_addr.s_addr && to_remote_g2[i].is_connected) {
							if (to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port)) {
								if ( /*** (memcmp(readBuffer2 + 42, owner, 8) != 0) && ***/         /* block repeater announcements */
									(memcmp(dsvt.hdr.urcall, "CQCQCQ", 6) == 0) && /* CQ calls only */
									(dsvt.hdr.flag[0] == 0x00  ||                  /* normal */
									 dsvt.hdr.flag[0] == 0x08  ||                  /* EMR */
									 dsvt.hdr.flag[0] == 0x20  ||                  /* BK */
									 dsvt.hdr.flag[0] == 0x28) &&                  /* EMR + BK */
									0==memcmp(dsvt.hdr.rpt2, owner.c_str(), CALL_SIZE-1) &&         /* rpt2 must be us */
									dsvt.hdr.rpt2[7] == 'G') {
									to_remote_g2[i].in_streamid = dsvt.streamid;

									/* inform XRF about the source */
									dsvt.flagb[2] = to_remote_g2[i].from_mod;

									memcpy(dsvt.hdr.rpt1, to_remote_g2[i].to_call, CALL_SIZE);
									dsvt.hdr.rpt1[7] = to_remote_g2[i].to_mod;
									memcpy(dsvt.hdr.rpt2, to_remote_g2[i].to_call, CALL_SIZE);
									dsvt.hdr.rpt2[7] = 'G';
									calcPFCS(dsvt.title, 56);

									sendto(xrf_g2_sock, dsvt.title, 56, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));
								}
							} else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_ref_port)) {
								if ( /*** (memcmp(readBuffer2 + 42, owner, 8) != 0) && ***/         /* block repeater announcements */
											0==memcmp(dsvt.hdr.urcall, "CQCQCQ", 6) && /* CQ calls only */
											(dsvt.hdr.flag[0] == 0x00 ||               /* normal */
											 dsvt.hdr.flag[0] == 0x08 ||               /* EMR */
											 dsvt.hdr.flag[0] == 0x20 ||               /* BK */
											 dsvt.hdr.flag[0] == 0x28) &&              /* EMR + BK */
											0==memcmp(dsvt.hdr.rpt2, owner.c_str(), CALL_SIZE-1) &&         /* rpt2 must be us */
											dsvt.hdr.rpt2[7] == 'G') {
									to_remote_g2[i].in_streamid = dsvt.streamid;

									SREFDSVT rdsvt;
									rdsvt.head[0] = (unsigned char)(58 & 0xFF);
									rdsvt.head[1] = (unsigned char)(58 >> 8 & 0x1F);
									rdsvt.head[1] = (unsigned char)(rdsvt.head[1] | 0xFFFFFF80);

									memcpy(rdsvt.dsvt.title, dsvt.title, 56);

									memset(rdsvt.dsvt.hdr.rpt1, ' ', CALL_SIZE);
									memcpy(rdsvt.dsvt.hdr.rpt1, to_remote_g2[i].to_call, strlen(to_remote_g2[i].to_call));
									rdsvt.dsvt.hdr.rpt1[7] = to_remote_g2[i].to_mod;
									memset(rdsvt.dsvt.hdr.rpt2, ' ', CALL_SIZE);
									memcpy(rdsvt.dsvt.hdr.rpt2, to_remote_g2[i].to_call, strlen(to_remote_g2[i].to_call));
									rdsvt.dsvt.hdr.rpt2[7] = 'G';
									memcpy(rdsvt.dsvt.hdr.urcall, "CQCQCQ  ", CALL_SIZE);

									calcPFCS(rdsvt.dsvt.title, 56);

									sendto(ref_g2_sock, rdsvt.head, 58, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));
								}
							} else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_dcs_port)) {
								if ( /*** (memcmp(readBuffer2 + 42, owner, 8) != 0) && ***/         /* block repeater announcements */
										0==memcmp(dsvt.hdr.urcall, "CQCQCQ", 6) && /* CQ calls only */
										(dsvt.hdr.flag[0] == 0x00 ||               /* normal */
										 dsvt.hdr.flag[0] == 0x08 ||               /* EMR */
										 dsvt.hdr.flag[0] == 0x20 ||               /* BK */
										 dsvt.hdr.flag[0] == 0x28) &&              /* EMR + BK */
										0==memcmp(dsvt.hdr.rpt2, owner.c_str(), CALL_SIZE-1) &&         /* rpt2 must be us */
										dsvt.hdr.rpt2[7] == 'G') {
									to_remote_g2[i].in_streamid = dsvt.streamid;

									memcpy(xrf_2_dcs[i].mycall, dsvt.hdr.mycall, CALL_SIZE);
									memcpy(xrf_2_dcs[i].sfx, dsvt.hdr.sfx, 4);
									xrf_2_dcs[i].dcs_rptr_seq = 0;
								}
							}
						}
					}
				} else if (found) {	// length is 27
					if ((dsvt.ctrl & 0x40) != 0) {
						for (int i=0; i<3; i++) {
							if (old_sid[i].sid == dsvt.streamid) {
								if (qso_details)
									printf("END from remote g2: streamID=%04x, %d bytes from IP=%s\n", ntohs(dsvt.streamid), length, inet_ntoa(fromDst4.sin_addr));
								old_sid[i].sid = 0x0;

								break;
							}
						}
					}

					/* relay data to our local G2 */
					Link2Gate.Write(dsvt.title, 27);

					/* send data to donglers */
					/* no changes here */
					for (auto pos = inbound_list.begin(); pos != inbound_list.end(); pos++) {
						SINBOUND *inbound = (SINBOUND *)pos->second;
						if (fromDst4.sin_addr.s_addr != inbound->sin.sin_addr.s_addr) {
							SREFDSVT rdsvt;
							rdsvt.head[0] = (unsigned char)(29 & 0xFF);
							rdsvt.head[1] = (unsigned char)(29 >> 8 & 0x1F);
							rdsvt.head[1] = (unsigned char)(rdsvt.head[1] | 0xFFFFFF80);

							memcpy(rdsvt.dsvt.title, dsvt.title, 27);

							sendto(ref_g2_sock, rdsvt.head, 29, 0, (struct sockaddr *)&(inbound->sin), sizeof(struct sockaddr_in));
						}
					}

					/* do we have to broadcast ? */
					if (brd_from_xrf.xrf_streamid == dsvt.streamid) {
						memcpy(from_xrf_torptr_brd.title, dsvt.title, 27);

						if (brd_from_xrf.rptr_streamid[0] != 0x0) {
							from_xrf_torptr_brd.streamid = brd_from_xrf.rptr_streamid[0];
							Link2Gate.Write(from_xrf_torptr_brd.title, 27);
						}

						if (brd_from_xrf.rptr_streamid[1] != 0x0) {
							from_xrf_torptr_brd.streamid = brd_from_xrf.rptr_streamid[1];
							Link2Gate.Write(from_xrf_torptr_brd.title, 27);
						}

						if (dsvt.ctrl & 0x40) {
							brd_from_xrf.xrf_streamid = brd_from_xrf.rptr_streamid[0] = brd_from_xrf.rptr_streamid[1] = 0x0;
							brd_from_xrf_idx = 0;
						}
					}

					for (int i=0; i<3; i++) {
						if (to_remote_g2[i].is_connected && to_remote_g2[i].toDst4.sin_addr.s_addr!=fromDst4.sin_addr.s_addr && to_remote_g2[i].in_streamid==dsvt.streamid) {
							if (to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port)) {
								/* inform XRF about the source */
								dsvt.flagb[2] = to_remote_g2[i].from_mod;

								sendto(xrf_g2_sock, dsvt.title, 27, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));
							} else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_ref_port)) {
								SREFDSVT rdsvt;
								rdsvt.head[0] = (unsigned char)(29 & 0xFF);
								rdsvt.head[1] = (unsigned char)(29 >> 8 & 0x1F);
								rdsvt.head[1] = (unsigned char)(rdsvt.head[1] | 0xFFFFFF80);

								memcpy(rdsvt.dsvt.title, dsvt.title, 27);

								sendto(ref_g2_sock, rdsvt.head, 29, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));
							} else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_dcs_port)) {
								memset(dcs_buf, 0x00, 600);
								dcs_buf[0] = dcs_buf[1] = dcs_buf[2] = '0';
								dcs_buf[3] = '1';
								dcs_buf[4] = dcs_buf[5] = dcs_buf[6] = 0x0;
								memcpy(dcs_buf + 7, to_remote_g2[i].to_call, 8);
								dcs_buf[14] = to_remote_g2[i].to_mod;
								memcpy(dcs_buf + 15, owner.c_str(), CALL_SIZE);
								dcs_buf[22] =  to_remote_g2[i].from_mod;
								memcpy(dcs_buf + 23, "CQCQCQ  ", 8);
								memcpy(dcs_buf + 31, xrf_2_dcs[i].mycall, 8);
								memcpy(dcs_buf + 39, xrf_2_dcs[i].sfx, 4);
								memcpy(dcs_buf + 43, &dsvt.streamid, 2);
								dcs_buf[45] = dsvt.ctrl;  /* cycle sequence */
								memcpy(dcs_buf + 46, dsvt.vasd.voice, 12);

								dcs_buf[58] = (xrf_2_dcs[i].dcs_rptr_seq >> 0)  & 0xff;
								dcs_buf[59] = (xrf_2_dcs[i].dcs_rptr_seq >> 8)  & 0xff;
								dcs_buf[60] = (xrf_2_dcs[i].dcs_rptr_seq >> 16) & 0xff;

								xrf_2_dcs[i].dcs_rptr_seq++;

								dcs_buf[61] = 0x01;
								dcs_buf[62] = 0x00;

								sendto(dcs_g2_sock, dcs_buf, 100, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));
							}

							if (dsvt.ctrl & 0x40) {
								to_remote_g2[i].in_streamid = 0x0;
							}
							break;
						}
					}
				}
			}
			FD_CLR (xrf_g2_sock,&fdset);
		}

		if (keep_running && FD_ISSET(ref_g2_sock, &fdset)) {
			socklen_t fromlen = sizeof(struct sockaddr_in);
			unsigned char buf[100];
			int length = recvfrom(ref_g2_sock, buf, 100, 0, (struct sockaddr *)&fromDst4,&fromlen);

			strncpy(ip, inet_ntoa(fromDst4.sin_addr), IP_SIZE);
			ip[IP_SIZE] = '\0';

			found = false;

			/* LH */
			if (length==4 && buf[0]==4 && buf[1]==192 && buf[2]==7 && buf[3]==0) {
				unsigned short j_idx = 0;
				unsigned short k_idx = 0;
				unsigned char tmp[2];

				auto pos = inbound_list.find(ip);
				if (pos != inbound_list.end()) {
					//SINBOUND *inbound = (SINBOUND *)pos->second;
					// printf("Remote station %s %s requested LH list\n", inbound_ptr->call, ip);

					/* header is 10 bytes */

					/* reply type */
					buf[2] = 7;
					buf[3] = 0;

					/* it looks like time_t here */
					time(&tnow);
					memcpy(buf + 6, (char *)&tnow, sizeof(time_t));

					for (auto r_dt_lh_pos = dt_lh_list.rbegin(); r_dt_lh_pos != dt_lh_list.rend();  r_dt_lh_pos++) {
						/* each entry has 24 bytes */

						/* start at position 10 to bypass the header */
						strcpy((char *)buf + 10 + (24 * j_idx), r_dt_lh_pos->second.c_str());
						p = strchr((char *)r_dt_lh_pos->first.c_str(), '=');
						if (p) {
							memcpy((char *)buf + 18 + (24 * j_idx), p + 2, 8);

							/* if local or local w/gps */
							if (p[1]=='l' || p[1]=='g')
								buf[18 + (24 * j_idx) + 6] = *(p + 1);

							*p = '\0';
							tnow = atol(r_dt_lh_pos->first.c_str());
							*p = '=';
							memcpy(buf + 26 + (24 * j_idx), &tnow, sizeof(time_t));
						} else {
							memcpy(buf + 18 + (24 * j_idx), "ERROR   ", 8);
							time(&tnow);
							memcpy(buf + 26 + (24 * j_idx), &tnow, sizeof(time_t));
						}

						buf[30 + (24 * j_idx)] = 0;
						buf[31 + (24 * j_idx)] = 0;
						buf[32 + (24 * j_idx)] = 0;
						buf[33 + (24 * j_idx)] = 0;

						j_idx++;

						/* process 39 entries at a time */
						if (j_idx == 39) {
							/* 39 * 24 = 936 + 10 header = 946 */
							buf[0] = 0xb2;
							buf[1] = 0xc3;

							/* 39 entries */
							buf[4] = 0x27;
							buf[5] = 0x00;

							sendto(ref_g2_sock, buf, 946, 0, (struct sockaddr *)&fromDst4, sizeof(struct sockaddr_in));

							j_idx = 0;
						}
					}

					if (j_idx != 0) {
						k_idx = 10 + (j_idx * 24);
						memcpy(tmp, (char *)&k_idx, 2);
						buf[0] = tmp[0];
						buf[1] = tmp[1] | 0xc0;

						memcpy(tmp, (char *)&j_idx, 2);
						buf[4] = tmp[0];
						buf[5] = tmp[1];

						sendto(ref_g2_sock, buf, k_idx, 0, (struct sockaddr *)&fromDst4, sizeof(struct sockaddr_in));
					}
				}
			/* linked repeaters request */
			} else if (length==4 && buf[0]==4 && buf[1]==192 && buf[2]==5 && buf[3]==0) {
				unsigned short i_idx = 0;
				unsigned short j_idx = 0;
				unsigned short k_idx = 0;
				unsigned char tmp[2];
				unsigned short total = 0;

				auto pos = inbound_list.find(ip);
				if (pos != inbound_list.end()) {
					//SINBOUND *inbound = (SINBOUND *)pos->second;
					// printf("Remote station %s %s requested linked repeaters list\n", inbound_ptr->call, ip);

					/* header is 8 bytes */

					/* reply type */
					buf[2] = 5;
					buf[3] = 1;

					/* we can have up to 3 linked systems */
					total = 3;
					memcpy(tmp, (char *)&total, 2);
					buf[6] = tmp[0];
					buf[7] = tmp[1];

					for (int i=0, i_idx=0; i<3;  i++, i_idx++) {
						/* each entry has 20 bytes */
						if (to_remote_g2[i].to_mod != ' ') {
							if (i == 0)
								buf[8 + (20 * j_idx)] = 'A';
							else if (i == 1)
								buf[8 + (20 * j_idx)] = 'B';
							else if (i == 2)
								buf[8 + (20 * j_idx)] = 'C';

							strcpy((char *)buf + 9 + (20 * j_idx), to_remote_g2[i].to_call);
							buf[16 + (20 * j_idx)] = to_remote_g2[i].to_mod;

							buf[17 + (20 * j_idx)] = buf[18 + (20 * j_idx)] = buf[19 + (20 * j_idx)] = 0;
							buf[20 + (20 * j_idx)] = 0x50;
							buf[21 + (20 * j_idx)] = 0x04;
							buf[22 + (20 * j_idx)] = 0x32;
							buf[23 + (20 * j_idx)] = 0x4d;
							buf[24 + (20 * j_idx)] = 0x9f;
							buf[25 + (20 * j_idx)] = 0xdb;
							buf[26 + (20 * j_idx)] = 0x0e;
							buf[27 + (20 * j_idx)] = 0;

							j_idx++;

							if (j_idx == 39) {
								/* 20 bytes for each user, so 39 * 20 = 780 bytes + 8 bytes header = 788 */
								buf[0] = 0x14;
								buf[1] = 0xc3;

								k_idx = i_idx - 38;
								memcpy(tmp, (char *)&k_idx, 2);
								buf[4] = tmp[0];
								buf[5] = tmp[1];

								sendto(ref_g2_sock, buf, 788, 0, (struct sockaddr *)&fromDst4, sizeof(struct sockaddr_in));
								j_idx = 0;
							}
						}
					}

					if (j_idx != 0) {
						k_idx = 8 + (j_idx * 20);
						memcpy(tmp, (char *)&k_idx, 2);
						buf[0] = tmp[0];
						buf[1] = tmp[1] | 0xc0;

						if (i_idx > j_idx)
							k_idx = i_idx - j_idx;
						else
							k_idx = 0;

						memcpy(tmp, (char *)&k_idx, 2);
						buf[4] = tmp[0];
						buf[5] = tmp[1];

						sendto(ref_g2_sock, buf, 8+(j_idx*20), 0, (struct sockaddr *)&fromDst4, sizeof(struct sockaddr_in));
					}
				}
			/* connected user list request */
			} else if (length==4 && buf[0]==4 && buf[1]==192 && buf[2]==6 && buf[3]==0) {
				unsigned short i_idx = 0;
				unsigned short j_idx = 0;
				unsigned short k_idx = 0;
				unsigned char tmp[2];
				unsigned short total = 0;

				auto pos = inbound_list.find(ip);
				if (pos != inbound_list.end()) {
					// printf("Remote station %s %s requested connected user list\n", inbound_ptr->call, ip);
					/* header is 8 bytes */
					/* reply type */
					buf[2] = 6;
					buf[3] = 0;

					/* total connected users */
					total =  inbound_list.size();
					memcpy(tmp, (char *)&total, 2);
					buf[6] = tmp[0];
					buf[7] = tmp[1];

					for (pos = inbound_list.begin(), i_idx = 0; pos != inbound_list.end();  pos++, i_idx++) {
						/* each entry has 20 bytes */
						buf[8 + (20 * j_idx)] = ' ';
						SINBOUND *inbound = (SINBOUND *)pos->second;

						buf[8 + (20 * j_idx)] = inbound->mod;
						strcpy((char *)buf + 9 + (20 * j_idx), inbound->call);

						buf[17 + (20 * j_idx)] = 0;
						/* readBuffer2[18 + (20 * j_idx)] = 0; */
						buf[18 + (20 * j_idx)] = inbound->client;
						buf[19 + (20 * j_idx)] = 0;
						buf[20 + (20 * j_idx)] = 0x0d;
						buf[21 + (20 * j_idx)] = 0x4d;
						buf[22 + (20 * j_idx)] = 0x37;
						buf[23 + (20 * j_idx)] = 0x4d;
						buf[24 + (20 * j_idx)] = 0x6f;
						buf[25 + (20 * j_idx)] = 0x98;
						buf[26 + (20 * j_idx)] = 0x04;
						buf[27 + (20 * j_idx)] = 0;

						j_idx++;

						if (j_idx == 39) {
							/* 20 bytes for each user, so 39 * 20 = 788 bytes + 8 bytes header = 788 */
							buf[0] = 0x14;
							buf[1] = 0xc3;

							k_idx = i_idx - 38;
							memcpy(tmp, (char *)&k_idx, 2);
							buf[4] = tmp[0];
							buf[5] = tmp[1];

							sendto(ref_g2_sock, buf, 788, 0, (struct sockaddr *)&fromDst4, sizeof(struct sockaddr_in));

							j_idx = 0;
						}
					}

					if (j_idx != 0) {
						k_idx = 8 + (j_idx * 20);
						memcpy(tmp, (char *)&k_idx, 2);
						buf[0] = tmp[0];
						buf[1] = tmp[1] | 0xc0;

						if (i_idx > j_idx)
							k_idx = i_idx - j_idx;
						else
							k_idx = 0;

						memcpy(tmp, (char *)&k_idx, 2);
						buf[4] = tmp[0];
						buf[5] = tmp[1];

						sendto(ref_g2_sock, buf, 8+(j_idx*20), 0, (struct sockaddr *)&fromDst4, sizeof(struct sockaddr_in));
					}
				}
			/* date request */
			} else if (length== 4 && buf[0]==4 && buf[1]==192 && buf[2]==8 && buf[3]==0) {
				time_t ltime;
				struct tm tm;

				auto pos = inbound_list.find(ip);
				if (pos != inbound_list.end()) {
					//SINBOUND *inbound = (SINBOUND *)pos->second;
					// printf("Remote station %s %s requested date\n", inbound_ptr->call, ip);

					time(&ltime);
					localtime_r(&ltime,&tm);

					buf[0] = 34;
					buf[4] = 0xb5;
					buf[5] = 0xae;
					buf[6] = 0x37;
					buf[7] = 0x4d;
					snprintf((char *)buf + 8, 99, "20%02d/%02d/%02d %02d:%02d:%02d %5.5s",
							tm.tm_year % 100, tm.tm_mon+1,tm.tm_mday, tm.tm_hour,tm.tm_min,tm.tm_sec,
							(tzname[0] == NULL)?"     ":tzname[0]);

					sendto(ref_g2_sock, buf, 34, 0, (struct sockaddr *)&fromDst4, sizeof(struct sockaddr_in));
				}
			/* version request */
			} else if (length== 4 && buf[0]==4 && buf[1]==192 && buf[2]==3 && buf[3]==0) {
				auto pos = inbound_list.find(ip);
				if (pos != inbound_list.end()) {
					//SINBOUND *inbound = (SINBOUND *)pos->second;
					// printf("Remote station %s %s requested version\n", inbound_ptr->call, ip);

					buf[0] = 9;
					strncpy((char *)buf + 4, VERSION, 4);
					buf[8] = 0;

					sendto(ref_g2_sock, buf, 9, 0, (struct sockaddr *)&fromDst4, sizeof(struct sockaddr_in));
				}
			}
			else if (length==5 && buf[0]==5 && buf[1]==0 && buf[2]==24 && buf[3]==0 && buf[4]==0) {
				/* reply with the same DISCONNECT */
				sendto(ref_g2_sock, buf, 5, 0, (struct sockaddr *)&fromDst4, sizeof(struct sockaddr_in));

				for (int i=0; i<3; i++) {
					if (fromDst4.sin_addr.s_addr==to_remote_g2[i].toDst4.sin_addr.s_addr && to_remote_g2[i].toDst4.sin_port==htons(rmt_ref_port)) {
						printf("Call %s disconnected\n", to_remote_g2[i].to_call);

						to_remote_g2[i].to_call[0] = '\0';
						memset(&(to_remote_g2[i].toDst4),0,sizeof(struct sockaddr_in));
						to_remote_g2[i].from_mod = to_remote_g2[i].to_mod = ' ';
						to_remote_g2[i].countdown = 0;
						to_remote_g2[i].is_connected = false;
						to_remote_g2[i].in_streamid = 0x0;
					}
				}

				auto pos = inbound_list.find(ip);
				if (pos != inbound_list.end()) {
					SINBOUND *inbound = (SINBOUND *)pos->second;
					if (memcmp(inbound->call, "1NFO", 4) != 0)
						printf("Call %s disconnected\n", inbound->call);
					free(pos->second);
					pos->second = NULL;
					inbound_list.erase(pos);
				}
				print_status_file();
			}

			for (int i=0; i<3; i++) {
				if (fromDst4.sin_addr.s_addr==to_remote_g2[i].toDst4.sin_addr.s_addr && to_remote_g2[i].toDst4.sin_port==htons(rmt_ref_port)) {
					found = true;
					if (length==5 && buf[0]==5 && buf[1]==0 && buf[2]==24 && buf[3]==0 && buf[4]==1) {
						printf("Connected to call %s\n", to_remote_g2[i].to_call);
						queryCommand[0] = 28;
						queryCommand[1] = 192;
						queryCommand[2] = 4;
						queryCommand[3] = 0;

						memcpy(queryCommand + 4, login_call.c_str(), CALL_SIZE);
						for (int j=11; j>3; j--) {
							if (queryCommand[j] == ' ')
								queryCommand[j] = '\0';
							else
								break;
						}
						memset(queryCommand + 12, '\0', 8);
						memcpy(queryCommand + 20, "DV019999", 8);

						// ATTENTION: I should ONLY send once for each distinct
						// remote IP, so  get out of the loop immediately
						sendto(ref_g2_sock, queryCommand, 28, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));

						break;
					}
				}
			}

			for (int i=0; i<3; i++) {
				if ((fromDst4.sin_addr.s_addr == to_remote_g2[i].toDst4.sin_addr.s_addr) && (to_remote_g2[i].toDst4.sin_port == htons(rmt_ref_port))) {
					found = true;
					if (length==8 && buf[0]==8 && buf[1]==192 && buf[2]==4 && buf[3]==0) {
						if (buf[4]== 79 && buf[5]==75 && buf[6]==82) {
							if (!to_remote_g2[i].is_connected) {
								to_remote_g2[i].is_connected = true;
								to_remote_g2[i].countdown = TIMEOUT;
								printf("Login OK to call %s mod %c\n", to_remote_g2[i].to_call, to_remote_g2[i].to_mod);
								print_status_file();

								tracing[i].last_time = time(NULL);

								strcpy(linked_remote_system, to_remote_g2[i].to_call);
								space_p = strchr(linked_remote_system, ' ');
								if (space_p)
									*space_p = '\0';
								sprintf(notify_msg[i], "%c_linked.dat_LINKED_%s_%c", to_remote_g2[i].from_mod, linked_remote_system, to_remote_g2[i].to_mod);
							}
						} else if (buf[4]==70 && buf[5]==65 && buf[6]==73 && buf[7]==76) {
							printf("Login failed to call %s mod %c\n", to_remote_g2[i].to_call, to_remote_g2[i].to_mod);

							sprintf(notify_msg[i], "%c_failed_link.dat_FAILED_TO_LINK", to_remote_g2[i].from_mod);

							to_remote_g2[i].to_call[0] = '\0';
							memset(&(to_remote_g2[i].toDst4),0,sizeof(struct sockaddr_in));
							to_remote_g2[i].from_mod = to_remote_g2[i].to_mod = ' ';
							to_remote_g2[i].countdown = 0;
							to_remote_g2[i].is_connected = false;
							to_remote_g2[i].in_streamid = 0x0;
						} else if (buf[4]==66 && buf[5]==85 && buf[6]==83 && buf[7]==89) {
							printf("Busy or unknown status from call %s mod %c\n", to_remote_g2[i].to_call, to_remote_g2[i].to_mod);

							sprintf(notify_msg[i], "%c_failed_link.dat_FAILED_TO_LINK", to_remote_g2[i].from_mod);

							to_remote_g2[i].to_call[0] = '\0';
							memset(&(to_remote_g2[i].toDst4),0,sizeof(struct sockaddr_in));
							to_remote_g2[i].from_mod = to_remote_g2[i].to_mod = ' ';
							to_remote_g2[i].countdown = 0;
							to_remote_g2[i].is_connected = false;
							to_remote_g2[i].in_streamid = 0x0;
						}
					}
				}
			}

			for (int i=0; i<3; i++) {
				if ((fromDst4.sin_addr.s_addr == to_remote_g2[i].toDst4.sin_addr.s_addr) && (to_remote_g2[i].toDst4.sin_port == htons(rmt_ref_port))) {
					found = true;
					if (length==24 && buf[0]==24 && buf[1]==192 && buf[2]==3 && buf[3]==0) {
						to_remote_g2[i].countdown = TIMEOUT;
					}
				}
			}

			for (int i=0; i<3; i++) {
				if (fromDst4.sin_addr.s_addr==to_remote_g2[i].toDst4.sin_addr.s_addr && to_remote_g2[i].toDst4.sin_port==htons(rmt_ref_port)) {
					found = true;
					if (length == 3)
						to_remote_g2[i].countdown = TIMEOUT;
				}
			}

			/* find out if it is a connected dongle */
			auto pos = inbound_list.find(ip);
			if (pos != inbound_list.end()) {
				SINBOUND *inbound = (SINBOUND *)pos->second;
				found = true;
				inbound->countdown = TIMEOUT;
				/*** ip is same, do not update port
				memcpy((char *)&(inbound_ptr->sin),(char *)&fromDst4, sizeof(struct sockaddr_in));
				***/
			}

			if (!found) {
				/*
				   The incoming packet is not in the list of outbound repeater connections.
				   and it is not a connected dongle.
				   In this case, this must be an INCOMING dongle request
				*/
				if (length==5 && buf[0]==5 && buf[1]==0 && buf[2]==24 && buf[3]==0 && buf[4]==1) {
					if ((inbound_list.size() + 1) > max_dongles)
						printf("Inbound DONGLE-p connection from %s but over the max_dongles limit of %d\n", ip, (int)inbound_list.size());
					else
						sendto(ref_g2_sock, buf, 5, 0, (struct sockaddr *)&fromDst4, sizeof(fromDst4));
				} else if (length==28 && buf[0]==28 && buf[1]==192 && buf[2]==4 && buf[3]==0) {
					/* verify callsign */
					memcpy(call, buf + 4, CALL_SIZE);
					call[CALL_SIZE] = '\0';
					for (int i=7; i>0; i--) {
						if (call[i] == '\0')
							call[i] = ' ';
						else
							break;
					}

					if (memcmp(call, "1NFO", 4))
						printf("Inbound DONGLE-p CALL=%s, ip=%s, DV=%.8s\n", call, ip, buf + 20);

					if ((inbound_list.size() + 1) > max_dongles)
						printf("Inbound DONGLE-p connection from %s but over the max_dongles limit of %d\n", ip, (int)inbound_list.size());
					//else if (admin.size() && (admin.find(call) == admin.end()))
					//	printf("Incoming call [%s] from %s not an ADMIN\n", call, ip);
					else if (regexec(&preg, call, 0, NULL, 0) != 0) {
						printf("Invalid dongle callsign: CALL=%s,ip=%s\n", call, ip);

						buf[0] = 8;
						buf[4] = 70;
						buf[5] = 65;
						buf[6] = 73;
						buf[7] = 76;

						sendto(ref_g2_sock, buf, 8, 0, (struct sockaddr *)&fromDst4, sizeof(fromDst4));
					} else {
						/* add the dongle to the inbound list */
						SINBOUND *inbound = (SINBOUND *)malloc(sizeof(SINBOUND));
						if (inbound) {
							inbound->countdown = TIMEOUT;
							memcpy((char *)&(inbound->sin),(char *)&fromDst4, sizeof(struct sockaddr_in));
							strcpy(inbound->call, call);

							inbound->mod = ' ';

							if (memcmp(buf + 20, "AP", 2) == 0)
								inbound->client = 'A';  /* dvap */
							else if (memcmp(buf + 20, "DV019999", 8) == 0)
								inbound->client = 'H';  /* spot */
							else
								inbound->client = 'D';  /* dongle */

							auto insert_pair = inbound_list.insert(std::pair<std::string, SINBOUND *>(ip, inbound));
							if (insert_pair.second) {
								if (memcmp(inbound->call, "1NFO", 4) != 0)
									printf("new CALL=%s, DONGLE-p, ip=%s, users=%d\n", inbound->call,ip, (int)inbound_list.size());

								buf[0] = 8;
								buf[4] = 79;
								buf[5] = 75;
								buf[6] = 82;
								buf[7] = 87;

								sendto(ref_g2_sock, buf, 8, 0, (struct sockaddr *)&fromDst4, sizeof(fromDst4));
								print_status_file();

							} else {
								printf("failed to add CALL=%s,ip=%s\n",inbound->call,ip);
								free(inbound);
								inbound = NULL;

								buf[0] = 8;
								buf[4] = 70;
								buf[5] = 65;
								buf[6] = 73;
								buf[7] = 76;

								sendto(ref_g2_sock, buf, 8, 0, (struct sockaddr *)&fromDst4, sizeof(fromDst4));
							}
						} else {
							printf("malloc() failed for call=%s,ip=%s\n",call,ip);

							buf[0] = 8;
							buf[4] = 70;
							buf[5] = 65;
							buf[6] = 73;
							buf[7] = 76;

							sendto(ref_g2_sock, buf, 8, 0, (struct sockaddr *)&fromDst4, sizeof(fromDst4));
						}
					}
				}
			}

			if ((length==58 || length==29 || length==32) && 0==memcmp(buf + 2, "DSVT", 4) && (buf[6]==0x10 || buf[6]==0x20) && buf[10]==0x20) {
				/* Is it one of the donglers or repeaters-reflectors */
				found = false;
				for (int i=0; i<3; i++) {
					if (fromDst4.sin_addr.s_addr==to_remote_g2[i].toDst4.sin_addr.s_addr && to_remote_g2[i].toDst4.sin_port==htons(rmt_ref_port)) {
						to_remote_g2[i].countdown = TIMEOUT;
						found = true;
					}
				}
				if (!found) {
					auto pos = inbound_list.find(ip);
					if (pos != inbound_list.end()) {
						SINBOUND *inbound = (SINBOUND *)pos->second;
						inbound->countdown = TIMEOUT;
						found = true;
					}
				}

				SREFDSVT rdsvt; memcpy(rdsvt.head, buf, length);	// copy to struct

				if (length==58 && found) {
					memset(source_stn, ' ', 9);
					source_stn[8] = '\0';

					/* some bad hotspot programs out there using INCORRECT flag */
					if (rdsvt.dsvt.hdr.flag[0]==0x40U || rdsvt.dsvt.hdr.flag[0]==0x48U || rdsvt.dsvt.hdr.flag[0]==0x60U || rdsvt.dsvt.hdr.flag[0]==0x68U)
						rdsvt.dsvt.hdr.flag[0] -= 0x40U;

					/* A reflector will send to us its own RPT1 */
					/* A repeater will send to us its own RPT1 */
					/* A dongler will send to us our RPT1 */

					/* It is from a repeater-reflector, correct rpt1, rpt2 and re-compute pfcs */
					int i;
					for (i=0; i<3; i++) {
						if (fromDst4.sin_addr.s_addr==to_remote_g2[i].toDst4.sin_addr.s_addr && to_remote_g2[i].toDst4.sin_port==htons(rmt_ref_port) &&
						        (
						            (0==memcmp(rdsvt.dsvt.hdr.rpt1, to_remote_g2[i].to_call, 7) && rdsvt.dsvt.hdr.rpt1[7]==to_remote_g2[i].to_mod)  ||
						            (0==memcmp(rdsvt.dsvt.hdr.rpt2, to_remote_g2[i].to_call, 7) && rdsvt.dsvt.hdr.rpt2[7]==to_remote_g2[i].to_mod)
						        )) {
							memcpy(rdsvt.dsvt.hdr.rpt1, owner.c_str(), CALL_SIZE);
							rdsvt.dsvt.hdr.rpt1[7] = to_remote_g2[i].from_mod;
							memcpy(rdsvt.dsvt.hdr.urcall, "CQCQCQ  ", CALL_SIZE);

							memcpy(source_stn, to_remote_g2[i].to_call, CALL_SIZE);
							source_stn[7] = to_remote_g2[i].to_mod;

							break;
						}
					}

					if (i == 3) {
						pos = inbound_list.find(ip);
						if (pos != inbound_list.end()) {
							SINBOUND *inbound = (SINBOUND *)pos->second;
							memcpy(source_stn, inbound->call, 8);
						}
					}

					/* somebody's crazy idea of having a personal callsign in RPT2 */
					/* we must set it to our gateway callsign */
					memcpy(rdsvt.dsvt.hdr.rpt2, owner.c_str(), CALL_SIZE);
					rdsvt.dsvt.hdr.rpt2[7] = 'G';
					calcPFCS(rdsvt.dsvt.title, 56);

					/* At this point, all data have our RPT1 and RPT2 */

					i = -1;
					if (rdsvt.dsvt.hdr.rpt1[7] == 'A')
						i = 0;
					else if (rdsvt.dsvt.hdr.rpt1[7] == 'B')
						i = 1;
					else if (rdsvt.dsvt.hdr.rpt1[7] == 'C')
						i = 2;

					/* are we sure that RPT1 is our system? */
					if (0==memcmp(rdsvt.dsvt.hdr.rpt1, owner.c_str(), CALL_SIZE-1) && i>=0) {
						/* Last Heard */
						if (old_sid[i].sid != rdsvt.dsvt.streamid) {
							if (qso_details)
								printf("START from remote g2: streamID=%04x, flags=%02x:%02x:%02x, my=%.8s, sfx=%.4s, ur=%.8s, rpt1=%.8s, rpt2=%.8s, %d bytes fromIP=%s, source=%.8s\n",
								        ntohs(rdsvt.dsvt.streamid), rdsvt.dsvt.hdr.flag[0], rdsvt.dsvt.hdr.flag[0], rdsvt.dsvt.hdr.flag[0],
								        rdsvt.dsvt.hdr.mycall, rdsvt.dsvt.hdr.sfx, rdsvt.dsvt.hdr.urcall, rdsvt.dsvt.hdr.rpt1, rdsvt.dsvt.hdr.rpt2,
								        length, inet_ntoa(fromDst4.sin_addr), source_stn);

							// put user into tmp1
							memcpy(tmp1, rdsvt.dsvt.hdr.mycall, 8);
							tmp1[8] = '\0';

							// delete the user if exists
							for (auto dt_lh_pos = dt_lh_list.begin(); dt_lh_pos != dt_lh_list.end();  dt_lh_pos++) {
								if (strcmp((char *)dt_lh_pos->second.c_str(), tmp1) == 0) {
									dt_lh_list.erase(dt_lh_pos);
									break;
								}
							}
							/* Limit?, delete oldest user */
							if (dt_lh_list.size() == LH_MAX_SIZE) {
								auto dt_lh_pos = dt_lh_list.begin();
								dt_lh_list.erase(dt_lh_pos);
							}
							// add user
							time(&tnow);
							sprintf(tmp2, "%ld=r%.6s%c%c", tnow, source_stn, source_stn[7], rdsvt.dsvt.hdr.rpt1[7]);
							dt_lh_list[tmp2] = tmp1;

							old_sid[i].sid = rdsvt.dsvt.streamid;
						}

						/* send the data to the local gateway/repeater */
						Link2Gate.Write(rdsvt.dsvt.title, 56);

						/* send the data to the donglers */
						for (auto pos = inbound_list.begin(); pos != inbound_list.end(); pos++) {
							SINBOUND *inbound = (SINBOUND *)pos->second;
							if (fromDst4.sin_addr.s_addr != inbound->sin.sin_addr.s_addr) {
								sendto(ref_g2_sock, rdsvt.head, 58, 0, (struct sockaddr *)&(inbound->sin), sizeof(struct sockaddr_in));
							} else
								inbound->mod = rdsvt.dsvt.hdr.rpt1[7];
						}

						if (to_remote_g2[i].toDst4.sin_addr.s_addr!=fromDst4.sin_addr.s_addr && to_remote_g2[i].is_connected) {
							if ( /*** (memcmp(readBuffer2 + 44, owner, 8) != 0) && ***/         /* block repeater announcements */
							    0==memcmp(rdsvt.dsvt.hdr.urcall, "CQCQCQ", 6) &&	/* CQ calls only */
							    (rdsvt.dsvt.hdr.flag[0]==0x00 ||	/* normal */
							     rdsvt.dsvt.hdr.flag[0]==0x08 ||	/* EMR */
							     rdsvt.dsvt.hdr.flag[0]==0x20 ||	/* BK */
							     rdsvt.dsvt.hdr.flag[7]==0x28) &&	/* EMR + BK */
							    0==memcmp(rdsvt.dsvt.hdr.rpt2, owner.c_str(), CALL_SIZE-1) &&         /* rpt2 must be us */
							    rdsvt.dsvt.hdr.rpt2[7] == 'G') {
								to_remote_g2[i].in_streamid = rdsvt.dsvt.streamid;

								if (to_remote_g2[i].toDst4.sin_port==htons(rmt_xrf_port) || to_remote_g2[i].toDst4.sin_port== htons(rmt_ref_port)) {
									memcpy(rdsvt.dsvt.hdr.rpt1, to_remote_g2[i].to_call, CALL_SIZE);
									rdsvt.dsvt.hdr.rpt1[7] = to_remote_g2[i].to_mod;
									memcpy(rdsvt.dsvt.hdr.rpt2, to_remote_g2[i].to_call, CALL_SIZE);
									rdsvt.dsvt.hdr.rpt2[7] = 'G';
									calcPFCS(rdsvt.dsvt.title, 56);

									if (to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port)) {
										/* inform XRF about the source */
										rdsvt.dsvt.flagb[2] = to_remote_g2[i].from_mod;
										sendto(xrf_g2_sock, rdsvt.dsvt.title, 56, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));
									} else
										sendto(ref_g2_sock, rdsvt.head, 58, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));
								} else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_dcs_port)) {
									memcpy(ref_2_dcs[i].mycall, rdsvt.dsvt.hdr.mycall, 8);
									memcpy(ref_2_dcs[i].sfx, rdsvt.dsvt.hdr.sfx, 4);
									ref_2_dcs[i].dcs_rptr_seq = 0;
								}
							}
						}
					}
				} else if (found) {
					if (rdsvt.dsvt.ctrl & 0x40U) {
						for (int i=0; i<3; i++) {
							if (old_sid[i].sid == rdsvt.dsvt.streamid) {
								if (qso_details)
									printf("END from remote g2: streamID=%04x, %d bytes from IP=%s\n", ntohs(rdsvt.dsvt.streamid), length, inet_ntoa(fromDst4.sin_addr));

								old_sid[i].sid = 0x0;

								break;
							}
						}
					}

					/* send the data to the local gateway/repeater */
					Link2Gate.Write(rdsvt.dsvt.title, 27);

					/* send the data to the donglers */
					for (pos = inbound_list.begin(); pos != inbound_list.end(); pos++) {
						SINBOUND *inbound = (SINBOUND *)pos->second;
						if (fromDst4.sin_addr.s_addr != inbound->sin.sin_addr.s_addr) {
							sendto(ref_g2_sock, rdsvt.head, 29, 0, (struct sockaddr *)&(inbound->sin), sizeof(struct sockaddr_in));
						}
					}

					for (int i=0; i<3; i++) {
						if (to_remote_g2[i].is_connected && to_remote_g2[i].toDst4.sin_addr.s_addr!=fromDst4.sin_addr.s_addr && to_remote_g2[i].in_streamid==rdsvt.dsvt.streamid) {
							if (to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port)) {
								/* inform XRF about the source */
								rdsvt.dsvt.flagb[2] = to_remote_g2[i].from_mod;
								sendto(xrf_g2_sock, rdsvt.dsvt.title, 27, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));
							} else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_ref_port))
								sendto(ref_g2_sock, rdsvt.head, 29,  0,(struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));
							else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_dcs_port)) {
								memset(dcs_buf, 0x00, 600);
								dcs_buf[0] = dcs_buf[1] = dcs_buf[2] = '0';
								dcs_buf[3] = '1';
								dcs_buf[4] = dcs_buf[5] = dcs_buf[6] = 0x0;
								memcpy(dcs_buf + 7, to_remote_g2[i].to_call, 8);
								dcs_buf[14] = to_remote_g2[i].to_mod;
								memcpy(dcs_buf + 15, owner.c_str(), CALL_SIZE);
								dcs_buf[22] = to_remote_g2[i].from_mod;
								memcpy(dcs_buf + 23, "CQCQCQ  ", 8);
								memcpy(dcs_buf + 31, ref_2_dcs[i].mycall, 8);
								memcpy(dcs_buf + 39, ref_2_dcs[i].sfx, 4);
								dcs_buf[43] = buf[14];  /* streamid0 */
								dcs_buf[44] = buf[15];  /* streamid1 */
								dcs_buf[45] = buf[16];  /* cycle sequence */
								memcpy(dcs_buf + 46, rdsvt.dsvt.vasd.voice, 12);

								dcs_buf[58] = (ref_2_dcs[i].dcs_rptr_seq >> 0)  & 0xff;
								dcs_buf[59] = (ref_2_dcs[i].dcs_rptr_seq >> 8)  & 0xff;
								dcs_buf[60] = (ref_2_dcs[i].dcs_rptr_seq >> 16) & 0xff;

								ref_2_dcs[i].dcs_rptr_seq++;

								dcs_buf[61] = 0x01;
								dcs_buf[62] = 0x00;

								sendto(dcs_g2_sock, dcs_buf, 100, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));
							}

							if (rdsvt.dsvt.ctrl & 0x40) {
								to_remote_g2[i].in_streamid = 0x0;
							}
							break;
						}
					}
				}
			}
			FD_CLR (ref_g2_sock,&fdset);
		}

		if (keep_running && FD_ISSET(dcs_g2_sock, &fdset)) {
			socklen_t fromlen = sizeof(struct sockaddr_in);
			int length = recvfrom(dcs_g2_sock, dcs_buf, 1000, 0, (struct sockaddr *)&fromDst4, &fromlen);

			strncpy(ip, inet_ntoa(fromDst4.sin_addr), IP_SIZE);
			ip[IP_SIZE] = '\0';

			/* header, audio */
			if (dcs_buf[0]=='0' && dcs_buf[1]=='0' && dcs_buf[2]=='0' && dcs_buf[3]=='1') {
				if (length == 100) {
					memset(source_stn, ' ', 9);
					source_stn[8] = '\0';

					/* find out our local module */
					int i;
					for (i=0; i<3; i++) {
						if (to_remote_g2[i].is_connected && fromDst4.sin_addr.s_addr==to_remote_g2[i].toDst4.sin_addr.s_addr &&
								0==memcmp(dcs_buf + 7, to_remote_g2[i].to_call, 7) && to_remote_g2[i].to_mod==dcs_buf[14]) {
							memcpy(source_stn, to_remote_g2[i].to_call, 8);
							source_stn[7] = to_remote_g2[i].to_mod;
							break;
						}
					}

					/* Is it our local module */
					if (i < 3) {
						/* Last Heard */
						if (memcmp(&old_sid[i].sid, dcs_buf + 43, 2)) {
							if (qso_details)
								printf("START from dcs: streamID=%02x%02x, my=%.8s, sfx=%.4s, ur=%.8s, rpt1=%.8s, rpt2=%.8s, %d bytes fromIP=%s, source=%.8s\n",
								        dcs_buf[44],dcs_buf[43], &dcs_buf[31], &dcs_buf[39], &dcs_buf[23], &dcs_buf[7], &dcs_buf[15],
								        length, inet_ntoa(fromDst4.sin_addr), source_stn);

							// put user into tmp1
							memcpy(tmp1, dcs_buf + 31, 8);
							tmp1[8] = '\0';

							// delete the user if exists
							for (auto dt_lh_pos=dt_lh_list.begin(); dt_lh_pos!=dt_lh_list.end();  dt_lh_pos++) {
								if (strcmp(dt_lh_pos->second.c_str(), tmp1) == 0) {
									dt_lh_list.erase(dt_lh_pos);
									break;
								}
							}
							/* Limit?, delete oldest user */
							if (dt_lh_list.size() == LH_MAX_SIZE) {
								auto dt_lh_pos = dt_lh_list.begin();
								dt_lh_list.erase(dt_lh_pos);
							}
							// add user
							time(&tnow);
							sprintf(tmp2, "%ld=r%.6s%c%c", tnow, source_stn, source_stn[7], to_remote_g2[i].from_mod);
							dt_lh_list[tmp2] = tmp1;

							memcpy(&old_sid[i].sid, dcs_buf + 43, 2);
						}

						to_remote_g2[i].countdown = TIMEOUT;

						/* new stream ? */
						if (memcmp(&to_remote_g2[i].in_streamid, dcs_buf+43, 2)) {
							memcpy(&to_remote_g2[i].in_streamid, dcs_buf+43, 2);
							dcs_seq[i] = 0xff;

							/* generate our header */
							SREFDSVT rdsvt;
							rdsvt.head[0] = (unsigned char)(58 & 0xFF);
							rdsvt.head[1] = (unsigned char)(58 >> 8 & 0x1F);
							rdsvt.head[1] = (unsigned char)(rdsvt.head[1] | 0xFFFFFF80);
							memcpy(rdsvt.dsvt.title, "DSVT", 4);
							rdsvt.dsvt.config = 0x10;
							rdsvt.dsvt.flaga[0] = rdsvt.dsvt.flaga[1] = rdsvt.dsvt.flaga[2] = 0x00;
							rdsvt.dsvt.id = 0x20;
							rdsvt.dsvt.flagb[0] = 0x00;
							rdsvt.dsvt.flagb[1] = 0x01;
							if (to_remote_g2[i].from_mod == 'A')
								rdsvt.dsvt.flagb[2] = 0x03;
							else if (to_remote_g2[i].from_mod == 'B')
								rdsvt.dsvt.flagb[2] = 0x01;
							else
								rdsvt.dsvt.flagb[2] = 0x02;
							memcpy(&rdsvt.dsvt.streamid, dcs_buf+43, 2);
							rdsvt.dsvt.ctrl = 0x80;
							rdsvt.dsvt.hdr.flag[0] = rdsvt.dsvt.hdr.flag[1] = rdsvt.dsvt.hdr.flag[2] = 0x00;
							memcpy(rdsvt.dsvt.hdr.rpt1, owner.c_str(), CALL_SIZE);
							rdsvt.dsvt.hdr.rpt1[7] = to_remote_g2[i].from_mod;
							memcpy(rdsvt.dsvt.hdr.rpt2, owner.c_str(), CALL_SIZE);
							rdsvt.dsvt.hdr.rpt2[7] = 'G';
							memcpy(rdsvt.dsvt.hdr.urcall, "CQCQCQ  ", 8);
							memcpy(rdsvt.dsvt.hdr.mycall, dcs_buf + 31, 8);
							memcpy(rdsvt.dsvt.hdr.sfx, dcs_buf + 39, 4);
							calcPFCS(rdsvt.dsvt.title, 56);

							/* send the header to the local gateway/repeater */
							for (int j=0; j<5; j++)
								Link2Gate.Write(rdsvt.dsvt.title, 56);

							/* send the data to the donglers */
							for (auto pos = inbound_list.begin(); pos != inbound_list.end(); pos++) {
								SINBOUND *inbound = (SINBOUND *)pos->second;
								for (int j=0; j<5; j++)
									sendto(ref_g2_sock, rdsvt.head, 58, 0, (struct sockaddr *)&(inbound->sin), sizeof(struct sockaddr_in));
							}
						}

						if (0==memcmp(&to_remote_g2[i].in_streamid, dcs_buf+43, 2) && dcs_seq[i]!=dcs_buf[45]) {
							dcs_seq[i] = dcs_buf[45];
							SREFDSVT rdsvt;
							rdsvt.head[0] = (unsigned char)(29 & 0xFF);
							rdsvt.head[1] = (unsigned char)(29 >> 8 & 0x1F);
							rdsvt.head[1] = (unsigned char)(rdsvt.head[1] | 0xFFFFFF80);
							memcpy(rdsvt.dsvt.title, "DSVT", 4);
							rdsvt.dsvt.config = 0x20;
							rdsvt.dsvt.flaga[0] = rdsvt.dsvt.flaga[1] = rdsvt.dsvt.flaga[2] = 0x00;
							rdsvt.dsvt.id = 0x20;
							rdsvt.dsvt.flagb[0] = 0x00;
							rdsvt.dsvt.flagb[1] = 0x01;
							if (to_remote_g2[i].from_mod == 'A')
								rdsvt.dsvt.flagb[2] = 0x03;
							else if (to_remote_g2[i].from_mod == 'B')
								rdsvt.dsvt.flagb[2] = 0x01;
							else
								rdsvt.dsvt.flagb[2] = 0x02;
							memcpy(&rdsvt.dsvt.streamid, dcs_buf+43, 2);
							rdsvt.dsvt.ctrl = dcs_buf[45];
							memcpy(rdsvt.dsvt.vasd.voice, dcs_buf+46, 12);

							/* send the data to the local gateway/repeater */
							Link2Gate.Write(rdsvt.dsvt.title, 27);

							/* send the data to the donglers */
							for (auto pos = inbound_list.begin(); pos != inbound_list.end(); pos++) {
								SINBOUND *inbound = (SINBOUND *)pos->second;
								sendto(ref_g2_sock, rdsvt.head, 29, 0, (struct sockaddr *)&(inbound->sin), sizeof(struct sockaddr_in));
							}

							if ((dcs_buf[45] & 0x40) != 0) {
								old_sid[i].sid = 0x0;

								if (qso_details)
									printf("END from dcs: streamID=%04x, %d bytes from IP=%s\n", ntohs(rdsvt.dsvt.streamid), length, inet_ntoa(fromDst4.sin_addr));

								to_remote_g2[i].in_streamid = 0x0;
								dcs_seq[i] = 0xff;
							}
						}
					}
				}
			} else if (dcs_buf[0]=='E' && dcs_buf[1]=='E' && dcs_buf[2]=='E' && dcs_buf[3]=='E')
				;
			else if (length == 35)
				;
			/* is this a keepalive 22 bytes */
			else if (length == 22) {
				int i = -1;
				if (dcs_buf[17] == 'A')
					i = 0;
				else if (dcs_buf[17] == 'B')
					i = 1;
				else if (dcs_buf[17] == 'C')
					i = 2;

				/* It is one of our valid repeaters */
				// DG1HT from owner 8 to 7
				if (i>=0 && 0==memcmp(dcs_buf + 9, owner.c_str(), CALL_SIZE-1)) {
					/* is that the remote system that we asked to connect to? */
					if (fromDst4.sin_addr.s_addr==to_remote_g2[i].toDst4.sin_addr.s_addr && to_remote_g2[i].toDst4.sin_port==htons(rmt_dcs_port) &&
							0==memcmp(to_remote_g2[i].to_call, dcs_buf, 7) && to_remote_g2[i].to_mod==dcs_buf[7]) {
						if (!to_remote_g2[i].is_connected) {
							tracing[i].last_time = time(NULL);

							to_remote_g2[i].is_connected = true;
							printf("Connected from: %.*s\n", 8, dcs_buf);
							print_status_file();

							strcpy(linked_remote_system, to_remote_g2[i].to_call);
							space_p = strchr(linked_remote_system, ' ');
							if (space_p)
								*space_p = '\0';
							sprintf(notify_msg[i], "%c_linked.dat_LINKED_%s_%c", to_remote_g2[i].from_mod, linked_remote_system, to_remote_g2[i].to_mod);
						}
						to_remote_g2[i].countdown = TIMEOUT;
					}
				}
			} else if (length == 14) {	/* is this a reply to our link/unlink request: 14 bytes */
				int i = -1;
				if (dcs_buf[8] == 'A')
					i = 0;
				else if (dcs_buf[8] == 'B')
					i = 1;
				else if (dcs_buf[8] == 'C')
					i = 2;

				/* It is one of our valid repeaters */
				if ((i >= 0) && (memcmp(dcs_buf, owner.c_str(), CALL_SIZE) == 0)) {
					/* It is from a remote that we contacted */
					if ((fromDst4.sin_addr.s_addr == to_remote_g2[i].toDst4.sin_addr.s_addr) && (to_remote_g2[i].toDst4.sin_port == htons(rmt_dcs_port)) && (to_remote_g2[i].from_mod == dcs_buf[8])) {
						if ((to_remote_g2[i].to_mod == dcs_buf[9]) && (memcmp(dcs_buf + 10, "ACK", 3) == 0)) {
							to_remote_g2[i].countdown = TIMEOUT;
							if (!to_remote_g2[i].is_connected) {
								tracing[i].last_time = time(NULL);

								to_remote_g2[i].is_connected = true;
								printf("Connected from: %.*s\n", 8, to_remote_g2[i].to_call);
								print_status_file();

								strcpy(linked_remote_system, to_remote_g2[i].to_call);
								space_p = strchr(linked_remote_system, ' ');
								if (space_p)
									*space_p = '\0';
								sprintf(notify_msg[i], "%c_linked.dat_LINKED_%s_%c", to_remote_g2[i].from_mod, linked_remote_system, to_remote_g2[i].to_mod);
							}
						} else if (memcmp(dcs_buf + 10, "NAK", 3) == 0) {
							printf("Link module %c to [%s] %c is unlinked\n", to_remote_g2[i].from_mod, to_remote_g2[i].to_call, to_remote_g2[i].to_mod);

							sprintf(notify_msg[i], "%c_failed_link.dat_UNLINKED", to_remote_g2[i].from_mod);

							to_remote_g2[i].to_call[0] = '\0';
							memset(&(to_remote_g2[i].toDst4),0,sizeof(struct sockaddr_in));
							to_remote_g2[i].from_mod = to_remote_g2[i].to_mod = ' ';
							to_remote_g2[i].countdown = 0;
							to_remote_g2[i].is_connected = false;
							to_remote_g2[i].in_streamid = 0x0;

							print_status_file();
						}
					}
				}
			}
			FD_CLR (dcs_g2_sock,&fdset);
		}

		if (keep_running && FD_ISSET(Gate2Link.GetFD(), &fdset)) {
			SDSTR dstr;
			int length = Gate2Link.Read(dstr.pkt_id, 100);

			if ((length==58 || length==29 || length==32) && dstr.flag[0]==0x73 && dstr.flag[1] == 0x12 && dstr.flag[2] ==0x0 && (0==memcmp(dstr.pkt_id,"DSTR", 4) || 0==memcmp(dstr.pkt_id,"CCS_", 4)) && dstr.vpkt.icm_id==0x20 && (dstr.remaining==0x30 || dstr.remaining==0x13 || dstr.remaining==0x16)) {

				if (length == 58) {
					if (qso_details)
						printf("START from local g2: cntr=%04x, streamID=%04x, flags=%02x:%02x:%02x, my=%.8s, sfx=%.4s, ur=%.8s, rpt1=%.8s, rpt2=%.8s, %d bytes on %s\n", ntohs(dstr.counter), ntohs(dstr.vpkt.streamid), dstr.vpkt.hdr.flag[0], dstr.vpkt.hdr.flag[1], dstr.vpkt.hdr.flag[2], dstr.vpkt.hdr.my, dstr.vpkt.hdr.nm, dstr.vpkt.hdr.ur, dstr.vpkt.hdr.r1, dstr.vpkt.hdr.r2, length, gate2link.c_str());

					/* save mycall */
					memcpy(call, dstr.vpkt.hdr.my, 8);
					call[8] = '\0';

					int i = -1;
					if (dstr.vpkt.hdr.r1[7] == 'A')
						i = 0;
					else if (dstr.vpkt.hdr.r1[7] == 'B')
						i = 1;
					else if (dstr.vpkt.hdr.r1[7] == 'C')
						i = 2;

					if (i >= 0) {
						memcpy(dtmf_mycall[i], dstr.vpkt.hdr.my, 8);
						dtmf_mycall[i][8] = '\0';

						new_group[i] = true;
						GPS_seen[i] = false;

						/* Last Heard */
						//put user into tmp1
						memcpy(tmp1, dstr.vpkt.hdr.my, 8);
						tmp1[8] = '\0';

						// delete the user if exists
						for (auto dt_lh_pos=dt_lh_list.begin(); dt_lh_pos!=dt_lh_list.end();  dt_lh_pos++) {
							if (strcmp(dt_lh_pos->second.c_str(), tmp1) == 0) {
								dt_lh_list.erase(dt_lh_pos);
								break;
							}
						}
						/* Limit?, delete oldest user */
						if (dt_lh_list.size() == LH_MAX_SIZE) {
							auto dt_lh_pos = dt_lh_list.begin();
							dt_lh_list.erase(dt_lh_pos);
						}
						/* add user */
						time(&tnow);
						if (0 == memcmp(dstr.pkt_id,"CCS_", 4))
							sprintf(tmp2, "%ld=r%.7s%c", tnow, "-->CCS ", dstr.vpkt.hdr.r1[7]);
						else
							sprintf(tmp2, "%ld=l%.8s", tnow, dstr.vpkt.hdr.r1);
						dt_lh_list[tmp2] = tmp1;

						memcpy(dstr.pkt_id, "DSTR", 4);

						tracing[i].streamid = dstr.vpkt.streamid;
						tracing[i].last_time = time(NULL);
					}

					if (memcmp(dstr.vpkt.hdr.ur, "CQCQCQ", 6) && i>=0) {
						if (memcmp(dstr.vpkt.hdr.ur, owner.c_str(), CALL_SIZE-1) && dstr.vpkt.hdr.ur[7] == 'L' && 0==memcmp(dstr.vpkt.hdr.r2, owner.c_str(), CALL_SIZE-1) && dstr.vpkt.hdr.r2[7] == 'G' && (dstr.vpkt.hdr.flag[0]==0x00 || dstr.vpkt.hdr.flag[0]==0x08 || dstr.vpkt.hdr.flag[0]==0x20 || dstr.vpkt.hdr.flag[0]==0x28)) {
							if (
									// if there is a black list, is he in the blacklist?
									(link_blacklist.size() && link_blacklist.end()!=link_blacklist.find(call)) ||
									// or if there is an allow list, is he not in it?
									(link_unlink_user.size() && link_unlink_user.find(call)==link_unlink_user.end())
								) {
								printf("link request denied, unauthorized user [%s]\n", call);
							} else {
								char temp_repeater[CALL_SIZE + 1];
								memset(temp_repeater, ' ', CALL_SIZE);
								memcpy(temp_repeater, dstr.vpkt.hdr.ur, CALL_SIZE - 2);
								temp_repeater[CALL_SIZE] = '\0';

								if ((to_remote_g2[i].to_call[0] == '\0') ||   /* not linked */
								        ((to_remote_g2[i].to_call[0] != '\0') &&  /* waiting for a link reply that may never arrive */
								         !to_remote_g2[i].is_connected))

									g2link(dstr.vpkt.hdr.r1[7], temp_repeater, dstr.vpkt.hdr.ur[6]);
								else if (to_remote_g2[i].is_connected) {
									strcpy(linked_remote_system, to_remote_g2[i].to_call);
									space_p = strchr(linked_remote_system, ' ');
									if (space_p)
										*space_p = '\0';
									sprintf(notify_msg[i], "%c_already_linked.dat_LINKED_%s_%c", to_remote_g2[i].from_mod, linked_remote_system, to_remote_g2[i].to_mod);
								}
							}
						} else if (0==memcmp(dstr.vpkt.hdr.ur, "       U", CALL_SIZE)) {
							if (
									// if there is a black list, is he in the blacklist?
									(link_blacklist.size() && link_blacklist.end()!=link_blacklist.find(call)) ||
									// or if there is an allow list, is he not in it?
									(link_unlink_user.size() && link_unlink_user.find(call)==link_unlink_user.end())
								) {
								printf("unlink request denied, unauthorized user [%s]\n", call);
							} else {
								if (to_remote_g2[i].to_call[0] != '\0') {
									if (to_remote_g2[i].toDst4.sin_port == htons(rmt_ref_port)) {
										/* Check to see if any other local bands are linked to that same IP */
										int j;
										for (j=0; j<3; j++) {
											if (j != i) {
												if (to_remote_g2[j].toDst4.sin_addr.s_addr==to_remote_g2[i].toDst4.sin_addr.s_addr && to_remote_g2[j].toDst4.sin_port==htons(rmt_ref_port)) {
													printf("Info: Local %c is also linked to %s (different module) %c\n", to_remote_g2[j].from_mod, to_remote_g2[j].to_call, to_remote_g2[j].to_mod);
													break;
												}
											}
										}

										if (j == 3) {
											/* nothing else is linked there, send DISCONNECT */
											queryCommand[0] = 5;
											queryCommand[1] = 0;
											queryCommand[2] = 24;
											queryCommand[3] = 0;
											queryCommand[4] = 0;
											sendto(ref_g2_sock, queryCommand, 5, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));
										}
									} else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port)) {
										strcpy(unlink_request, owner.c_str());
										unlink_request[8] = to_remote_g2[i].from_mod;
										unlink_request[9] = ' ';
										unlink_request[10] = '\0';

										for (int j=0; j<5; j++)
											sendto(xrf_g2_sock, unlink_request, CALL_SIZE+3, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));
									} else {
										strcpy(cmd_2_dcs, owner.c_str());
										cmd_2_dcs[8] = to_remote_g2[i].from_mod;
										cmd_2_dcs[9] = ' ';
										cmd_2_dcs[10] = '\0';
										memcpy(cmd_2_dcs + 11, to_remote_g2[i].to_call, 8);

										for (int j=0; j<5; j++)
											sendto(dcs_g2_sock, cmd_2_dcs, 19, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));
									}

									printf("Unlinked from [%s] mod %c\n", to_remote_g2[i].to_call, to_remote_g2[i].to_mod);
									sprintf(notify_msg[i], "%c_unlinked.dat_UNLINKED", to_remote_g2[i].from_mod);

									/* now zero out this entry */
									to_remote_g2[i].to_call[0] = '\0';
									memset(&(to_remote_g2[i].toDst4),0,sizeof(struct sockaddr_in));
									to_remote_g2[i].from_mod = to_remote_g2[i].to_mod = ' ';
									to_remote_g2[i].countdown = 0;
									to_remote_g2[i].is_connected = false;
									to_remote_g2[i].in_streamid = 0x0;

									print_status_file();
								} else {
									sprintf(notify_msg[i], "%c_already_unlinked.dat_UNLINKED", dstr.vpkt.hdr.r1[7]);
								}
							}
						}
						else if (0 == memcmp(dstr.vpkt.hdr.ur, "       I", CALL_SIZE)) {
							if (to_remote_g2[i].is_connected) {
								strcpy(linked_remote_system, to_remote_g2[i].to_call);
								space_p = strchr(linked_remote_system, ' ');
								if (space_p)
									*space_p = '\0';
								sprintf(notify_msg[i], "%c_linked.dat_LINKED_%s_%c", to_remote_g2[i].from_mod, linked_remote_system, to_remote_g2[i].to_mod);
							} else {
								sprintf(notify_msg[i], "%c_id.dat_%s_NOT_LINKED", dstr.vpkt.hdr.r1[7], owner.c_str());
							}
						}
						else if (0==memcmp(dstr.vpkt.hdr.ur, "      ", 6) && dstr.vpkt.hdr.ur[7]=='X') {	// execute a script
							if (dstr.vpkt.hdr.ur[6] != ' ') {	// there has to be a char here
								bool user_ok = true;
								if (admin.size()>0 && admin.end()==admin.find(call)) { // only admins (if defined) can execute scripts
									printf("%s not found in the link_admin list!\n", call);
									user_ok = false;
								}
								if (user_ok) {
									memset(system_cmd, '\0', sizeof(system_cmd));
									snprintf(system_cmd, FILENAME_MAX, "%s/exec_%c.sh %s %c &", announce_dir.c_str(), dstr.vpkt.hdr.ur[6], call, dstr.vpkt.hdr.r1[7]);
									printf("Executing %s\n", system_cmd);
									system(system_cmd);
								}
							}
						}
						else if (0==memcmp(dstr.vpkt.hdr.ur, "      ", 6) && dstr.vpkt.hdr.ur[6]=='D' && admin.find(call)!=admin.end()) { // only ADMIN can block dongle users
							if (dstr.vpkt.hdr.ur[7] == '1') {
								max_dongles = saved_max_dongles;
								printf("Dongle connections are now allowed\n");
							} else if (dstr.vpkt.hdr.ur[7] == '0') {
								inbound_list.clear();
								max_dongles = 0;
								printf("Dongle connections are now disallowed\n");
							}
						}
						else if (0==memcmp(dstr.vpkt.hdr.ur, "       F", CALL_SIZE) && admin.find(call)!=admin.end()) { // only ADMIN can reload gwys.txt
							gwy_list.clear();
							load_gwys(gwys);
						}
					}

					/* send data to the donglers */
					SREFDSVT rdsvt;
					if (inbound_list.size() > 0) {
						rdsvt.head[0] = (unsigned char)(58 & 0xFF);
						rdsvt.head[1] = (unsigned char)(58 >> 8 & 0x1F);
						rdsvt.head[1] = (unsigned char)(rdsvt.head[1] | 0xFFFFFF80);

						memcpy(rdsvt.dsvt.title, "DSVT", 4);
						rdsvt.dsvt.config = 0x10;
						rdsvt.dsvt.flaga[0] = rdsvt.dsvt.flaga[1] = rdsvt.dsvt.flaga[2] = 0x00;
						rdsvt.dsvt.id = dstr.vpkt.icm_id;
						rdsvt.dsvt.flagb[0] = dstr.vpkt.dst_rptr_id;
						rdsvt.dsvt.flagb[1] = dstr.vpkt.snd_rptr_id;
						rdsvt.dsvt.flagb[2] = dstr.vpkt.snd_term_id;
						memcpy(&rdsvt.dsvt.streamid, &dstr.vpkt.streamid, 44);
						memcpy(rdsvt.dsvt.hdr.rpt1, owner.c_str(), CALL_SIZE);
						rdsvt.dsvt.hdr.rpt1[7] = dstr.vpkt.hdr.r1[7];
						memcpy(rdsvt.dsvt.hdr.rpt2, owner.c_str(), CALL_SIZE);
						rdsvt.dsvt.hdr.rpt2[7] = 'G';
						memcpy(rdsvt.dsvt.hdr.urcall, "CQCQCQ  ", 8);
						calcPFCS(rdsvt.dsvt.title, 56);

						for (auto pos = inbound_list.begin(); pos != inbound_list.end(); pos++) {
							SINBOUND *inbound = (SINBOUND *)pos->second;
							for (int j=0; j<5; j++)
								sendto(ref_g2_sock, rdsvt.head, 58, 0, (struct sockaddr *)&(inbound->sin), sizeof(struct sockaddr_in));
						}
					}

					if (i >= 0) {
						/* do we have to broadcast ? */
						/* make sure the source is linked to xrf */
						if (to_remote_g2[i].is_connected && 0==memcmp(to_remote_g2[i].to_call, "XRF", 3) && 0==memcmp(dstr.vpkt.hdr.r2, owner.c_str(), CALL_SIZE-1) && dstr.vpkt.hdr.r2[7]=='G' && 0==memcmp(dstr.vpkt.hdr.ur, "CQCQCQ", 6)) {
							brd_from_rptr_idx = 0;
							streamid_raw = ntohs(dstr.vpkt.streamid);

							for (int j=0; j<3; j++) {
								if (j!=i && to_remote_g2[j].is_connected && 0==memcmp(to_remote_g2[j].to_call, to_remote_g2[i].to_call, 8) && to_remote_g2[j].to_mod==to_remote_g2[i].to_mod && to_remote_g2[j].to_mod!='E') {
									memcpy(fromrptr_torptr_brd.title, "DSVT", 4);
									fromrptr_torptr_brd.config = 0x10;
									fromrptr_torptr_brd.flaga[0] = fromrptr_torptr_brd.flaga[1] = fromrptr_torptr_brd.flaga[2] = 0x0;
									fromrptr_torptr_brd.id = dstr.vpkt.icm_id;
									fromrptr_torptr_brd.flagb[0] = dstr.vpkt.dst_rptr_id;
									fromrptr_torptr_brd.flagb[1] = dstr.vpkt.snd_rptr_id;
									fromrptr_torptr_brd.flagb[2] = dstr.vpkt.snd_term_id;
									memcpy(&fromrptr_torptr_brd.streamid, &dstr.vpkt.streamid, 44);

									if (++streamid_raw == 0)
										streamid_raw++;
									fromrptr_torptr_brd.streamid = htons(streamid_raw);

									memcpy(fromrptr_torptr_brd.hdr.rpt1, owner.c_str(), CALL_SIZE);
									fromrptr_torptr_brd.hdr.rpt1[7] = to_remote_g2[j].from_mod;
									memcpy(fromrptr_torptr_brd.hdr.rpt2, owner.c_str(), CALL_SIZE);
									fromrptr_torptr_brd.hdr.rpt2[7] = 'G';

									memcpy(fromrptr_torptr_brd.hdr.urcall, "CQCQCQ  ", CALL_SIZE);

									calcPFCS(fromrptr_torptr_brd.title, 56);

									Link2Gate.Write(fromrptr_torptr_brd.title, 56);

									brd_from_rptr.from_rptr_streamid = dstr.vpkt.streamid;
									brd_from_rptr.to_rptr_streamid[brd_from_rptr_idx] = fromrptr_torptr_brd.streamid;
									brd_from_rptr_idx ++;
								}
							}
						}

						if (to_remote_g2[i].is_connected) {
							if (0==memcmp(dstr.vpkt.hdr.r2, owner.c_str(), 7) && 0==memcmp(dstr.vpkt.hdr.ur, "CQCQCQ", 6) && dstr.vpkt.hdr.r2[7] == 'G') {
								to_remote_g2[i].out_streamid = dstr.vpkt.streamid;

								if (to_remote_g2[i].toDst4.sin_port==htons(rmt_xrf_port) || to_remote_g2[i].toDst4.sin_port== htons(rmt_ref_port)) {
									SREFDSVT rdsvt;
									rdsvt.head[0] = (unsigned char)(58 & 0xFF);
									rdsvt.head[1] = (unsigned char)(58 >> 8 & 0x1F);
									rdsvt.head[1] = (unsigned char)(rdsvt.head[1] | 0xFFFFFF80);

									memcpy(rdsvt.dsvt.title, "DSVT", 4);
									rdsvt.dsvt.config = 0x10;
									rdsvt.dsvt.flaga[0] = rdsvt.dsvt.flaga[1] = rdsvt.dsvt.flaga[2] = 0x0;
									rdsvt.dsvt.id = dstr.vpkt.icm_id;
									rdsvt.dsvt.flagb[0] = dstr.vpkt.dst_rptr_id;
									rdsvt.dsvt.flagb[1] = dstr.vpkt.snd_rptr_id;
									rdsvt.dsvt.flagb[2] = dstr.vpkt.snd_term_id;
									memcpy(&rdsvt.dsvt.streamid, &dstr.vpkt.streamid, 44);
									memset(rdsvt.dsvt.hdr.rpt1, ' ', CALL_SIZE);
									memcpy(rdsvt.dsvt.hdr.rpt1, to_remote_g2[i].to_call, strlen(to_remote_g2[i].to_call));
									rdsvt.dsvt.hdr.rpt1[7] = to_remote_g2[i].to_mod;
									memset(rdsvt.dsvt.hdr.rpt2, ' ', CALL_SIZE);
									memcpy(rdsvt.dsvt.hdr.rpt2, to_remote_g2[i].to_call, strlen(to_remote_g2[i].to_call));
									rdsvt.dsvt.hdr.rpt2[7] = 'G';
									memcpy(rdsvt.dsvt.hdr.urcall, "CQCQCQ  ", CALL_SIZE);
									calcPFCS(rdsvt.dsvt.title, 56);

									if (to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port)) {
										/* inform XRF about the source */
										rdsvt.dsvt.flagb[2] = to_remote_g2[i].from_mod;
										calcPFCS(rdsvt.dsvt.title, 56);
										for (int j=0; j<5; j++)
											sendto(xrf_g2_sock, rdsvt.dsvt.title, 56, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));
									} else {
										for (int j=0; j<5; j++)
											sendto(ref_g2_sock, rdsvt.head, 58, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));
									}
								} else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_dcs_port)) {
									memcpy(rptr_2_dcs[i].mycall, dstr.vpkt.hdr.my, CALL_SIZE);
									memcpy(rptr_2_dcs[i].sfx, dstr.vpkt.hdr.nm, 4);
									rptr_2_dcs[i].dcs_rptr_seq = 0;
								}
							}
						}
					}
				}
				else { // length is 29 or 32
					if (inbound_list.size() > 0) {
						SREFDSVT rdsvt;
						rdsvt.head[0] = (unsigned char)(29 & 0xFF);
						rdsvt.head[1] = (unsigned char)(29 >> 8 & 0x1F);
						rdsvt.head[1] = (unsigned char)(rdsvt.head[1] | 0xFFFFFF80);

						memcpy(rdsvt.dsvt.title, "DSVT", 4);
						rdsvt.dsvt.config = 0x20;
						rdsvt.dsvt.flaga[0] = rdsvt.dsvt.flaga[1] = rdsvt.dsvt.flaga[2] = 0x0;
						rdsvt.dsvt.id = dstr.vpkt.icm_id;
						rdsvt.dsvt.flagb[0] = dstr.vpkt.dst_rptr_id;
						rdsvt.dsvt.flagb[1] = dstr.vpkt.snd_rptr_id;
						rdsvt.dsvt.flagb[2] = dstr.vpkt.snd_term_id;
						memcpy(&rdsvt.dsvt.streamid, &dstr.vpkt.streamid, 3);
						if (length == 29)
							memcpy(rdsvt.dsvt.vasd.voice, dstr.vpkt.vasd.voice, 12);
						else
							memcpy(rdsvt.dsvt.vasd.voice, dstr.vpkt.vasd1.voice, 12);

						for (auto pos = inbound_list.begin(); pos != inbound_list.end(); pos++) {
							SINBOUND *inbound = (SINBOUND *)pos->second;
							sendto(ref_g2_sock, rdsvt.head, 29, 0, (struct sockaddr *)&(inbound->sin), sizeof(struct sockaddr_in));
						}
					}

					for (int i=0; i<3; i++) {
						if (to_remote_g2[i].is_connected && to_remote_g2[i].out_streamid==dstr.vpkt.streamid) {
							/* check for broadcast */
							if (brd_from_rptr.from_rptr_streamid == dstr.vpkt.streamid) {
								memcpy(fromrptr_torptr_brd.title, "DSVT", 4);
								fromrptr_torptr_brd.config = 0x10;
								fromrptr_torptr_brd.flaga[0] = fromrptr_torptr_brd.flaga[1] = fromrptr_torptr_brd.flaga[2] = 0x0;
								fromrptr_torptr_brd.id = dstr.vpkt.icm_id;
								fromrptr_torptr_brd.flagb[0] = dstr.vpkt.dst_rptr_id;
								fromrptr_torptr_brd.flagb[1] = dstr.vpkt.snd_rptr_id;
								fromrptr_torptr_brd.flagb[2] = dstr.vpkt.snd_term_id;
								memcpy(&fromrptr_torptr_brd.streamid, &dstr.vpkt.streamid, 3);

								if (length == 29)
									memcpy(fromrptr_torptr_brd.vasd.voice, dstr.vpkt.vasd.voice, 12);
								else
									memcpy(fromrptr_torptr_brd.vasd.voice, dstr.vpkt.vasd1.voice, 12);

								if (brd_from_rptr.to_rptr_streamid[0]) {
									fromrptr_torptr_brd.streamid = brd_from_rptr.to_rptr_streamid[0];
									Link2Gate.Write(fromrptr_torptr_brd.title, 27);
								}

								if (brd_from_rptr.to_rptr_streamid[1]) {
									fromrptr_torptr_brd.streamid = brd_from_rptr.to_rptr_streamid[1];
									Link2Gate.Write(fromrptr_torptr_brd.title, 27);
								}

								if (dstr.vpkt.ctrl & 0x40U) {
									brd_from_rptr.from_rptr_streamid = brd_from_rptr.to_rptr_streamid[0] = brd_from_rptr.to_rptr_streamid[1] = 0x0;
									brd_from_rptr_idx = 0;
								}
							}

							if (to_remote_g2[i].toDst4.sin_port==htons(rmt_xrf_port) || to_remote_g2[i].toDst4.sin_port== htons(rmt_ref_port)) {
								SREFDSVT rdsvt;
								rdsvt.head[0] = (unsigned char)(29 & 0xFF);
								rdsvt.head[1] = (unsigned char)(29 >> 8 & 0x1F);
								rdsvt.head[1] = (unsigned char)(rdsvt.head[1] | 0xFFFFFF80);

								memcpy(rdsvt.dsvt.title, "DSVT", 4);
								rdsvt.dsvt.config = 0x20;
								rdsvt.dsvt.flaga[0] = rdsvt.dsvt.flaga[1] = rdsvt.dsvt.flaga[2] = 0x00;
								rdsvt.dsvt.id =  dstr.vpkt.icm_id;
								rdsvt.dsvt.flagb[0] = dstr.vpkt.dst_rptr_id;
								rdsvt.dsvt.flagb[1] = dstr.vpkt.snd_rptr_id;
								rdsvt.dsvt.flagb[2] = dstr.vpkt.snd_term_id;
								memcpy(&rdsvt.dsvt.streamid, &dstr.vpkt.streamid, 3);
								if (length == 29)
									memcpy(rdsvt.dsvt.vasd.voice, dstr.vpkt.vasd.voice, 12);
								else
									memcpy(rdsvt.dsvt.vasd.voice, dstr.vpkt.vasd1.voice, 12);

								if (to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port)) {
									/* inform XRF about the source */
									rdsvt.dsvt.flagb[2] = to_remote_g2[i].from_mod;

									sendto(xrf_g2_sock, rdsvt.dsvt.title, 27, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));
								} else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_ref_port))
									sendto(ref_g2_sock, rdsvt.head, 29, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));
							} else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_dcs_port)) {
								memset(dcs_buf, 0x0, 600);
								dcs_buf[0] = dcs_buf[1] = dcs_buf[2] = '0';
								dcs_buf[3] = '1';
								dcs_buf[4] = dcs_buf[5] = dcs_buf[6] = 0x0;
								memcpy(dcs_buf + 7, to_remote_g2[i].to_call, 8);
								dcs_buf[14] = to_remote_g2[i].to_mod;
								memcpy(dcs_buf + 15, owner.c_str(), CALL_SIZE);
								dcs_buf[22] = to_remote_g2[i].from_mod;
								memcpy(dcs_buf + 23, "CQCQCQ  ", 8);
								memcpy(dcs_buf + 31, rptr_2_dcs[i].mycall, 8);
								memcpy(dcs_buf + 39, rptr_2_dcs[i].sfx, 4);
								memcpy(dcs_buf + 43, &dstr.vpkt.streamid, 2);
								dcs_buf[45] = dstr.vpkt.ctrl;  /* cycle sequence */
								memcpy(dcs_buf + 46, dstr.vpkt.vasd.voice, 12);

								dcs_buf[58] = (rptr_2_dcs[i].dcs_rptr_seq >> 0)  & 0xff;
								dcs_buf[59] = (rptr_2_dcs[i].dcs_rptr_seq >> 8)  & 0xff;
								dcs_buf[60] = (rptr_2_dcs[i].dcs_rptr_seq >> 16) & 0xff;

								rptr_2_dcs[i].dcs_rptr_seq++;

								dcs_buf[61] = 0x01;
								dcs_buf[62] = 0x00;

								sendto(dcs_g2_sock, dcs_buf, 100, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));
							}

							if (dstr.vpkt.ctrl & 0x40U) {
								to_remote_g2[i].out_streamid = 0x0;
							}
							break;
						}
					}

					for (int i=0; i<3; i++) {
						if (tracing[i].streamid == dstr.vpkt.streamid) {
							/* update the last time RF user talked */
							tracing[i].last_time = time(NULL);

							if (dstr.vpkt.ctrl & 0x40U) {
								if (qso_details)
									printf("END from local g2: cntr=%04x, streamID=%04x, %d bytes\n", ntohs(dstr.counter), ntohs(dstr.vpkt.streamid), length);

								if ('\0' == notify_msg[i][0]) {
									if (bool_rptr_ack)
										rptr_ack(i);
								}

								memset(dtmf_mycall[i], 0, sizeof(dtmf_mycall[i]));
								new_group[i] = true;
								GPS_seen[i] = false;

								tracing[i].streamid = 0x0;
							} else {
								if (!GPS_seen[i]) {
									if (length == 29)
										memcpy(tmp_txt, dstr.vpkt.vasd.text, 3);
									else
										memcpy(tmp_txt, dstr.vpkt.vasd1.text, 3);

									if (tmp_txt[0]!=0x55 || tmp_txt[1]!=0x2d || tmp_txt[2]!=0x16) {
										if (new_group[i]) {
											tmp_txt[0] = tmp_txt[0] ^ 0x70;
											header_type = tmp_txt[0] & 0xf0;
														 // header				squelch
											if (header_type== 0x50 || header_type==0xc0)
												new_group[i] = false;
											else if (header_type == 0x30) { /* GPS or GPS id or APRS */
												GPS_seen[i] = true;
												new_group[i] = false;

												memcpy(tmp1, dtmf_mycall[i], 8);
												tmp1[8] = '\0';

												// delete the user if exists and it is a local RF entry
												p_tmp2 = NULL;
												for (auto dt_lh_pos = dt_lh_list.begin(); dt_lh_pos != dt_lh_list.end();  dt_lh_pos++) {
													if (strcmp((char *)dt_lh_pos->second.c_str(), tmp1) == 0) {
														strcpy(tmp2, (char *)dt_lh_pos->first.c_str());
														p_tmp2 = strstr(tmp2, "=l");
														if (p_tmp2) {
															dt_lh_list.erase(dt_lh_pos);
															break;
														}
													}
												}
												/* we have tmp1 and tmp2, we have the user and it is already been removed */
												/* add the user with gps indicator g */
												if (p_tmp2) {
													*(p_tmp2 + 1) = 'g';
													dt_lh_list[tmp2] = tmp1;
												}
											} else if (header_type == 0x40) /* ABC text */
												new_group[i] = false;
											else
												new_group[i] = false;
										} else
											new_group[i] = true;
									}
								}
							}
							break;
						}
					}
				}
			}
			FD_CLR (Gate2Link.GetFD(), &fdset);
		}
		for (int i=0; i<3; i++) {
			if (keep_running && notify_msg[i][0] && 0x0U == tracing[i].streamid) {
				PlayAudioNotifyThread(notify_msg[i]);
				notify_msg[i][0] = '\0';
			}
		}
	}
}

void CQnetLink::PlayAudioNotifyThread(char *msg)
{
	if (! announce)
		return;

	if (msg[0]<'A' || msg[0]>'C') {
		fprintf(stderr, "Improper module in msg '%s'\n", msg);
		return;
	}

	SECHO edata;

	edata.is_linked = (NULL == strstr(msg, "_linked.dat_LINKED_")) ? false : true;
	char *p = strstr(msg, ".dat");
	if (NULL == p) {
		fprintf(stderr, "Improper AMBE data file in msg '%s'\n", msg);
		return;
	}
	if ('_' == p[4]) {
		std::string message(p+5);
		message.resize(20, ' ');
		strcpy(edata.message, message.c_str());
		for (int i=0; i<20; i++) {
			if ('_' == edata.message[i])
				edata.message[i] = ' ';
		}
	} else {
		strcpy(edata.message, "QnetGateway Message ");
	}
	p[4] = '\0';
	snprintf(edata.file, FILENAME_MAX, "%s/%s", announce_dir.c_str(), msg+2);

	memcpy(edata.header.title, "DSVT", 4);
	edata.header.config = 0x10U;
	edata.header.flaga[0] = edata.header.flaga[1] = edata.header.flaga[2] = 0x0U;
	edata.header.id = 0x20;
	edata.header.streamid = Random.NewStreamID();
	edata.header.ctrl = 0x80U;
	edata.header.hdr.flag[0] = edata.header.hdr.flag[1] = edata.header.hdr.flag[2] = 0x0U;
	memcpy(edata.header.hdr.rpt1, owner.c_str(), CALL_SIZE);
	edata.header.hdr.rpt1[7] = msg[0];
	memcpy(edata.header.hdr.rpt2, owner.c_str(), CALL_SIZE);
	edata.header.hdr.rpt2[7] = 'G';
	memcpy(edata.header.hdr.urcall, "CQCQCQ  ", CALL_SIZE);
	memcpy(edata.header.hdr.mycall, owner.c_str(), CALL_SIZE);
	memcpy(edata.header.hdr.sfx, "RPTR", 4);
	calcPFCS(edata.header.title, 56);

	try {
		std::async(std::launch::async, &CQnetLink::AudioNotifyThread, this, std::ref(edata));
	} catch (const std::exception &e) {
		printf ("Failed to start AudioNotifyThread(). Exception: %s\n", e.what());
	}
	return;
}

void CQnetLink::AudioNotifyThread(SECHO &edata)
{
	struct sigaction act;
	act.sa_handler = sigCatch;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	if (sigaction(SIGTERM, &act, 0) != 0) {
		fprintf(stderr, "sigaction-TERM failed, error=%d\n", errno);
		return;
	}
	if (sigaction(SIGINT, &act, 0) != 0) {
		fprintf(stderr, "sigaction-INT failed, error=%d\n", errno);
		return;
	}

	char mod = edata.header.hdr.rpt1[7];

	if ((mod != 'A') && (mod != 'B') && (mod != 'C')) {
		fprintf(stderr, "Invalid module %c in %s\n", mod, edata.file);
		return;
	}

	sleep(delay_before);

	printf("sending File:[%s], mod:[%c], RADIO_ID=[%s]\n", edata.file, mod, edata.message);

	struct stat sbuf;
	if (stat(edata.file, &sbuf)) {
		fprintf(stderr, "can't stat %s\n", edata.file);
		return;
	}

	if (sbuf.st_size % 9)
		printf("Warning %s file size is %ld (not a multiple of 9)!\n", edata.file, sbuf.st_size);
	int ambeblocks = (int)sbuf.st_size / 9;


	FILE *fp = fopen(edata.file, "rb");
	if (!fp) {
		fprintf(stderr, "Failed to open file %s for reading\n", edata.file);
		return;
	}

	Link2Gate.Write(edata.header.title, 56);

	edata.header.config = 0x20U;

	int count;
	const unsigned char sdsync[3] = { 0x55U, 0x2DU, 0x16U };
	const unsigned char sdsilence[3] = { 0x16U, 0x29U, 0xF5U };
	for (count=0; count<ambeblocks && keep_running; count++) {
		int nread = fread(edata.header.vasd.voice, 9, 1, fp);
		if (nread == 1) {
			edata.header.ctrl = (unsigned char)(count % 21);
			if (0x0U == edata.header.ctrl) {
				memcpy(edata.header.vasd.text, sdsync, 3);
			} else {
				switch (count) {
					case 1:
						edata.header.vasd.text[0] = '@' ^ 0x70;
						edata.header.vasd.text[1] = edata.message[0] ^ 0x4f;
						edata.header.vasd.text[2] = edata.message[1] ^ 0x93;
						break;
					case 2:
						edata.header.vasd.text[0] = edata.message[2] ^ 0x70;
						edata.header.vasd.text[1] = edata.message[3] ^ 0x4f;
						edata.header.vasd.text[2] = edata.message[4] ^ 0x93;
						break;
					case 3:
						edata.header.vasd.text[0] = 'A' ^ 0x70;
						edata.header.vasd.text[1] = edata.message[5] ^ 0x4f;
						edata.header.vasd.text[2] = edata.message[6] ^ 0x93;
						break;
					case 4:
						edata.header.vasd.text[0] = edata.message[7] ^ 0x70;
						edata.header.vasd.text[1] = edata.message[8] ^ 0x4f;
						edata.header.vasd.text[2] = edata.message[9] ^ 0x93;
						break;
					case 5:
						edata.header.vasd.text[0] = 'B' ^ 0x70;
						edata.header.vasd.text[1] = edata.message[10] ^ 0x4f;
						edata.header.vasd.text[2] = edata.message[11] ^ 0x93;
						break;
					case 6:
						edata.header.vasd.text[0] = edata.message[12] ^ 0x70;
						edata.header.vasd.text[1] = edata.message[13] ^ 0x4f;
						edata.header.vasd.text[2] = edata.message[14] ^ 0x93;
						break;
					case 7:
						edata.header.vasd.text[0] = 'C' ^ 0x70;
						edata.header.vasd.text[1] = edata.message[15] ^ 0x4f;
						edata.header.vasd.text[2] = edata.message[16] ^ 0x93;
						break;
					case 8:
						edata.header.vasd.text[0] = edata.message[17] ^ 0x70;
						edata.header.vasd.text[1] = edata.message[18] ^ 0x4f;
						edata.header.vasd.text[2] = edata.message[19] ^ 0x93;
						break;
					default:
						memcpy(edata.header.vasd.text, sdsilence, 3);
						break;
				}
			}
			if (count+1 == ambeblocks && ! edata.is_linked)
				edata.header.ctrl |= 0x40U;
			Link2Gate.Write(edata.header.title, 27);
			std::this_thread::sleep_for(std::chrono::milliseconds(delay_between));
		}
	}
	fclose(fp);

	if (! edata.is_linked)
		return;

	// open the speak file
	std::string speakfile(announce_dir);
	speakfile.append("/speak.dat");
	fp = fopen(speakfile.c_str(), "rb");
	if (NULL == fp)
		return;

	// create the speak sentence
	std::string say("2");
	say.append(edata.message + 7);
	auto rit = say.rbegin();
	while (isspace(*rit)) {
		say.resize(say.size()-1);
		rit = say.rbegin();
	}

	// play it
	for (auto it=say.begin(); it!=say.end(); it++) {
		bool lastch = (it+1 == say.end());
		unsigned long offset = 0;
		int size = 0;
		if ('A' <= *it && *it <= 'Z')
			offset = speak[*it - 'A' + (lastch ? 26 : 0)];
		else if ('1' <= *it && *it <= '9')
			offset = speak[*it - '1' + 52];
		else if ('0' == *it)
			offset = speak[61];
		if (offset) {
			size = (int)(offset % 1000UL);
			offset = (offset / 1000UL) * 9UL;
		}
		if (0 == size)
			continue;
		if (fseek(fp, offset, SEEK_SET)) {
			fprintf(stderr, "fseek to %ld error!\n", offset);
			return;
		}
		for (int i=0; i<size; i++) {
			edata.header.ctrl = count++ % 21;
			int nread = fread(edata.header.vasd.voice, 9, 1, fp);
			if (nread == 1) {
				memcpy(edata.header.vasd.text, edata.header.ctrl ? sdsilence : sdsync, 3);
				if (i+1==size && lastch)
					edata.header.ctrl |= 0x40U;	// signal the last voiceframe (of the last character)
				Link2Gate.Write(edata.header.title, 27);
				std::this_thread::sleep_for(std::chrono::milliseconds(delay_between));
			}
		}
	}
	fclose(fp);
	return;
}

bool CQnetLink::Init(const char *cfgfile)
{
	struct sigaction act;

	tzset();
	setvbuf(stdout, (char *)NULL, _IOLBF, 0);


	int rc = regcomp(&preg, "^(([1-9][A-Z])|([A-Z][0-9])|([A-Z][A-Z][0-9]))[0-9A-Z]*[A-Z][ ]*[ A-RT-Z]$", REG_EXTENDED | REG_NOSUB);
	if (rc != 0) {
		printf("The IRC regular expression is NOT valid\n");
		return true;
	}

	act.sa_handler = sigCatch;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	if (sigaction(SIGTERM, &act, 0) != 0) {
		printf("sigaction-TERM failed, error=%d\n", errno);
		return true;
	}
	if (sigaction(SIGINT, &act, 0) != 0) {
		printf("sigaction-INT failed, error=%d\n", errno);
		return true;
	}

	for (int i=0; i<3; i++) {
		notify_msg[i][0] = '\0';
		to_remote_g2[i].to_call[0] = '\0';
		memset(&(to_remote_g2[i].toDst4),0,sizeof(struct sockaddr_in));
		to_remote_g2[i].to_mod = to_remote_g2[i].from_mod = ' ';
		to_remote_g2[i].countdown = 0;
		to_remote_g2[i].is_connected = false;
		to_remote_g2[i].in_streamid = to_remote_g2[i].out_streamid = 0x0;
	}

	brd_from_xrf.xrf_streamid = brd_from_xrf.rptr_streamid[0] = brd_from_xrf.rptr_streamid[1] = 0x0;
	brd_from_xrf_idx = 0;

	brd_from_rptr.from_rptr_streamid = brd_from_rptr.to_rptr_streamid[0] = brd_from_rptr.to_rptr_streamid[1] = 0x0;
	brd_from_rptr_idx = 0;

	/* process configuration file */
	if (read_config(cfgfile)) {
		printf("Failed to process config file %s\n", cfgfile);
		return true;
	}
	print_status_file();

	/* Open DB */
	if (!load_gwys(gwys))
		return true;

	/* create our server */
	if (!srv_open()) {
		printf("srv_open() failed\n");
		return true;
	}

	std::string index(announce_dir);
	index.append("/index.dat");
	std::ifstream indexfile(index.c_str(), std::ifstream::in);
	if (indexfile) {
		for (int i=0; i<62; i++) {
			std::string name, offset, size;
			indexfile >> name >> offset >> size;
			if (name.size() && offset.size() && size.size()) {
				unsigned long of = std::stoul(offset);
				unsigned long sz = std::stoul(size);
				speak.push_back(1000U * of + sz);
			}
		}
		indexfile.close();
	}
	if (62 == speak.size()) {
		printf("read %d indicies from %s\n", (unsigned int)speak.size(), index.c_str());
	} else {
		fprintf(stderr, "read unexpected (%d) number of indices from %s\n", (unsigned int)speak.size(), index.c_str());
		speak.clear();
	}
	return false;
}

void CQnetLink::Shutdown()
{
	char unlink_request[CALL_SIZE + 3];
	char cmd_2_dcs[19];

	/* Clear connections */
	queryCommand[0] = 5;
	queryCommand[1] = 0;
	queryCommand[2] = 24;
	queryCommand[3] = 0;
	queryCommand[4] = 0;
	for (int i=0; i<3; i++) {
		if (to_remote_g2[i].to_call[0] != '\0') {
			if (to_remote_g2[i].toDst4.sin_port == htons(rmt_ref_port))
				sendto(ref_g2_sock, queryCommand, 5, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));
			else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port)) {
				strcpy(unlink_request, owner.c_str());
				unlink_request[8] = to_remote_g2[i].from_mod;
				unlink_request[9] = ' ';
				unlink_request[10] = '\0';
				for (int j=0; j<5; j++)
					sendto(xrf_g2_sock, unlink_request, CALL_SIZE+3, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));
			} else {
				strcpy(cmd_2_dcs, owner.c_str());
				cmd_2_dcs[8] = to_remote_g2[i].from_mod;
				cmd_2_dcs[9] = ' ';
				cmd_2_dcs[10] = '\0';
				memcpy(cmd_2_dcs + 11, to_remote_g2[i].to_call, 8);

				for (int j=0; j<5; j++)
					sendto(dcs_g2_sock, cmd_2_dcs, 19, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));
			}
		}
		to_remote_g2[i].to_call[0] = '\0';
		memset(&(to_remote_g2[i].toDst4),0,sizeof(struct sockaddr_in));
		to_remote_g2[i].from_mod = to_remote_g2[i].to_mod = ' ';
		to_remote_g2[i].countdown = 0;
		to_remote_g2[i].is_connected = false;
		to_remote_g2[i].in_streamid = to_remote_g2[i].out_streamid = 0x0;
	}

	/* tell inbound dongles we are down */
	for (auto pos = inbound_list.begin(); pos != inbound_list.end(); pos++) {
		SINBOUND *inbound = (SINBOUND *)pos->second;
		sendto(ref_g2_sock, queryCommand, 5, 0, (struct sockaddr *)&(inbound->sin), sizeof(struct sockaddr_in));
	}
	inbound_list.clear();

	print_status_file();
	srv_close();

	return;
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		printf("Usage: ./g2_link g2_link.cfg\n");
		return 1;
	}
	CQnetLink qnlink;
	if (qnlink.Init(argv[1]))
		return 1;
	printf("g2_link %s initialized...entering processing loop\n", VERSION);
	qnlink.Process();
	printf("g2_link exiting\n");
	qnlink.Shutdown();
}
