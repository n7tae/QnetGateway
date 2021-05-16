
/*
 *   Copyright (C) 2010 by Scott Lawson KI4LKF
 *   Copyright (C) 2015,2008-2020 by Thomas A. Early N7TAE
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
#include <errno.h>
#include <regex.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>
#include <netdb.h>

#include <iostream>
#include <sstream>
#include <fstream>
#include <future>
#include <exception>
#include <utility>
#include <thread>
#include <chrono>
#include <csignal>

#include "DPlusAuthenticator.h"
#include "QnetConfigure.h"
#include "QnetLink.h"
#include "Utilities.h"

#define LINK_VERSION "QnetLink-607"
#ifndef BIN_DIR
#define BIN_DIR "/usr/local/bin"
#endif
#ifndef CFG_DIR
#define CFG_DIR "/usr/local/etc"
#endif

CQnetLink::CQnetLink()
{
}

CQnetLink::~CQnetLink()
{
	speak.clear();
}

void CQnetLink::REFWrite(const void *buf, const size_t size, const CSockAddress &addr)
{
	if (AF_INET == addr.GetFamily())
		REFSock4.Write(buf, size, addr);
	else if (uses_ipv6)
		REFSock6.Write(buf, size, addr);
}

void CQnetLink::DCSWrite(const void *buf, const size_t size, const CSockAddress &addr)
{
	if (AF_INET == addr.GetFamily())
		DCSSock4.Write(buf, size, addr);
	else if (uses_ipv6)
		DCSSock6.Write(buf, size, addr);
}

void CQnetLink::XRFWrite(const void *buf, const size_t size, const CSockAddress &addr)
{
	if (AF_INET == addr.GetFamily())
		XRFSock4.Write(buf, size, addr);
	else if (uses_ipv6)
		XRFSock6.Write(buf, size, addr);
}

bool CQnetLink::resolve_rmt(const char *name, const unsigned short port, CSockAddress &addr)
{
	struct addrinfo hints;
	struct addrinfo *res;
	struct addrinfo *rp;
	bool found = false;

	memset(&hints, 0x00, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	int rc = getaddrinfo(name, NULL, &hints, &res);
	if (rc != 0)
	{
		printf("getaddrinfo return error code %d for [%s]\n", rc, name);
		return false;
	}

	for (rp=res; rp!=NULL; rp=rp->ai_next)
	{
		if ((AF_INET==rp->ai_family || AF_INET6==rp->ai_family) && SOCK_DGRAM==rp->ai_socktype)
		{
			if (AF_INET == rp->ai_family)
			{
				char saddr[INET_ADDRSTRLEN];
				struct sockaddr_in *addr4 = (struct sockaddr_in *)rp->ai_addr;
				if (inet_ntop(rp->ai_family, &(addr4->sin_addr), saddr, INET_ADDRSTRLEN))
				{
					addr.Initialize(rp->ai_family, port, saddr);
					found = true;
					break;
				}
			}
			else if (AF_INET6 == rp->ai_family)
			{
				char saddr[INET6_ADDRSTRLEN];
				struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)rp->ai_addr;
				if (inet_ntop(rp->ai_family, &(addr6->sin6_addr), saddr, INET6_ADDRSTRLEN))
				{
					addr.Initialize(rp->ai_family, port, saddr);
					found = true;
					break;
				}
			}
		}
	}
	freeaddrinfo(res);

	if (found && strcmp(name, addr.GetAddress()))
	{
		printf("Node address %s on port %u resolved to %s\n", name, port, addr.GetAddress());
	}

	return found;
}

/* send keepalive to donglers */
void CQnetLink::send_heartbeat()
{
	// heartbeats for connected donglers
	for (auto pos = inbound_list.begin(); pos != inbound_list.end(); pos++)
	{
		SINBOUND *inbound = (SINBOUND *)pos->second;
		REFWrite(REF_ACK, 3, inbound->addr);

		if (inbound->countdown >= 0)
			inbound->countdown--;

		if (inbound->countdown < 0)
		{
			printf("call=%s timeout, removing %s, users=%d\n", inbound->call, pos->first.c_str(), (int)inbound_list.size() - 1);
			qnDB.DeleteLS(pos->first.c_str());
			delete pos->second;
			inbound_list.erase(pos);
		}
	}

	/* send heartbeat to linked XRF repeaters/reflectors */
	char cmd_2_dcs[23];
	if (to_remote_g2[0].addr.GetPort() == rmt_xrf_port)
		XRFWrite(owner.c_str(), CALL_SIZE+1, to_remote_g2[0].addr);

	if ((to_remote_g2[1].addr.GetPort() == rmt_xrf_port) && (strcmp(to_remote_g2[1].cs, to_remote_g2[0].cs) != 0))
		XRFWrite(owner.c_str(), CALL_SIZE+1, to_remote_g2[1].addr);

	if ((to_remote_g2[2].addr.GetPort() == rmt_xrf_port) && (strcmp(to_remote_g2[2].cs, to_remote_g2[0].cs) != 0) && (strcmp(to_remote_g2[2].cs, to_remote_g2[1].cs) != 0))
		XRFWrite(owner.c_str(), CALL_SIZE+1, to_remote_g2[2].addr);

	/* send heartbeat to linked DCS reflectors */
	if (to_remote_g2[0].addr.GetPort() == rmt_dcs_port)
	{
		strcpy(cmd_2_dcs, owner.c_str());
		cmd_2_dcs[7] = to_remote_g2[0].from_mod;
		memcpy(cmd_2_dcs + 9, to_remote_g2[0].cs, 8);
		cmd_2_dcs[16] = to_remote_g2[0].to_mod;
		DCSWrite(cmd_2_dcs, 17, to_remote_g2[0].addr);
	}
	if (to_remote_g2[1].addr.GetPort() == rmt_dcs_port)
	{
		strcpy(cmd_2_dcs, owner.c_str());
		cmd_2_dcs[7] = to_remote_g2[1].from_mod;
		memcpy(cmd_2_dcs + 9, to_remote_g2[1].cs, 8);
		cmd_2_dcs[16] = to_remote_g2[1].to_mod;
		DCSWrite(cmd_2_dcs, 17, to_remote_g2[1].addr);
	}
	if (to_remote_g2[2].addr.GetPort() == rmt_dcs_port)
	{
		strcpy(cmd_2_dcs, owner.c_str());
		cmd_2_dcs[7] = to_remote_g2[2].from_mod;
		memcpy(cmd_2_dcs + 9, to_remote_g2[2].cs, 8);
		cmd_2_dcs[16] = to_remote_g2[2].to_mod;
		DCSWrite(cmd_2_dcs, 17, to_remote_g2[2].addr);
	}

	/* send heartbeat to linked REF reflectors */
	if (to_remote_g2[0].is_connected && to_remote_g2[0].addr.GetPort()==rmt_ref_port)
		REFWrite(REF_ACK, 3, to_remote_g2[0].addr);

	if (to_remote_g2[1].is_connected && to_remote_g2[1].addr.GetPort()==rmt_ref_port && strcmp(to_remote_g2[1].cs, to_remote_g2[0].cs))
		REFWrite(REF_ACK, 3, to_remote_g2[1].addr);

	if (to_remote_g2[2].is_connected && to_remote_g2[2].addr.GetPort()==rmt_ref_port && strcmp(to_remote_g2[2].cs, to_remote_g2[0].cs) && strcmp(to_remote_g2[2].cs, to_remote_g2[1].cs))
		REFWrite(REF_ACK, 3, to_remote_g2[2].addr);

	for (int i=0; i<3; i++)
	{
		/* check for timeouts from remote */
		if (to_remote_g2[i].cs[0] != '\0')
		{
			if (to_remote_g2[i].countdown >= 0)
				to_remote_g2[i].countdown--;

			if (to_remote_g2[i].countdown < 0)
			{
				/* maybe remote system has changed IP */
				printf("Unlinked from [%s] mod %c, TIMEOUT...\n", to_remote_g2[i].cs, to_remote_g2[i].to_mod);

				sprintf(notify_msg[i], "%c_unlinked.dat_LINK_TIMEOUT", to_remote_g2[i].from_mod);
				qnDB.DeleteLS(to_remote_g2[i].addr.GetAddress());
				if (to_remote_g2[i].auto_link)
				{
					char cs[CALL_SIZE+1];
					memcpy(cs, to_remote_g2[i].cs, CALL_SIZE+1);	// call is passed by pointer so we have to copy it
					g2link(to_remote_g2[i].from_mod, cs, to_remote_g2[i].to_mod);
				}
				else
				{
					to_remote_g2[i].cs[0] = '\0';
					to_remote_g2[i].from_mod = to_remote_g2[i].to_mod = ' ';
					to_remote_g2[i].addr.Clear();
					to_remote_g2[i].countdown = 0;
					to_remote_g2[i].is_connected = false;
					to_remote_g2[i].in_streamid = 0x0;
				}
			}
		}

		/*** check for RF inactivity ***/
		if (to_remote_g2[i].is_connected)
		{
			if (((tnow - tracing[i].last_time) > rf_inactivity_timer[i]) && (rf_inactivity_timer[i] > 0))
			{
				tracing[i].last_time = 0;

				printf("Unlinked from [%s] mod %c, local RF inactivity...\n", to_remote_g2[i].cs, to_remote_g2[i].to_mod);

				if (to_remote_g2[i].addr.GetPort() == rmt_ref_port)
				{
					queryCommand[0] = 5;
					queryCommand[1] = 0;
					queryCommand[2] = 24;
					queryCommand[3] = 0;
					queryCommand[4] = 0;
					REFWrite(queryCommand, 5, to_remote_g2[i].addr);

					/* zero out any other entries here that match that system */
					for (int j=0; j<3; j++)
					{
						if (j != i)
						{
							if (to_remote_g2[j].addr == to_remote_g2[i].addr)
							{
								to_remote_g2[j].cs[0] = '\0';
								to_remote_g2[j].addr.Clear();
								to_remote_g2[j].from_mod = ' ';
								to_remote_g2[j].to_mod = ' ';
								to_remote_g2[j].countdown = 0;
								to_remote_g2[j].is_connected = false;
								to_remote_g2[j].in_streamid = 0x0;
							}
						}
					}
				}
				else if (to_remote_g2[i].addr.GetPort() == rmt_xrf_port)
				{
					char unlink_request[CALL_SIZE + 3];
					strcpy(unlink_request, owner.c_str());
					unlink_request[8] = to_remote_g2[i].from_mod;
					unlink_request[9] = ' ';
					unlink_request[10] = '\0';

					for (int j=0; j<5; j++)
						XRFWrite(unlink_request, CALL_SIZE+3, to_remote_g2[i].addr);
				}
				else if (to_remote_g2[i].addr.GetPort() == rmt_dcs_port)
				{
					strcpy(cmd_2_dcs, owner.c_str());
					cmd_2_dcs[8] = to_remote_g2[i].from_mod;
					cmd_2_dcs[9] = ' ';
					cmd_2_dcs[10] = '\0';
					memcpy(cmd_2_dcs + 11, to_remote_g2[i].cs, 8);

					for (int j=0; j<2; j++)
						DCSWrite(cmd_2_dcs, 19, to_remote_g2[i].addr);
				}
				qnDB.DeleteLS(to_remote_g2[i].addr.GetAddress());
				sprintf(notify_msg[i], "%c_unlinked.dat_UNLINKED_TIMEOUT", to_remote_g2[i].from_mod);

				to_remote_g2[i].cs[0] = '\0';
				to_remote_g2[i].addr.Clear();
				to_remote_g2[i].from_mod = to_remote_g2[i].to_mod = ' ';
				to_remote_g2[i].countdown = 0;
				to_remote_g2[i].is_connected = false;
				to_remote_g2[i].in_streamid = 0x0;
			}
		}
	}
}

void CQnetLink::rptr_ack(int i)
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

	if (to_remote_g2[i].is_connected)
	{
		memcpy(mod_and_RADIO_ID[i] + 1, "LINKED TO ", 10);
		memcpy(mod_and_RADIO_ID[i] + 11, to_remote_g2[i].cs, CALL_SIZE);
		mod_and_RADIO_ID[i][11 + CALL_SIZE] = to_remote_g2[i].to_mod;
	}
	else if (to_remote_g2[i].cs[0] != '\0')
	{
		memcpy(mod_and_RADIO_ID[i] + 1, "TRYING    ", 10);
		memcpy(mod_and_RADIO_ID[i] + 11, to_remote_g2[i].cs, CALL_SIZE);
		mod_and_RADIO_ID[i][11 + CALL_SIZE] = to_remote_g2[i].to_mod;
	}
	else
	{
		memcpy(mod_and_RADIO_ID[i] + 1, "NOT LINKED", 10);
	}
	try
	{
		std::async(std::launch::async, &CQnetLink::RptrAckThread, this, mod_and_RADIO_ID[i]);
	}
	catch (const std::exception &e)
	{
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
	ToGate.Write(dsvt.title, 56);
	//std::this_thread::sleep_for(std::chrono::milliseconds(delay_between))

	dsvt.config = 0x20;
	memcpy(dsvt.vasd.voice, silence, 9);

	/* start sending silence + announcement text */

	for (int i=0; i<10; i++)
	{
		dsvt.ctrl = (unsigned char)i;
		switch (i)
		{
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
		ToGate.Write(dsvt.title, 27);
		if (i < 9)
			std::this_thread::sleep_for(std::chrono::milliseconds(delay_between));
	}
}

/* Open text file of repeaters, reflectors */
void CQnetLink::LoadGateways(const std::string &filename)
{
	qnDB.ClearGW();
	const std::string website("auth.dstargateway.org");
	int dplus = 0;
	// DPlus Authenticate
	if (dplus_authorize && !dplus_priority)
	{
		CDPlusAuthenticator auth(login_call, website);
		dplus = auth.Process(qnDB, dplus_reflectors, dplus_repeaters);
		if (0 == dplus)
			fprintf(stdout, "DPlus Authorization failed.\n");
		else
			fprintf(stderr, "DPlus Authorization complete!\n");
	}

	int count = 0;
	std::ifstream hostfile(filename);
	if (hostfile.is_open())
	{
		CHostQueue hqueue;
		std::string line;
		while (std::getline(hostfile, line))
		{
			trim(line);
			if (! line.empty() && ('#' != line.at(0)))
			{
				std::istringstream iss(line);
				std::string host, address;
				unsigned short port;
				iss >> host >> address >> port;
				hqueue.Push(CHost(host, address, port));
				count++;
			}
		}
		hostfile.close();
		if (! hqueue.Empty())
			qnDB.UpdateGW(hqueue);
	}

	if (dplus_authorize)
	{
		if (! dplus_priority)
			printf("#Gateways: %s=%d %s=%d Total=%d\n", website.c_str(), dplus, filename.c_str(), count, qnDB.Count("GATEWAYS"));
	}
	else
	{
		printf("#Gateways: %s=%d\n", filename.c_str(), count);
	}

	// DPlus Authenticate
	if (dplus_authorize && dplus_priority)
	{
		CDPlusAuthenticator auth(login_call, website);
		dplus = auth.Process(qnDB, dplus_reflectors, dplus_repeaters);
		if (0 == dplus)
		{
			printf("#Gateways: %s=%d\n", filename.c_str(), count);
			fprintf(stdout, "DPlus Authorization failed.\n");
		}
		else
		{
			fprintf(stderr, "DPlus Authorization completed!\n");
			printf("#Gateways %s=%d %s=%d Total=%d\n", filename.c_str(), count, website.c_str(), dplus, qnDB.Count("GATEWAYS"));
		}
	}
}

/* compute checksum */
void CQnetLink::calcPFCS(unsigned char *packet, int len)
{
	unsigned short crc_tabccitt[256] =
	{
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

	if (len == 56)
	{
		low = 15;
		high = 54;
	}
	else if (len == 58)
	{
		low = 17;
		high = 56;
	}
	else
		return;

	for (short int i=low; i<high ; i++)
	{
		unsigned short short_c = 0x00ff & (unsigned short)packet[i];
		tmp = (crc_dstar_ffff & 0x00ff) ^ short_c;
		crc_dstar_ffff = (crc_dstar_ffff >> 8) ^ crc_tabccitt[tmp];
	}
	crc_dstar_ffff =  ~crc_dstar_ffff;
	tmp = crc_dstar_ffff;

	if (len == 56)
	{
		packet[54] = (unsigned char)(crc_dstar_ffff & 0xff);
		packet[55] = (unsigned char)((tmp >> 8) & 0xff);
	}
	else
	{
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

	while (std::string::npos != pos || std::string::npos != lastPos)
	{
		std::string element = str.substr(lastPos, pos-lastPos);
		if (element.length()>=3 && element.length()<=6)
		{
			ToUpper(element);
			element.resize(CALL_SIZE, ' ');
			set.insert(element);	// Found a token, add it to the list.
		}
		else
			fprintf(stderr, "found bad callsign in list: %s\n", str.c_str());
		lastPos = str.find_first_not_of(delimiters, pos);	// Skip delimiters.
		pos = str.find_first_of(delimiters, lastPos);	// Find next non-delimiter.
	}
}

void CQnetLink::PrintCallsigns(const std::string &key, const std::set<std::string> &set)
{
	printf("%s = [", key.c_str());
	for (auto it=set.begin(); it!=set.end(); it++)
	{
		if (it != set.begin())
			printf(",");
		printf("%s", (*it).c_str());
	}
	printf("]\n");
}

/* process configuration file */
bool CQnetLink::ReadConfig(const char *cfgFile)
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
	std::string host;
	cfg.GetValue("ircddb0_host", estr, host, 0, MAXHOSTNAMELEN);
	if (host.npos == host.find("v6."))
	{
		cfg.GetValue("ircddb1_host", estr, host, 0, MAXHOSTNAMELEN);
		uses_ipv6 = (host.npos == host.find("v6.")) ? false : true;
	}
	else
	{
		uses_ipv6 = true;
	}
	if (uses_ipv6)
		printf("IPv6 linking is enabled\n");

	int modules = 0;
	for (int i=0; i<3; i++)
	{
		key.assign("module_");
		key.append(1, 'a'+i);
		if (cfg.KeyExists(key))
		{
			std::string modem_type;
			cfg.GetValue(key, estr, modem_type, 1, 16);
			modules++;
			cfg.GetValue(key+"_inactivity", modem_type, rf_inactivity_timer[i], 0, 300);
			rf_inactivity_timer[i] *= 60;
			cfg.GetValue(key+"_link_at_start", modem_type, link_at_startup[i], 0, 8);
			cfg.GetValue(key+"_auto_link", modem_type, to_remote_g2[i].auto_link);
		}
	}
	if (0 == modules)
	{
		fprintf(stderr, "no rf modules defined!\n");
		return true;
	}

	std::string csv;
	key.assign("link_admin");
	if (cfg.KeyExists(key))
	{
		cfg.GetValue(key, estr, csv, 0, 10240);
		UnpackCallsigns(csv, admin);
		PrintCallsigns(key, admin);
	}

	csv.clear();
	key.assign("link_no_link_unlink");
	if (cfg.KeyExists(key))
	{
		cfg.GetValue(key, estr, csv, 0, 10240);
		UnpackCallsigns(csv, link_blacklist);
		PrintCallsigns(key, link_blacklist);
	}
	else
	{
		csv.clear();
		key.assign("link_link_unlink");
		if (cfg.KeyExists(key))
		{
			cfg.GetValue(key, estr, csv, 0, 10240);
			UnpackCallsigns(csv, link_unlink_user);
			PrintCallsigns(key, link_unlink_user);
		}
	}

	key.assign("link_");
	int port;
	cfg.GetValue(key+"ref_port", estr, port, 10000, 65535);
	rmt_ref_port = (unsigned short)port;
	cfg.GetValue(key+"xrf_port", estr, port, 10000, 65535);
	rmt_xrf_port = (unsigned short)port;
	cfg.GetValue(key+"dcs_port", estr, port, 10000, 65535);
	rmt_dcs_port = (unsigned short)port;
	cfg.GetValue(key+"acknowledge", estr, bool_rptr_ack);
	cfg.GetValue(key+"announce", estr, announce);
	int maxdongle;
	cfg.GetValue(key+"max_dongles", estr, maxdongle, 0, 10);
	saved_max_dongles = max_dongles = (unsigned int)maxdongle;

	key.assign("gateway_");
	cfg.GetValue(key+"tolink", estr, togate, 1, FILENAME_MAX);

	cfg.GetValue("log_qso", estr, qso_details);
	cfg.GetValue("log_debug", estr, log_debug);

	key.assign("file_");
	cfg.GetValue(key+"gwys", estr, gwys, 2, FILENAME_MAX);
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
	if (login_call.length() < 4)
	{
		login_call.assign(owner);
	}
	else
	{
		ToUpper(login_call);
		login_call.resize(CALL_SIZE, ' ');
	}
	cfg.GetValue(key+"priority", estr, dplus_priority);

	return false;
}

/* create our server */
bool CQnetLink::srv_open()
{
	if (uses_ipv6)
	{
		if (XRFSock6.Open(CSockAddress(AF_INET6, rmt_xrf_port, "any")) || DCSSock6.Open(CSockAddress(AF_INET6, rmt_dcs_port, "any")) || REFSock6.Open(CSockAddress(AF_INET6, rmt_ref_port, "any")))
		{
			srv_close();
			return true;
		}
	}
	if (XRFSock4.Open(CSockAddress(AF_INET, rmt_xrf_port, "any")) || DCSSock4.Open(CSockAddress(AF_INET, rmt_dcs_port, "any")) || REFSock4.Open(CSockAddress(AF_INET, rmt_ref_port, "any")))
	{
		srv_close();
		return true;
	}

	/* create our gateway unix sockets */
	printf("Connecting to qngateway at %s\n", togate.c_str());
	if (ToGate.Open(togate.c_str(), this))
	{
		srv_close();
		return true;
	}

	/* initialize all remote links */
	for (int i = 0; i < 3; i++)
	{
		to_remote_g2[i].cs[0] = '\0';
		to_remote_g2[i].addr.Clear();
		to_remote_g2[i].from_mod = ' ';
		to_remote_g2[i].to_mod = ' ';
		to_remote_g2[i].countdown = 0;
		to_remote_g2[i].is_connected = false;
		to_remote_g2[i].in_streamid = 0x0;
		to_remote_g2[i].out_streamid = 0x0;
	}
	return false;
}

/* destroy our server */
void CQnetLink::srv_close()
{
	XRFSock6.Close();
	DCSSock6.Close();
	REFSock6.Close();
	XRFSock4.Close();
	DCSSock4.Close();
	REFSock4.Close();
	ToGate.Close();
}

/* find the repeater IP by callsign and link to it */
void CQnetLink::g2link(const char from_mod, const char *call, const char to_mod)
{
	char linked_remote_system[CALL_SIZE + 1];

	char link_request[519];

	bool ok = false;

	memset(link_request, 0, sizeof(link_request));

	int i;
	if (from_mod == 'A')
		i = 0;
	else if (from_mod == 'B')
		i = 1;
	else if (from_mod == 'C')
		i = 2;
	else
	{
		printf("from_mod %c invalid\n", from_mod);
		return;
	}

	to_remote_g2[i].addr.Clear();
	to_remote_g2[i].countdown = 0;
	to_remote_g2[i].from_mod = '\0';
	to_remote_g2[i].in_streamid = 0;
	to_remote_g2[i].is_connected = false;
	to_remote_g2[i].out_streamid = 0;
	to_remote_g2[i].cs[0] = '\0';
	to_remote_g2[i].to_mod = '\0';

	std::string address;
	unsigned short port;
	if (qnDB.FindGW(call, address, port))
	{
		sprintf(notify_msg[i], "%c_gatewaynotfound.dat_GATEWAY_NOT_FOUND", from_mod);
		printf("%s not found in gwy list\n", call);
		return;
	}

	strcpy(to_remote_g2[i].cs, call);
	to_remote_g2[i].to_mod = to_mod;

	if ((memcmp(call, "REF", 3) == 0) || (memcmp(call, "DCS", 3) == 0))
	{
		int counter;
		for (counter = 0; counter < 3; counter++)
		{
			if (counter != i)
			{
				if ('\0'!=to_remote_g2[counter].cs[0] && !strcmp(to_remote_g2[counter].cs,to_remote_g2[i].cs) && to_remote_g2[counter].to_mod==to_remote_g2[i].to_mod)
					break;
			}
		}
		to_remote_g2[i].cs[0] = '\0';
		to_remote_g2[i].to_mod = ' ';

		if (counter < 3)
		{
			printf("Another mod(%c) is already linked to %s %c\n", to_remote_g2[counter].from_mod, to_remote_g2[counter].cs, to_remote_g2[counter].to_mod);
			return;
		}
	}

	if (address.size())
	{
		ok = resolve_rmt(address.c_str(), port, to_remote_g2[i].addr);
		if (!ok)
		{
			printf("Call %s is host %s but could not resolve to IP\n", call, address.c_str());
			to_remote_g2[i].addr.Clear();
			to_remote_g2[i].countdown = 0;
			to_remote_g2[i].from_mod = '\0';
			to_remote_g2[i].in_streamid = 0;
			to_remote_g2[i].is_connected = false;
			to_remote_g2[i].out_streamid = 0;
			to_remote_g2[i].cs[0] = '\0';
			to_remote_g2[i].to_mod = '\0';
			return;
		}

		strcpy(to_remote_g2[i].cs, call);
		to_remote_g2[i].from_mod = from_mod;
		to_remote_g2[i].to_mod = to_mod;
		to_remote_g2[i].countdown = TIMEOUT;
		to_remote_g2[i].is_connected = false;
		to_remote_g2[i].in_streamid= 0x0;

		/* is it XRF? */
		if (port == rmt_xrf_port)
		{
			strcpy(link_request, owner.c_str());
			link_request[8] = from_mod;
			link_request[9] = to_mod;
			link_request[10] = '\0';

			printf("sending link request from mod %c to link with: [%s] mod %c [%s]:%u\n", to_remote_g2[i].from_mod, to_remote_g2[i].cs, to_remote_g2[i].to_mod, address.c_str(), port);

			for (int j=0; j<5; j++)
				XRFWrite(link_request, CALL_SIZE + 3, to_remote_g2[i].addr);
		}
		else if (port == rmt_dcs_port)
		{
			strcpy(link_request, owner.c_str());
			link_request[8] = from_mod;
			link_request[9] = to_mod;
			link_request[10] = '\0';
			memcpy(link_request + 11, to_remote_g2[i].cs, 8);
			strcpy(link_request + 19, "<table border=\"0\" width=\"95%\"><tr><td width=\"4%\"><img border=\"0\" src=g2ircddb.jpg></td><td width=\"96%\"><font size=\"2\"><b>REPEATER</b> QnetGateway v1.0+</font></td></tr></table>");

			printf("sending link request from mod %c to link with: [%s] mod %c [%s]:%u\n", to_remote_g2[i].from_mod, to_remote_g2[i].cs, to_remote_g2[i].to_mod, address.c_str(), port);
			DCSWrite(link_request, 519, to_remote_g2[i].addr);
		}
		else if (port == rmt_ref_port)
		{
			int counter;
			for (counter = 0; counter < 3; counter++)
			{
				if (counter != i)
				{
					if ( (to_remote_g2[counter].cs[0] != '\0') && (strcmp(to_remote_g2[counter].cs, to_remote_g2[i].cs) == 0) )
						break;
				}
			}
			if (counter > 2)
			{
				printf("sending link command from mod %c to: [%s] mod %c [%s]:%u\n", to_remote_g2[i].from_mod, to_remote_g2[i].cs, to_remote_g2[i].to_mod, address.c_str(), port);

				queryCommand[0] = 5;
				queryCommand[1] = 0;
				queryCommand[2] = 24;
				queryCommand[3] = 0;
				queryCommand[4] = 1;

				REFWrite(queryCommand, 5, to_remote_g2[i].addr);
			}
			else
			{
				if (to_remote_g2[counter].is_connected)
				{
					to_remote_g2[i].is_connected = true;
					printf("Local module %c is also connected to %s %c\n", from_mod, call, to_mod);

					tracing[i].last_time = time(NULL);

					// announce it here
					strcpy(linked_remote_system, to_remote_g2[i].cs);
					auto space_p = strchr(linked_remote_system, ' ');
					if (space_p)
						*space_p = '\0';
					sprintf(notify_msg[i], "%c_linked.dat_LINKED_%s_%c", to_remote_g2[i].from_mod, linked_remote_system, to_remote_g2[i].to_mod);
				}
				else
					printf("status from %s %c pending\n", to_remote_g2[i].cs, to_remote_g2[i].to_mod);
			}
		}
	}
	return;
}

void CQnetLink::ProcessXRF(unsigned char *buf, const int length)
{
	const std::string ip(fromDst4.GetAddress());
	char call[CALL_SIZE + 1];
	memcpy(call, buf, CALL_SIZE);
	call[CALL_SIZE] = '\0';

	/* A packet of length (CALL_SIZE + 1) is a keepalive from a repeater/reflector */
	/* If it is from a dongle, it is either a keepalive or a request to connect */
	bool found = false;
	if (length == (CALL_SIZE + 1))
	{
		/* Find out if it is a keepalive from a repeater */
		for (int i=0; i<3; i++)
		{
			if (fromDst4==to_remote_g2[i].addr && to_remote_g2[i].addr.GetPort()==rmt_xrf_port)
			{
				found = true;
				if (!to_remote_g2[i].is_connected)
				{
					tracing[i].last_time = time(NULL);

					to_remote_g2[i].is_connected = true;
					printf("Connected from: %.*s\n", length - 1, buf);

					char linked_remote_system[CALL_SIZE + 1];
					strcpy(linked_remote_system, to_remote_g2[i].cs);
					auto space_p = strchr(linked_remote_system, ' ');
					if (space_p)
						*space_p = '\0';
					sprintf(notify_msg[i], "%c_linked.dat_LINKED_%s_%c", to_remote_g2[i].from_mod, linked_remote_system, to_remote_g2[i].to_mod);

				}
				to_remote_g2[i].countdown = TIMEOUT;
			}
		}
	}
	else if (length == (CALL_SIZE + 6))
	{
		/* A packet of length (CALL_SIZE + 6) is either an ACK or a NAK from repeater-reflector */
		/* Because we sent a request before asking to link */

		for (int i=0; i<3; i++)
		{
			if ((fromDst4==to_remote_g2[i].addr && to_remote_g2[i].addr.GetPort()==rmt_xrf_port))
			{
				if (0==memcmp(buf + 10, "ACK", 3) && to_remote_g2[i].from_mod==buf[8])
				{
					if (!to_remote_g2[i].is_connected)
					{
						tracing[i].last_time = time(NULL);

						to_remote_g2[i].is_connected = true;
						printf("Connected from: %s %c [%s]:%u\n", to_remote_g2[i].cs, to_remote_g2[i].to_mod, to_remote_g2[i].addr.GetAddress(), to_remote_g2[i].addr.GetPort());
						qnDB.UpdateLS(to_remote_g2[i].addr.GetAddress(), to_remote_g2[i].from_mod, to_remote_g2[i].cs, to_remote_g2[i].to_mod, tracing[i].last_time);

						char linked_remote_system[CALL_SIZE + 1];
						strcpy(linked_remote_system, to_remote_g2[i].cs);
						auto space_p = strchr(linked_remote_system, ' ');
						if (space_p)
							*space_p = '\0';
						sprintf(notify_msg[i], "%c_linked.dat_LINKED_%s_%c", to_remote_g2[i].from_mod, linked_remote_system, to_remote_g2[i].to_mod);
					}
				}
				else if (0==memcmp(buf + 10, "NAK", 3) && to_remote_g2[i].from_mod==buf[8])
				{
					printf("Link module %c to [%s] %c is rejected\n", to_remote_g2[i].from_mod, to_remote_g2[i].cs, to_remote_g2[i].to_mod);

					sprintf(notify_msg[i], "%c_failed_link.dat_FAILED_TO_LINK", to_remote_g2[i].from_mod);

					to_remote_g2[i].cs[0] = '\0';
					to_remote_g2[i].addr.Clear();
					to_remote_g2[i].from_mod = to_remote_g2[i].to_mod = ' ';
					to_remote_g2[i].countdown = 0;
					to_remote_g2[i].is_connected = false;
					to_remote_g2[i].in_streamid = 0x0;
				}
			}
		}
	}
	else if (length == CALL_SIZE + 3)
	{
		// A packet of length (CALL_SIZE + 3) is a request
		// from a remote repeater to link-unlink with our repeater

		/* Check our linked repeaters/reflectors */
		for (int i=0; i<3; i++)
		{
			if (fromDst4==to_remote_g2[i].addr && to_remote_g2[i].addr.GetPort()==rmt_xrf_port)
			{
				if (to_remote_g2[i].to_mod == buf[8])
				{
					/* unlink request from remote repeater that we know */
					if (buf[9] == ' ')
					{
						printf("Received: %.*s\n", length - 1, buf);
						printf("Module %c to [%s] %c is unlinked\n", to_remote_g2[i].from_mod, to_remote_g2[i].cs, to_remote_g2[i].to_mod);
						qnDB.DeleteLS(to_remote_g2[i].addr.GetAddress());
						sprintf(notify_msg[i], "%c_unlinked.dat_UNLINKED", to_remote_g2[i].from_mod);

						to_remote_g2[i].cs[0] = '\0';
						to_remote_g2[i].addr.Clear();
						to_remote_g2[i].from_mod = to_remote_g2[i].to_mod = ' ';
						to_remote_g2[i].countdown = 0;
						to_remote_g2[i].is_connected = false;
						to_remote_g2[i].in_streamid = 0x0;
					}
					else if ((i==0 && buf[9]=='A') || (i==1 && buf[9]=='B') || (i==2 && buf[9]=='C'))    /* link request from a remote repeater that we know */
					{
						/*
							I HAVE TO ADD CODE here to PREVENT the REMOTE NODE
							from LINKING one of their remote modules to
							more than one of our local modules
						*/

						printf("Received: %.*s\n", length - 1, buf);

						memcpy(to_remote_g2[i].cs, buf, CALL_SIZE);
						to_remote_g2[i].cs[CALL_SIZE] = '\0';
						to_remote_g2[i].addr = fromDst4;
						to_remote_g2[i].to_mod = buf[8];
						to_remote_g2[i].countdown = TIMEOUT;
						to_remote_g2[i].is_connected = true;
						to_remote_g2[i].in_streamid = 0x0;

						printf("Module %c to [%s] %c linked\n", buf[9], to_remote_g2[i].cs, to_remote_g2[i].to_mod);

						tracing[i].last_time = time(NULL);



						/* send back an ACK */
						memcpy(buf + 10, "ACK", 4);
						XRFWrite(buf, CALL_SIZE+6, to_remote_g2[i].addr);

						if (to_remote_g2[i].from_mod != buf[9])
						{
							to_remote_g2[i].from_mod = buf[9];

							char linked_remote_system[CALL_SIZE + 1];
							strcpy(linked_remote_system, to_remote_g2[i].cs);
							auto space_p = strchr(linked_remote_system, ' ');
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
		if (qnDB.FindGW(call))
		{
			int rc = regexec(&preg, call, 0, NULL, 0);
			if (rc != 0)
			{
				printf("Invalid repeater %s, %s requesting to link\n", call, ip.c_str());
				i = -1;
			}
		}
		else
		{
			/* We did NOT find this repeater in gwys.txt, reject the incoming link request */
			printf("Incoming link from %s,%s but not found in gwys.txt\n", call, ip.c_str());
			i = -1;
		}

		if (i >= 0)
		{
			/* Is the local repeater module linked to anything ? */
			if (to_remote_g2[i].to_mod == ' ')
			{
				if (buf[8]>='A' && buf[8]<='E')
				{
					/*
						I HAVE TO ADD CODE here to PREVENT the REMOTE NODE
						from LINKING one of their remote modules to
						more than one of our local modules
					*/

					/* now it can be added as a repeater */
					strcpy(to_remote_g2[i].cs, call);
					to_remote_g2[i].cs[CALL_SIZE] = '\0';
					to_remote_g2[i].addr = fromDst4;
					to_remote_g2[i].from_mod = buf[9];
					to_remote_g2[i].to_mod = buf[8];
					to_remote_g2[i].countdown = TIMEOUT;
					to_remote_g2[i].is_connected = true;
					to_remote_g2[i].in_streamid = 0x0;

					tracing[i].last_time = time(NULL);
					qnDB.UpdateLS(to_remote_g2[i].addr.GetAddress(), to_remote_g2[i].from_mod, to_remote_g2[i].cs, to_remote_g2[i].to_mod, tracing[i].last_time);

					printf("Received: %.*s\n", length - 1, buf);
					printf("Module %c to [%s] %c linked\n", to_remote_g2[i].from_mod, to_remote_g2[i].cs, to_remote_g2[i].to_mod);

					char linked_remote_system[CALL_SIZE + 1];
					strcpy(linked_remote_system, to_remote_g2[i].cs);
					auto space_p = strchr(linked_remote_system, ' ');
					if (space_p)
						*space_p = '\0';
					sprintf(notify_msg[i], "%c_linked.dat_LINKED_%s_%c", to_remote_g2[i].from_mod, linked_remote_system, to_remote_g2[i].to_mod);

					/* send back an ACK */
					memcpy(buf + 10, "ACK", 4);
					XRFWrite(buf, CALL_SIZE+6, to_remote_g2[i].addr);
				}
			}
			else
			{
				if (fromDst4 != to_remote_g2[i].addr)
				{
					/* Our repeater module is linked to another repeater-reflector */
					memcpy(buf + 10, "NAK", 4);
					if (fromDst4.GetPort() != rmt_xrf_port)
					{
						fromDst4.Initialize(fromDst4.GetFamily(), rmt_xrf_port, fromDst4.GetAddress());
					}
					XRFWrite(buf, CALL_SIZE+6, fromDst4);
				}
			}
		}
	}
	else if ((length==56 || length==27) && 0==memcmp(buf, "DSVT", 4) && (buf[4]==0x10 || buf[4]==0x20) && buf[8]==0x20)
	{
		/* reset countdown and protect against hackers */

		found = false;
		for (int i=0; i<3; i++)
		{
			if ((fromDst4 == to_remote_g2[i].addr) && (to_remote_g2[i].addr.GetPort() == rmt_xrf_port))
			{
				to_remote_g2[i].countdown = TIMEOUT;
				found = true;
			}
		}

		SDSVT dsvt;
		memcpy(dsvt.title, buf, length);	// copy to struct

		/* process header */
		if ((length == 56) && found)
		{
			char source_stn[9];
			memset(source_stn, ' ', 9);
			source_stn[8] = '\0';

			/* some bad hotspot programs out there using INCORRECT flag */
			if (dsvt.hdr.flag[0]==0x40U || dsvt.hdr.flag[0]==0x48U || dsvt.hdr.flag[0]==0x60U || dsvt.hdr.flag[0]==0x68U) dsvt.hdr.flag[0] -= 0x40;

			/* A reflector will send to us its own RPT1 */
			/* A repeater will send to us our RPT1 */

			for (int i=0; i<3; i++)
			{
				if (fromDst4==to_remote_g2[i].addr && to_remote_g2[i].addr.GetPort()==rmt_xrf_port)
				{
					/* it is a reflector, reflector's rpt1 */
					if (0==memcmp(dsvt.hdr.rpt1, to_remote_g2[i].cs, 7) && dsvt.hdr.rpt1[7]==to_remote_g2[i].to_mod)
					{
						memcpy(dsvt.hdr.rpt1, owner.c_str(), CALL_SIZE);
						dsvt.hdr.rpt1[7] = to_remote_g2[i].from_mod;
						memcpy(dsvt.hdr.urcall, "CQCQCQ  ", 8);

						memcpy(source_stn, to_remote_g2[i].cs, 8);
						source_stn[7] = to_remote_g2[i].to_mod;
						break;
					}
					else
						/* it is a repeater, our rpt1 */
						if (memcmp(dsvt.hdr.rpt1, owner.c_str(), CALL_SIZE-1) && dsvt.hdr.rpt1[7]==to_remote_g2[i].from_mod)
						{
							memcpy(source_stn, to_remote_g2[i].cs, 8);
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
			if (0==memcmp(dsvt.hdr.rpt1, owner.c_str(), CALL_SIZE-1) && i>=0)
			{
				/* Last Heard */
				if (old_sid[i].sid != dsvt.streamid)
				{
					if (qso_details)
						printf("START from remote g2: streamID=%04x, flags=%02x:%02x:%02x, my=%.8s, sfx=%.4s, ur=%.8s, rpt1=%.8s, rpt2=%.8s, %d bytes fromIP=%s, source=%.8s\n", ntohs(dsvt.streamid), dsvt.hdr.flag[0], dsvt.hdr.flag[1], dsvt.hdr.flag[2], dsvt.hdr.mycall, dsvt.hdr.sfx, dsvt.hdr.urcall, dsvt.hdr.rpt1, dsvt.hdr.rpt2, length, fromDst4.GetAddress(), source_stn);

					// put user into tmp1
					char tmp1[CALL_SIZE + 1];
					memcpy(tmp1, dsvt.hdr.mycall, 8);
					tmp1[8] = '\0';

					// delete the user if exists
					for (auto dt_lh_pos = dt_lh_list.begin(); dt_lh_pos != dt_lh_list.end();  dt_lh_pos++)
					{
						if (0 == strcmp((char *)dt_lh_pos->second.c_str(), tmp1))
						{
							dt_lh_list.erase(dt_lh_pos);
							break;
						}
					}
					/* Limit?, delete oldest user */
					if (dt_lh_list.size() == LH_MAX_SIZE)
					{
						auto dt_lh_pos = dt_lh_list.begin();
						dt_lh_list.erase(dt_lh_pos);
					}
					// add user
					time(&tnow);
					char tmp2[36];
					sprintf(tmp2, "%ld=r%.6s%c%c", tnow, source_stn, source_stn[7], dsvt.hdr.rpt1[7]);
					dt_lh_list[tmp2] = tmp1;

					old_sid[i].sid = dsvt.streamid;
				}

				/* relay data to our local G2 */
				ToGate.Write(dsvt.title, 56);

				/* send data to donglers */
				/* no changes here */
				for (auto pos = inbound_list.begin(); pos != inbound_list.end(); pos++)
				{
					SINBOUND *inbound = (SINBOUND *)pos->second;
					if (fromDst4 == inbound->addr)
					{
						inbound->mod = dsvt.hdr.rpt1[7];
					}
					else
					{
						SREFDSVT rdsvt;
						rdsvt.head[0] = 58U;
						rdsvt.head[1] = 0x80U;
						memcpy(rdsvt.dsvt.title, dsvt.title, 56);

						REFWrite(rdsvt.head, 58, inbound->addr);
					}
				}

				/* send the data to the repeater/reflector that is linked to our RPT1 */

				/* Is there another local module linked to the remote same xrf mod ? */
				/* If Yes, then broadcast */
				int k = i + 1;

				if (k < 3)
				{
					brd_from_xrf_idx = 0;
					auto streamid_raw = ntohs(dsvt.streamid);

					/* We can only enter this loop up to 2 times max */
					for (int j=k; j<3; j++)
					{
						/* it is a remote gateway, not a dongle user */
						if (fromDst4==to_remote_g2[j].addr &&
								/* it is xrf */
								to_remote_g2[j].addr.GetPort()==rmt_xrf_port &&
								0==memcmp(to_remote_g2[j].cs, "XRF", 3) &&
								/* it is the same xrf and xrf module */
								0==memcmp(to_remote_g2[j].cs, to_remote_g2[i].cs, 8) &&
								to_remote_g2[j].to_mod==to_remote_g2[i].to_mod)
						{
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
							ToGate.Write(from_xrf_torptr_brd.title, 56);

							/* save streamid for use with the audio packets that will arrive after this header */

							brd_from_xrf.xrf_streamid = dsvt.streamid;
							brd_from_xrf.rptr_streamid[brd_from_xrf_idx] = from_xrf_torptr_brd.streamid;
							brd_from_xrf_idx++;
						}
					}
				}

				if ((to_remote_g2[i].addr != fromDst4) && to_remote_g2[i].is_connected)
				{
					if (to_remote_g2[i].addr.GetPort() == rmt_xrf_port)
					{
						if ( /*** (memcmp(readBuffer2 + 42, owner, 8) != 0) && ***/         /* block repeater announcements */
							(memcmp(dsvt.hdr.urcall, "CQCQCQ", 6) == 0) && /* CQ calls only */
							(dsvt.hdr.flag[0] == 0x00  ||                  /* normal */
							 dsvt.hdr.flag[0] == 0x08  ||                  /* EMR */
							 dsvt.hdr.flag[0] == 0x20  ||                  /* BK */
							 dsvt.hdr.flag[0] == 0x28) &&                  /* EMR + BK */
							0==memcmp(dsvt.hdr.rpt2, owner.c_str(), CALL_SIZE-1) &&         /* rpt2 must be us */
							dsvt.hdr.rpt2[7] == 'G')
						{
							to_remote_g2[i].in_streamid = dsvt.streamid;

							/* inform XRF about the source */
							dsvt.flagb[2] = to_remote_g2[i].from_mod;

							memcpy(dsvt.hdr.rpt1, to_remote_g2[i].cs, CALL_SIZE);
							dsvt.hdr.rpt1[7] = to_remote_g2[i].to_mod;
							memcpy(dsvt.hdr.rpt2, to_remote_g2[i].cs, CALL_SIZE);
							dsvt.hdr.rpt2[7] = 'G';
							calcPFCS(dsvt.title, 56);

							XRFWrite(dsvt.title, 56, to_remote_g2[i].addr);
						}
					}
					else if (to_remote_g2[i].addr.GetPort() == rmt_ref_port)
					{
						if ( /*** (memcmp(readBuffer2 + 42, owner, 8) != 0) && ***/         /* block repeater announcements */
							0==memcmp(dsvt.hdr.urcall, "CQCQCQ", 6) && /* CQ calls only */
							(dsvt.hdr.flag[0] == 0x00 ||               /* normal */
							 dsvt.hdr.flag[0] == 0x08 ||               /* EMR */
							 dsvt.hdr.flag[0] == 0x20 ||               /* BK */
							 dsvt.hdr.flag[0] == 0x28) &&              /* EMR + BK */
							0==memcmp(dsvt.hdr.rpt2, owner.c_str(), CALL_SIZE-1) &&         /* rpt2 must be us */
							dsvt.hdr.rpt2[7] == 'G')
						{
							to_remote_g2[i].in_streamid = dsvt.streamid;

							SREFDSVT rdsvt;
							rdsvt.head[0] = 58U;
							rdsvt.head[1] = 0x80U;

							memcpy(rdsvt.dsvt.title, dsvt.title, 56);

							memset(rdsvt.dsvt.hdr.rpt1, ' ', CALL_SIZE);
							memcpy(rdsvt.dsvt.hdr.rpt1, to_remote_g2[i].cs, strlen(to_remote_g2[i].cs));
							rdsvt.dsvt.hdr.rpt1[7] = to_remote_g2[i].to_mod;
							memset(rdsvt.dsvt.hdr.rpt2, ' ', CALL_SIZE);
							memcpy(rdsvt.dsvt.hdr.rpt2, to_remote_g2[i].cs, strlen(to_remote_g2[i].cs));
							rdsvt.dsvt.hdr.rpt2[7] = 'G';
							memcpy(rdsvt.dsvt.hdr.urcall, "CQCQCQ  ", CALL_SIZE);

							calcPFCS(rdsvt.dsvt.title, 56);

							REFWrite(rdsvt.head, 58, to_remote_g2[i].addr);
						}
					}
					else if (to_remote_g2[i].addr.GetPort() == rmt_dcs_port)
					{
						if ( /*** (memcmp(readBuffer2 + 42, owner, 8) != 0) && ***/         /* block repeater announcements */
							0==memcmp(dsvt.hdr.urcall, "CQCQCQ", 6) && /* CQ calls only */
							(dsvt.hdr.flag[0] == 0x00 ||               /* normal */
							 dsvt.hdr.flag[0] == 0x08 ||               /* EMR */
							 dsvt.hdr.flag[0] == 0x20 ||               /* BK */
							 dsvt.hdr.flag[0] == 0x28) &&              /* EMR + BK */
							0==memcmp(dsvt.hdr.rpt2, owner.c_str(), CALL_SIZE-1) &&         /* rpt2 must be us */
							dsvt.hdr.rpt2[7] == 'G')
						{
							to_remote_g2[i].in_streamid = dsvt.streamid;

							memcpy(xrf_2_dcs[i].mycall, dsvt.hdr.mycall, CALL_SIZE);
							memcpy(xrf_2_dcs[i].sfx, dsvt.hdr.sfx, 4);
							xrf_2_dcs[i].dcs_rptr_seq = 0;
						}
					}
				}
			}
		}
		else if (found)  	// length is 27
		{
			if ((dsvt.ctrl & 0x40) != 0)
			{
				for (int i=0; i<3; i++)
				{
					if (old_sid[i].sid == dsvt.streamid)
					{
						if (qso_details)
							printf("END from remote g2: streamID=%04x, %d bytes from IP=%s\n", ntohs(dsvt.streamid), length, fromDst4.GetAddress());
						old_sid[i].sid = 0x0;

						break;
					}
				}
			}

			/* relay data to our local G2 */
			ToGate.Write(dsvt.title, 27);

			/* send data to donglers */
			/* no changes here */
			for (auto pos = inbound_list.begin(); pos != inbound_list.end(); pos++)
			{
				SINBOUND *inbound = (SINBOUND *)pos->second;
				if (fromDst4 != inbound->addr)
				{
					SREFDSVT rdsvt;
					rdsvt.head[0] = (dsvt.ctrl & 0x40U) ? 32U : 29U;
					rdsvt.head[1] = 0x80U;

					memcpy(rdsvt.dsvt.title, dsvt.title, 27);
					if (32U == rdsvt.head[0])
						memcpy(rdsvt.dsvt.vend.textend, endbytes, 6);

					REFWrite(rdsvt.head, rdsvt.head[0], inbound->addr);
				}
			}

			/* do we have to broadcast ? */
			if (brd_from_xrf.xrf_streamid == dsvt.streamid)
			{
				memcpy(from_xrf_torptr_brd.title, dsvt.title, 27);

				if (brd_from_xrf.rptr_streamid[0] != 0x0)
				{
					from_xrf_torptr_brd.streamid = brd_from_xrf.rptr_streamid[0];
					ToGate.Write(from_xrf_torptr_brd.title, 27);
				}

				if (brd_from_xrf.rptr_streamid[1] != 0x0)
				{
					from_xrf_torptr_brd.streamid = brd_from_xrf.rptr_streamid[1];
					ToGate.Write(from_xrf_torptr_brd.title, 27);
				}

				if (dsvt.ctrl & 0x40)
				{
					brd_from_xrf.xrf_streamid = brd_from_xrf.rptr_streamid[0] = brd_from_xrf.rptr_streamid[1] = 0x0;
					brd_from_xrf_idx = 0;
				}
			}

			for (int i=0; i<3; i++)
			{
				if (to_remote_g2[i].is_connected && (to_remote_g2[i].addr != fromDst4) && to_remote_g2[i].in_streamid==dsvt.streamid)
				{
					if (to_remote_g2[i].addr.GetPort() == rmt_xrf_port)
					{
						/* inform XRF about the source */
						dsvt.flagb[2] = to_remote_g2[i].from_mod;

						XRFWrite(dsvt.title, 27, to_remote_g2[i].addr);
					}
					else if (to_remote_g2[i].addr.GetPort() == rmt_ref_port)
					{
						SREFDSVT rdsvt;
						rdsvt.head[0] = (dsvt.ctrl & 0x40) ? 32U : 29U;
						rdsvt.head[1] = 0x80U;

						memcpy(rdsvt.dsvt.title, dsvt.title, 27);
						if (32U == rdsvt.head[0])
							memcpy(rdsvt.dsvt.vend.textend, endbytes, 6);
						REFWrite(rdsvt.head, rdsvt.head[0], to_remote_g2[i].addr);
					}
					else if (to_remote_g2[i].addr.GetPort() == rmt_dcs_port)
					{
						unsigned char dcs_buf[1000];
						memset(dcs_buf, 0x00, 600);
						dcs_buf[0] = dcs_buf[1] = dcs_buf[2] = '0';
						dcs_buf[3] = '1';
						dcs_buf[4] = dcs_buf[5] = dcs_buf[6] = 0x0;
						memcpy(dcs_buf + 7, to_remote_g2[i].cs, 8);
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

						DCSWrite(dcs_buf, 100, to_remote_g2[i].addr);
					}

					if (dsvt.ctrl & 0x40)
					{
						to_remote_g2[i].in_streamid = 0x0;
					}
					break;
				}
			}
		}
	}
}

void CQnetLink::ProcessDCS(unsigned char *dcs_buf, const int length)
{
	const std::string ip(fromDst4.GetAddress());

	/* header, audio */
	if (dcs_buf[0]=='0' && dcs_buf[1]=='0' && dcs_buf[2]=='0' && dcs_buf[3]=='1')
	{
		if (length == 100)
		{
			char source_stn[9];
			memset(source_stn, ' ', 9);
			source_stn[8] = '\0';

			/* find out our local module */
			int i;
			for (i=0; i<3; i++)
			{
				if (to_remote_g2[i].is_connected && fromDst4==to_remote_g2[i].addr && 0==memcmp(dcs_buf + 7, to_remote_g2[i].cs, 7) && to_remote_g2[i].to_mod==dcs_buf[14])
				{
					memcpy(source_stn, to_remote_g2[i].cs, 8);
					source_stn[7] = to_remote_g2[i].to_mod;
					break;
				}
			}

			/* Is it our local module */
			if (i < 3)
			{
				/* Last Heard */
				if (memcmp(&old_sid[i].sid, dcs_buf + 43, 2))
				{
					if (qso_details)
						printf("START from dcs: streamID=%02x%02x, my=%.8s, sfx=%.4s, ur=%.8s, rpt1=%.8s, rpt2=%.8s, %d bytes fromIP=%s, source=%.8s\n", dcs_buf[44],dcs_buf[43], &dcs_buf[31], &dcs_buf[39], &dcs_buf[23], &dcs_buf[7], &dcs_buf[15], length, fromDst4.GetAddress(), source_stn);

					// put user into tmp1
					char tmp1[CALL_SIZE + 1];
					memcpy(tmp1, dcs_buf + 31, 8);
					tmp1[8] = '\0';

					// delete the user if exists
					for (auto dt_lh_pos=dt_lh_list.begin(); dt_lh_pos!=dt_lh_list.end();  dt_lh_pos++)
					{
						if (strcmp(dt_lh_pos->second.c_str(), tmp1) == 0)
						{
							dt_lh_list.erase(dt_lh_pos);
							break;
						}
					}
					/* Limit?, delete oldest user */
					if (dt_lh_list.size() == LH_MAX_SIZE)
					{
						auto dt_lh_pos = dt_lh_list.begin();
						dt_lh_list.erase(dt_lh_pos);
					}
					// add user
					time(&tnow);
					char tmp2[36];
					sprintf(tmp2, "%ld=r%.6s%c%c", tnow, source_stn, source_stn[7], to_remote_g2[i].from_mod);
					dt_lh_list[tmp2] = tmp1;

					memcpy(&old_sid[i].sid, dcs_buf + 43, 2);
				}

				to_remote_g2[i].countdown = TIMEOUT;

				/* new stream ? */
				if (memcmp(&to_remote_g2[i].in_streamid, dcs_buf+43, 2))
				{
					memcpy(&to_remote_g2[i].in_streamid, dcs_buf+43, 2);
					dcs_seq[i] = 0xff;

					/* generate our header */
					SREFDSVT rdsvt;
					rdsvt.head[0] = 58U;
					rdsvt.head[1] = 0x80U;
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
						ToGate.Write(rdsvt.dsvt.title, 56);

					/* send the data to the donglers */
					for (auto pos = inbound_list.begin(); pos != inbound_list.end(); pos++)
					{
						SINBOUND *inbound = (SINBOUND *)pos->second;
						for (int j=0; j<5; j++)
							REFWrite(rdsvt.head, 58, inbound->addr);
					}
				}

				if (0==memcmp(&to_remote_g2[i].in_streamid, dcs_buf+43, 2) && dcs_seq[i]!=dcs_buf[45])
				{
					dcs_seq[i] = dcs_buf[45];
					SREFDSVT rdsvt;
					rdsvt.head[0] = (dcs_buf[45] & 0x40U) ? 32U : 29U;
					rdsvt.head[1] = 0x80U;
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
					if (dcs_buf[45] & 0x40U)
						memcpy(rdsvt.dsvt.vend.textend, endbytes, 6);

					/* send the data to the local gateway/repeater */
					ToGate.Write(rdsvt.dsvt.title, 27);

					/* send the data to the donglers */
					for (auto pos = inbound_list.begin(); pos != inbound_list.end(); pos++)
					{
						SINBOUND *inbound = (SINBOUND *)pos->second;
						REFWrite(rdsvt.head, rdsvt.head[0], inbound->addr);
					}

					if ((dcs_buf[45] & 0x40) != 0)
					{
						old_sid[i].sid = 0x0;

						if (qso_details)
							printf("END from dcs: streamID=%04x, %d bytes from IP=%s\n", ntohs(rdsvt.dsvt.streamid), length, fromDst4.GetAddress());

						to_remote_g2[i].in_streamid = 0x0;
						dcs_seq[i] = 0xff;
					}
				}
			}
		}
	}
	else if (dcs_buf[0]=='E' && dcs_buf[1]=='E' && dcs_buf[2]=='E' && dcs_buf[3]=='E')
		;
	else if (length == 35)
		;
	/* is this a keepalive 22 bytes */
	else if (length == 22)
	{
		int i = -1;
		if (dcs_buf[17] == 'A')
			i = 0;
		else if (dcs_buf[17] == 'B')
			i = 1;
		else if (dcs_buf[17] == 'C')
			i = 2;

		/* It is one of our valid repeaters */
		// DG1HT from owner 8 to 7
		if (i>=0 && 0==memcmp(dcs_buf + 9, owner.c_str(), CALL_SIZE-1))
		{
			/* is that the remote system that we asked to connect to? */
			if (fromDst4==to_remote_g2[i].addr && to_remote_g2[i].addr.GetPort()==rmt_dcs_port && 0==memcmp(to_remote_g2[i].cs, dcs_buf, 7) && to_remote_g2[i].to_mod==dcs_buf[7])
			{
				if (!to_remote_g2[i].is_connected)
				{
					tracing[i].last_time = time(NULL);

					to_remote_g2[i].is_connected = true;
					printf("Connected from: %.*s\n", 8, dcs_buf);
					qnDB.UpdateLS(to_remote_g2[i].addr.GetAddress(), to_remote_g2[i].from_mod, to_remote_g2[i].cs, to_remote_g2[i].to_mod, tracing[i].last_time);

					char linked_remote_system[CALL_SIZE + 1];
					strcpy(linked_remote_system, to_remote_g2[i].cs);
					auto space_p = strchr(linked_remote_system, ' ');
					if (space_p)
						*space_p = '\0';
					sprintf(notify_msg[i], "%c_linked.dat_LINKED_%s_%c", to_remote_g2[i].from_mod, linked_remote_system, to_remote_g2[i].to_mod);
				}
				to_remote_g2[i].countdown = TIMEOUT;
			}
		}
	}
	else if (length == 14)  	/* is this a reply to our link/unlink request: 14 bytes */
	{
		int i = -1;
		if (dcs_buf[8] == 'A')
			i = 0;
		else if (dcs_buf[8] == 'B')
			i = 1;
		else if (dcs_buf[8] == 'C')
			i = 2;

		/* It is one of our valid repeaters */
		if ((i >= 0) && (memcmp(dcs_buf, owner.c_str(), CALL_SIZE) == 0))
		{
			/* It is from a remote that we contacted */
			if ((fromDst4==to_remote_g2[i].addr) && (to_remote_g2[i].addr.GetPort()==rmt_dcs_port) && (to_remote_g2[i].from_mod == dcs_buf[8]))
			{
				if ((to_remote_g2[i].to_mod == dcs_buf[9]) && (memcmp(dcs_buf + 10, "ACK", 3) == 0))
				{
					to_remote_g2[i].countdown = TIMEOUT;
					if (!to_remote_g2[i].is_connected)
					{
						tracing[i].last_time = time(NULL);

						to_remote_g2[i].is_connected = true;
						printf("Connected from: %.*s\n", 8, to_remote_g2[i].cs);
						qnDB.UpdateLS(to_remote_g2[i].addr.GetAddress(), to_remote_g2[i].from_mod, to_remote_g2[i].cs, to_remote_g2[i].from_mod, tracing[i].last_time);

						char linked_remote_system[CALL_SIZE + 1];
						strcpy(linked_remote_system, to_remote_g2[i].cs);
						auto space_p = strchr(linked_remote_system, ' ');
						if (space_p)
							*space_p = '\0';
						sprintf(notify_msg[i], "%c_linked.dat_LINKED_%s_%c", to_remote_g2[i].from_mod, linked_remote_system, to_remote_g2[i].to_mod);
					}
				}
				else if (memcmp(dcs_buf + 10, "NAK", 3) == 0)
				{
					printf("Link module %c to [%s] %c is unlinked\n", to_remote_g2[i].from_mod, to_remote_g2[i].cs, to_remote_g2[i].to_mod);

					sprintf(notify_msg[i], "%c_failed_link.dat_UNLINKED", to_remote_g2[i].from_mod);
					qnDB.DeleteLS(to_remote_g2[i].addr.GetAddress());
					to_remote_g2[i].cs[0] = '\0';
					to_remote_g2[i].addr.Clear();
					to_remote_g2[i].from_mod = to_remote_g2[i].to_mod = ' ';
					to_remote_g2[i].countdown = 0;
					to_remote_g2[i].is_connected = false;
					to_remote_g2[i].in_streamid = 0x0;
				}
			}
		}
	}
}

void CQnetLink::ProcessREF(unsigned char *buf, const int length)
{
	const std::string ip(fromDst4.GetAddress());

	bool found = false;

	/* LH */
	if (length==4 && buf[0]==4 && buf[1]==192 && buf[2]==7 && buf[3]==0)
	{
		unsigned short j_idx = 0;
		unsigned short k_idx = 0;
		unsigned char tmp[2];

		auto pos = inbound_list.find(ip);
		if (pos != inbound_list.end())
		{
			//SINBOUND *inbound = (SINBOUND *)pos->second;
			// printf("Remote station %s %s requested LH list\n", inbound_ptr->call, ip);

			/* header is 10 bytes */

			/* reply type */
			buf[2] = 7;
			buf[3] = 0;

			/* it looks like time_t here */
			time(&tnow);
			memcpy(buf + 6, (char *)&tnow, sizeof(time_t));

			for (auto r_dt_lh_pos = dt_lh_list.rbegin(); r_dt_lh_pos != dt_lh_list.rend();  r_dt_lh_pos++)
			{
				/* each entry has 24 bytes */

				/* start at position 10 to bypass the header */
				strcpy((char *)buf + 10 + (24 * j_idx), r_dt_lh_pos->second.c_str());
				auto p = strchr((char *)r_dt_lh_pos->first.c_str(), '=');
				if (p)
				{
					memcpy((char *)buf + 18 + (24 * j_idx), p + 2, 8);

					/* if local or local w/gps */
					if (p[1]=='l' || p[1]=='g')
						buf[18 + (24 * j_idx) + 6] = *(p + 1);

					*p = '\0';
					tnow = atol(r_dt_lh_pos->first.c_str());
					*p = '=';
					memcpy(buf + 26 + (24 * j_idx), &tnow, sizeof(time_t));
				}
				else
				{
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
				if (j_idx == 39)
				{
					/* 39 * 24 = 936 + 10 header = 946 */
					buf[0] = 0xb2;
					buf[1] = 0xc3;

					/* 39 entries */
					buf[4] = 0x27;
					buf[5] = 0x00;

					REFWrite(buf, 946, fromDst4);

					j_idx = 0;
				}
			}

			if (j_idx != 0)
			{
				k_idx = 10 + (j_idx * 24);
				memcpy(tmp, (char *)&k_idx, 2);
				buf[0] = tmp[0];
				buf[1] = tmp[1] | 0xc0;

				memcpy(tmp, (char *)&j_idx, 2);
				buf[4] = tmp[0];
				buf[5] = tmp[1];

				REFWrite(buf, k_idx, fromDst4);
			}
		}
		/* linked repeaters request */
	}
	else if (length==4 && buf[0]==4 && buf[1]==192 && buf[2]==5 && buf[3]==0)
	{
		if (log_debug)
			printf("Got a linked repeater request!\n");
		unsigned short i_idx = 0;
		unsigned short j_idx = 0;
		unsigned short k_idx = 0;
		unsigned char tmp[2];
		unsigned short total = 0;

		auto pos = inbound_list.find(ip);
		if (pos != inbound_list.end())
		{
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

			for (int i=0, i_idx=0; i<3;  i++, i_idx++)
			{
				/* each entry has 20 bytes */
				if (to_remote_g2[i].to_mod != ' ')
				{
					if (i == 0)
						buf[8 + (20 * j_idx)] = 'A';
					else if (i == 1)
						buf[8 + (20 * j_idx)] = 'B';
					else if (i == 2)
						buf[8 + (20 * j_idx)] = 'C';

					strcpy((char *)buf + 9 + (20 * j_idx), to_remote_g2[i].cs);
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

					if (j_idx == 39)
					{
						/* 20 bytes for each user, so 39 * 20 = 780 bytes + 8 bytes header = 788 */
						buf[0] = 0x14;
						buf[1] = 0xc3;

						k_idx = i_idx - 38;
						memcpy(tmp, (char *)&k_idx, 2);
						buf[4] = tmp[0];
						buf[5] = tmp[1];

						REFWrite(buf, 788, fromDst4);
						j_idx = 0;
					}
				}
			}

			if (j_idx != 0)
			{
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

				REFWrite(buf, 8+(j_idx*20), fromDst4);
			}
		}
		/* connected user list request */
	}
	else if (length==4 && buf[0]==4 && buf[1]==192 && buf[2]==6 && buf[3]==0)
	{
		if (log_debug)
			printf("Got a linked dongle request!!\n");
		unsigned short i_idx = 0;
		unsigned short j_idx = 0;
		unsigned short k_idx = 0;
		unsigned char tmp[2];
		unsigned short total = 0;

		auto pos = inbound_list.find(ip);
		if (pos != inbound_list.end())
		{
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

			for (pos = inbound_list.begin(), i_idx = 0; pos != inbound_list.end();  pos++, i_idx++)
			{
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

				if (j_idx == 39)
				{
					/* 20 bytes for each user, so 39 * 20 = 788 bytes + 8 bytes header = 788 */
					buf[0] = 0x14;
					buf[1] = 0xc3;

					k_idx = i_idx - 38;
					memcpy(tmp, (char *)&k_idx, 2);
					buf[4] = tmp[0];
					buf[5] = tmp[1];

					REFWrite(buf, 788, fromDst4);

					j_idx = 0;
				}
			}

			if (j_idx != 0)
			{
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

				REFWrite(buf, 8+(j_idx*20), fromDst4);
			}
		}
		/* date request */
	}
	else if (length== 4 && buf[0]==4 && buf[1]==192 && buf[2]==8 && buf[3]==0)
	{
		if (log_debug)
			printf("Got a dongle time request!!\n");
		time_t ltime;
		struct tm tm;

		auto pos = inbound_list.find(ip);
		if (pos != inbound_list.end())
		{
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

			REFWrite(buf, 34, fromDst4);
		}
		/* version request */
	}
	else if (length== 4 && buf[0]==4 && buf[1]==192 && buf[2]==3 && buf[3]==0)
	{
		if (log_debug)
			printf("Got a version request!!\n");
		auto pos = inbound_list.find(ip);
		if (pos != inbound_list.end())
		{
			//SINBOUND *inbound = (SINBOUND *)pos->second;
			// printf("Remote station %s %s requested version\n", inbound_ptr->call, ip);

			buf[0] = 9;
			memcpy((char *)buf + 4, "1.00", 4);
			buf[8] = 0;

			REFWrite(buf, 9, fromDst4);
		}
	}
	else if (length==5 && buf[0]==5 && buf[1]==0 && buf[2]==24 && buf[3]==0 && buf[4]==0)
	{
		if (log_debug)
			printf("Got a disconnect request!!\n");
		/* reply with the same DISCONNECT */
		REFWrite(buf, 5, fromDst4);

		for (int i=0; i<3; i++)
		{
			if (fromDst4==to_remote_g2[i].addr && to_remote_g2[i].addr.GetPort()==rmt_ref_port)
			{
				printf("Call %s disconnected\n", to_remote_g2[i].cs);

				to_remote_g2[i].cs[0] = '\0';
				to_remote_g2[i].addr.Clear();
				to_remote_g2[i].from_mod = to_remote_g2[i].to_mod = ' ';
				to_remote_g2[i].countdown = 0;
				to_remote_g2[i].is_connected = false;
				to_remote_g2[i].in_streamid = 0x0;
			}
		}

		auto pos = inbound_list.find(ip);
		if (pos != inbound_list.end())
		{
			qnDB.DeleteLS(pos->first.c_str());
			SINBOUND *inbound = pos->second;
			if (memcmp(inbound->call, "1NFO", 4) != 0)
				printf("Call %s disconnected\n", inbound->call);
			delete pos->second;
			inbound_list.erase(pos);
		}
	}

	for (int i=0; i<3; i++)
	{
		if (fromDst4==to_remote_g2[i].addr && to_remote_g2[i].addr.GetPort()==rmt_ref_port)
		{
			found = true;
			if (length==5 && buf[0]==5 && buf[1]==0 && buf[2]==24 && buf[3]==0 && buf[4]==1)
			{
				printf("Connected to call %s\n", to_remote_g2[i].cs);
				queryCommand[0] = 28;
				queryCommand[1] = 192;
				queryCommand[2] = 4;
				queryCommand[3] = 0;

				memcpy(queryCommand + 4, login_call.c_str(), CALL_SIZE);
				for (int j=11; j>3; j--)
				{
					if (queryCommand[j] == ' ')
						queryCommand[j] = '\0';
					else
						break;
				}
				memset(queryCommand + 12, '\0', 8);
				memcpy(queryCommand + 20, "DV019999", 8);

				// ATTENTION: I should ONLY send once for each distinct
				// remote IP, so  get out of the loop immediately
				REFWrite(queryCommand, 28, to_remote_g2[i].addr);

				break;
			}
		}
	}

	for (int i=0; i<3; i++)
	{
		if ((fromDst4==to_remote_g2[i].addr) && (to_remote_g2[i].addr.GetPort()==rmt_ref_port))
		{
			found = true;
			if (length==8 && buf[0]==8 && buf[1]==192 && buf[2]==4 && buf[3]==0)
			{
				if (buf[4]== 79 && buf[5]==75 && buf[6]==82)
				{
					if (!to_remote_g2[i].is_connected)
					{
						to_remote_g2[i].is_connected = true;
						to_remote_g2[i].countdown = TIMEOUT;
						printf("Login OK to call %s mod %c\n", to_remote_g2[i].cs, to_remote_g2[i].to_mod);

						tracing[i].last_time = time(NULL);
						qnDB.UpdateLS(to_remote_g2[i].addr.GetAddress(), to_remote_g2[i].from_mod, to_remote_g2[i].cs, to_remote_g2[i].to_mod, tracing[i].last_time);

						char linked_remote_system[CALL_SIZE + 1];
						strcpy(linked_remote_system, to_remote_g2[i].cs);
						auto space_p = strchr(linked_remote_system, ' ');
						if (space_p)
							*space_p = '\0';
						sprintf(notify_msg[i], "%c_linked.dat_LINKED_%s_%c", to_remote_g2[i].from_mod, linked_remote_system, to_remote_g2[i].to_mod);
					}
				}
				else if (buf[4]==70 && buf[5]==65 && buf[6]==73 && buf[7]==76)
				{
					printf("Login failed to call %s mod %c\n", to_remote_g2[i].cs, to_remote_g2[i].to_mod);

					sprintf(notify_msg[i], "%c_failed_link.dat_FAILED_TO_LINK", to_remote_g2[i].from_mod);

					to_remote_g2[i].cs[0] = '\0';
					to_remote_g2[i].addr.Clear();
					to_remote_g2[i].from_mod = to_remote_g2[i].to_mod = ' ';
					to_remote_g2[i].countdown = 0;
					to_remote_g2[i].is_connected = false;
					to_remote_g2[i].in_streamid = 0x0;
				}
				else if (buf[4]==66 && buf[5]==85 && buf[6]==83 && buf[7]==89)
				{
					printf("Busy or unknown status from call %s mod %c\n", to_remote_g2[i].cs, to_remote_g2[i].to_mod);

					sprintf(notify_msg[i], "%c_failed_link.dat_FAILED_TO_LINK", to_remote_g2[i].from_mod);

					to_remote_g2[i].cs[0] = '\0';
					to_remote_g2[i].addr.Clear();
					to_remote_g2[i].from_mod = to_remote_g2[i].to_mod = ' ';
					to_remote_g2[i].countdown = 0;
					to_remote_g2[i].is_connected = false;
					to_remote_g2[i].in_streamid = 0x0;
				}
			}
		}
	}

	for (int i=0; i<3; i++)
	{
		if ((fromDst4==to_remote_g2[i].addr) && (to_remote_g2[i].addr.GetPort()==rmt_ref_port))
		{
			found = true;
			if (length==24 && buf[0]==24 && buf[1]==192 && buf[2]==3 && buf[3]==0)
			{
				to_remote_g2[i].countdown = TIMEOUT;
			}
		}
	}

	for (int i=0; i<3; i++)
	{
		if (fromDst4==to_remote_g2[i].addr && to_remote_g2[i].addr.GetPort()==rmt_ref_port)
		{
			found = true;
			if (length == 3)
				to_remote_g2[i].countdown = TIMEOUT;
		}
	}

	/* find out if it is a connected dongle */
	auto pos = inbound_list.find(ip);
	if (pos != inbound_list.end())
	{
		SINBOUND *inbound = (SINBOUND *)pos->second;
		found = true;
		inbound->countdown = TIMEOUT;
		/*** ip is same, do not update port
		memcpy((char *)&(inbound_ptr->sin),(char *)&fromDst4, sizeof(struct sockaddr_in));
		***/
	}

	if (!found)
	{
		/*
			The incoming packet is not in the list of outbound repeater connections.
			and it is not a connected dongle.
			In this case, this must be an INCOMING dongle request
		*/
		if (length==5 && buf[0]==5 && buf[1]==0 && buf[2]==24 && buf[3]==0 && buf[4]==1)
		{
			if ((inbound_list.size() + 1) > max_dongles)
				printf("Inbound DONGLE-p connection from %s but over the max_dongles limit of %d\n", ip.c_str(), (int)inbound_list.size());
			else
				REFWrite(buf, 5, fromDst4);
		}
		else if (length==28 && buf[0]==28 && buf[1]==192 && buf[2]==4 && buf[3]==0)
		{
			/* verify callsign */
			char call[CALL_SIZE + 1];
			memcpy(call, buf + 4, CALL_SIZE);
			call[CALL_SIZE] = '\0';
			for (int i=7; i>0; i--)
			{
				if (call[i] == '\0')
					call[i] = ' ';
				else
					break;
			}

			if (memcmp(call, "1NFO", 4))
				printf("Inbound DONGLE-p CALL=%s, ip=%s, DV=%.8s\n", call, ip.c_str(), buf + 20);

			if ((inbound_list.size() + 1) > max_dongles)
				printf("Inbound DONGLE-p connection from %s but over the max_dongles limit of %d\n", ip.c_str(), (int)inbound_list.size());
			//else if (admin.size() && (admin.find(call) == admin.end()))
			//	printf("Incoming call [%s] from %s not an ADMIN\n", call, ip.c_str());
			else if (regexec(&preg, call, 0, NULL, 0) != 0)
			{
				printf("Invalid dongle callsign: CALL=%s,ip=%s\n", call, ip.c_str());

				buf[0] = 8;
				buf[4] = 70;
				buf[5] = 65;
				buf[6] = 73;
				buf[7] = 76;

				REFWrite(buf, 8, fromDst4);
			}
			else
			{
				/* add the dongle to the inbound list */
				SINBOUND *inbound = new SINBOUND;
				if (inbound)
				{
					inbound->countdown = TIMEOUT;
					inbound->addr = fromDst4;
					strcpy(inbound->call, call);

					inbound->mod = ' ';

					if (memcmp(buf + 20, "AP", 2) == 0)
						inbound->client = 'A';  /* dvap */
					else if (memcmp(buf + 20, "DV019999", 8) == 0)
						inbound->client = 'H';  /* spot */
					else
						inbound->client = 'D';  /* dongle */

					auto insert_pair = inbound_list.insert(std::pair<std::string, SINBOUND *>(ip, inbound));
					if (insert_pair.second)
					{
						if (memcmp(inbound->call, "1NFO", 4) != 0)
							printf("new CALL=%s, DONGLE-p, ip=%s, users=%d\n", inbound->call, ip.c_str(), (int)inbound_list.size());

						buf[0] = 8;
						memcpy(buf+4, "OKAY", 4);

						REFWrite(buf, 8, fromDst4);
						qnDB.UpdateLS(ip.c_str(), 'p', inbound->call, 'p', time(NULL));

					}
					else
					{
						printf("failed to add CALL=%s,ip=%s\n", inbound->call, ip.c_str());
						delete inbound;

						buf[0] = 8;
						memcpy(buf+4, "FAIL", 4);

						REFWrite(buf, 8, fromDst4);
					}
				}
				else
				{
					printf("new SINBOUND failed for call=%s,ip=%s\n", call, ip.c_str());

					buf[0] = 8;
					memcpy(buf+4, "FAIL", 4);

					REFWrite(buf, 8, fromDst4);
				}
			}
		}
	}

	if ((length==58 || length==29 || length==32) && 0==memcmp(buf + 2, "DSVT", 4) && (buf[6]==0x10 || buf[6]==0x20) && buf[10]==0x20)
	{
		/* Is it one of the donglers or repeaters-reflectors */
		found = false;
		for (int i=0; i<3; i++)
		{
			if (fromDst4==to_remote_g2[i].addr && to_remote_g2[i].addr.GetPort()==rmt_ref_port)
			{
				to_remote_g2[i].countdown = TIMEOUT;
				found = true;
			}
		}
		if (!found)
		{
			auto pos = inbound_list.find(ip);
			if (pos != inbound_list.end())
			{
				SINBOUND *inbound = (SINBOUND *)pos->second;
				inbound->countdown = TIMEOUT;
				found = true;
			}
		}

		SREFDSVT rdsvt;
		memcpy(rdsvt.head, buf, length);	// copy to struct

		if (length==58 && found)
		{
			char source_stn[9];
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
			for (i=0; i<3; i++)
			{
				if (fromDst4==to_remote_g2[i].addr && to_remote_g2[i].addr.GetPort()==rmt_ref_port &&
						(
							(0==memcmp(rdsvt.dsvt.hdr.rpt1, to_remote_g2[i].cs, 7) && rdsvt.dsvt.hdr.rpt1[7]==to_remote_g2[i].to_mod)  ||
							(0==memcmp(rdsvt.dsvt.hdr.rpt2, to_remote_g2[i].cs, 7) && rdsvt.dsvt.hdr.rpt2[7]==to_remote_g2[i].to_mod)
						))
				{
					memcpy(rdsvt.dsvt.hdr.rpt1, owner.c_str(), CALL_SIZE);
					rdsvt.dsvt.hdr.rpt1[7] = to_remote_g2[i].from_mod;
					memcpy(rdsvt.dsvt.hdr.urcall, "CQCQCQ  ", CALL_SIZE);

					memcpy(source_stn, to_remote_g2[i].cs, CALL_SIZE);
					source_stn[7] = to_remote_g2[i].to_mod;

					break;
				}
			}

			if (i == 3)
			{
				pos = inbound_list.find(ip);
				if (pos != inbound_list.end())
				{
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
			if (0==memcmp(rdsvt.dsvt.hdr.rpt1, owner.c_str(), CALL_SIZE-1) && i>=0)
			{
				/* Last Heard */
				if (old_sid[i].sid != rdsvt.dsvt.streamid)
				{
					if (qso_details)
						printf("START from remote g2: streamID=%04x, flags=%02x:%02x:%02x, my=%.8s, sfx=%.4s, ur=%.8s, rpt1=%.8s, rpt2=%.8s, %d bytes fromIP=%s, source=%.8s\n",
							   ntohs(rdsvt.dsvt.streamid), rdsvt.dsvt.hdr.flag[0], rdsvt.dsvt.hdr.flag[0], rdsvt.dsvt.hdr.flag[0],
							   rdsvt.dsvt.hdr.mycall, rdsvt.dsvt.hdr.sfx, rdsvt.dsvt.hdr.urcall, rdsvt.dsvt.hdr.rpt1, rdsvt.dsvt.hdr.rpt2,
							   length, fromDst4.GetAddress(), source_stn);

					// put user into tmp1
					char tmp1[CALL_SIZE + 1];
					memcpy(tmp1, rdsvt.dsvt.hdr.mycall, 8);
					tmp1[8] = '\0';

					// delete the user if exists
					for (auto dt_lh_pos = dt_lh_list.begin(); dt_lh_pos != dt_lh_list.end();  dt_lh_pos++)
					{
						if (strcmp((char *)dt_lh_pos->second.c_str(), tmp1) == 0)
						{
							dt_lh_list.erase(dt_lh_pos);
							break;
						}
					}
					/* Limit?, delete oldest user */
					if (dt_lh_list.size() == LH_MAX_SIZE)
					{
						auto dt_lh_pos = dt_lh_list.begin();
						dt_lh_list.erase(dt_lh_pos);
					}
					// add user
					time(&tnow);
					char tmp2[36];
					sprintf(tmp2, "%ld=r%.6s%c%c", tnow, source_stn, source_stn[7], rdsvt.dsvt.hdr.rpt1[7]);
					dt_lh_list[tmp2] = tmp1;

					old_sid[i].sid = rdsvt.dsvt.streamid;
				}

				/* send the data to the local gateway/repeater */
				ToGate.Write(rdsvt.dsvt.title, 56);

				/* send the data to the donglers */
				for (auto pos = inbound_list.begin(); pos != inbound_list.end(); pos++)
				{
					SINBOUND *inbound = (SINBOUND *)pos->second;
					if (fromDst4 == inbound->addr)
						inbound->mod = rdsvt.dsvt.hdr.rpt1[7];
					else
						REFWrite(rdsvt.head, 58, inbound->addr);
				}

				if ((to_remote_g2[i].addr != fromDst4) && to_remote_g2[i].is_connected)
				{
					if ( /*** (memcmp(readBuffer2 + 44, owner, 8) != 0) && ***/         /* block repeater announcements */
						0==memcmp(rdsvt.dsvt.hdr.urcall, "CQCQCQ", 6) &&	/* CQ calls only */
						(rdsvt.dsvt.hdr.flag[0]==0x00 ||	/* normal */
						 rdsvt.dsvt.hdr.flag[0]==0x08 ||	/* EMR */
						 rdsvt.dsvt.hdr.flag[0]==0x20 ||	/* BK */
						 rdsvt.dsvt.hdr.flag[7]==0x28) &&	/* EMR + BK */
						0==memcmp(rdsvt.dsvt.hdr.rpt2, owner.c_str(), CALL_SIZE-1) &&         /* rpt2 must be us */
						rdsvt.dsvt.hdr.rpt2[7] == 'G')
					{
						to_remote_g2[i].in_streamid = rdsvt.dsvt.streamid;

						if (to_remote_g2[i].addr.GetPort()==rmt_xrf_port || to_remote_g2[i].addr.GetPort()==rmt_ref_port)
						{
							memcpy(rdsvt.dsvt.hdr.rpt1, to_remote_g2[i].cs, CALL_SIZE);
							rdsvt.dsvt.hdr.rpt1[7] = to_remote_g2[i].to_mod;
							memcpy(rdsvt.dsvt.hdr.rpt2, to_remote_g2[i].cs, CALL_SIZE);
							rdsvt.dsvt.hdr.rpt2[7] = 'G';
							calcPFCS(rdsvt.dsvt.title, 56);

							if (to_remote_g2[i].addr.GetPort() == rmt_xrf_port)
							{
								/* inform XRF about the source */
								rdsvt.dsvt.flagb[2] = to_remote_g2[i].from_mod;
								XRFWrite(rdsvt.dsvt.title, 56, to_remote_g2[i].addr);
							}
							else
								REFWrite(rdsvt.head, 58, to_remote_g2[i].addr);
						}
						else if (to_remote_g2[i].addr.GetPort() == rmt_dcs_port)
						{
							memcpy(ref_2_dcs[i].mycall, rdsvt.dsvt.hdr.mycall, 8);
							memcpy(ref_2_dcs[i].sfx, rdsvt.dsvt.hdr.sfx, 4);
							ref_2_dcs[i].dcs_rptr_seq = 0;
						}
					}
				}
			}
		}
		else if (found)
		{
			if (rdsvt.dsvt.ctrl & 0x40U)
			{
				for (int i=0; i<3; i++)
				{
					if (old_sid[i].sid == rdsvt.dsvt.streamid)
					{
						if (qso_details)
							printf("END from remote g2: streamID=%04x, %d bytes from IP=%s\n", ntohs(rdsvt.dsvt.streamid), length, fromDst4.GetAddress());

						old_sid[i].sid = 0x0;

						break;
					}
				}
			}

			/* send the data to the local gateway/repeater */
			ToGate.Write(rdsvt.dsvt.title, 27);

			/* send the data to the donglers */
			for (pos = inbound_list.begin(); pos != inbound_list.end(); pos++)
			{
				SINBOUND *inbound = (SINBOUND *)pos->second;
				if (fromDst4 != inbound->addr)
				{
					REFWrite(rdsvt.head, rdsvt.head[0], inbound->addr);
				}
			}

			for (int i=0; i<3; i++)
			{
				if (to_remote_g2[i].is_connected && (to_remote_g2[i].addr != fromDst4) && to_remote_g2[i].in_streamid==rdsvt.dsvt.streamid)
				{
					if (to_remote_g2[i].addr.GetPort() == rmt_xrf_port)
					{
						/* inform XRF about the source */
						rdsvt.dsvt.flagb[2] = to_remote_g2[i].from_mod;
						XRFWrite(rdsvt.dsvt.title, 27, to_remote_g2[i].addr);
					}
					else if (to_remote_g2[i].addr.GetPort() == rmt_ref_port)
						REFWrite(rdsvt.head, rdsvt.head[0],  to_remote_g2[i].addr);
					else if (to_remote_g2[i].addr.GetPort() == rmt_dcs_port)
					{
						unsigned char dcs_buf[600];
						memset(dcs_buf, 0x00, 600);
						dcs_buf[0] = dcs_buf[1] = dcs_buf[2] = '0';
						dcs_buf[3] = '1';
						dcs_buf[4] = dcs_buf[5] = dcs_buf[6] = 0x0;
						memcpy(dcs_buf + 7, to_remote_g2[i].cs, 8);
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

						DCSWrite(dcs_buf, 100, to_remote_g2[i].addr);
					}

					if (rdsvt.dsvt.ctrl & 0x40)
					{
						to_remote_g2[i].in_streamid = 0x0;
					}
					break;
				}
			}
		}
	}
}

void CQnetLink::Process()
{
	tnow = 0;
	auto heartbeat = time(NULL);

	if (uses_ipv6)
		printf("xrf6=%d, dcs6=%d, ref6=%d ", XRFSock6.GetSocket(), DCSSock6.GetSocket(), REFSock6.GetSocket());
	printf("xrf4=%d, dcs4=%d, ref4=%d, gateway=%d\n", XRFSock4.GetSocket(), DCSSock4.GetSocket(), REFSock4.GetSocket(), ToGate.GetFD());

	// initialize all request links
	bool first = true;
	for (int i=0; i<3; i++)
	{
		if (8 == link_at_startup[i].length())
		{
			if (first)
			{
				printf("sleep for 15 sec before link at startup\n");
				sleep(15);
				first = false;
			}
			std::string node(link_at_startup[i].substr(0, 6));
			node.resize(CALL_SIZE, ' ');
			g2link('A'+i, node.c_str(), link_at_startup[i].at(7));
		}
	}

	while (keep_running)
	{
		static bool loadG[3] = { false, false, false };
		time(&tnow);
		if (keep_running && (tnow - heartbeat) > 0)
		{
			send_heartbeat();
			time(&heartbeat);
		}

		// play a qnvoice file if it is specified
		// this could be coming from qnvoice or qngateway (connected2network or notincache)
		std::ifstream voicefile(qnvoice_file.c_str(), std::ifstream::in);
		if (voicefile)
		{
			if (keep_running)
			{
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

		int max_nfds = -1;
		fd_set fdset;
		FD_ZERO(&fdset);
		AddFDSet(max_nfds, XRFSock4.GetSocket(), &fdset);
		AddFDSet(max_nfds, DCSSock4.GetSocket(), &fdset);
		AddFDSet(max_nfds, REFSock4.GetSocket(), &fdset);
		if (uses_ipv6)
		{
			AddFDSet(max_nfds, XRFSock6.GetSocket(), &fdset);
			AddFDSet(max_nfds, DCSSock6.GetSocket(), &fdset);
			AddFDSet(max_nfds, REFSock6.GetSocket(), &fdset);
		}
		AddFDSet(max_nfds, ToGate.GetFD(), &fdset);
		tv.tv_sec = 0;
		tv.tv_usec = 20000;
		auto sval = select(max_nfds + 1, &fdset, 0, 0, &tv);
		if (0 > sval)
		{
			fprintf(stderr, "select error: %s\n", strerror(errno));
			keep_running = false;
		}

		unsigned char buffer[1000];
		if (keep_running && FD_ISSET(XRFSock4.GetSocket(), &fdset))
		{
			socklen_t fromlen = sizeof(struct sockaddr_storage);
			int length = XRFSock4.Read(buffer, 1000, fromDst4);
			ProcessXRF(buffer, length);
			FD_CLR(XRFSock4.GetSocket(), &fdset);
		}

		if (keep_running && FD_ISSET(REFSock4.GetSocket(), &fdset))
		{
			socklen_t fromlen = sizeof(struct sockaddr_storage);
			int length = REFSock4.Read(buffer, 1000, fromDst4);
			ProcessREF(buffer, length);
			FD_CLR (REFSock4.GetSocket(), &fdset);
		}

		if (keep_running && FD_ISSET(DCSSock4.GetSocket(), &fdset))
		{
			socklen_t fromlen = sizeof(struct sockaddr_storage);
			int length = DCSSock4.Read(buffer, 1000, fromDst4);
			ProcessDCS(buffer, length);
			FD_CLR(DCSSock4.GetSocket(), &fdset);
		}

		if (uses_ipv6)
		{
			if (keep_running && FD_ISSET(XRFSock6.GetSocket(), &fdset))
			{
				socklen_t fromlen = sizeof(struct sockaddr_storage);
				int length = XRFSock6.Read(buffer, 1000, fromDst4);
				ProcessXRF(buffer, length);
				FD_CLR(XRFSock6.GetSocket(), &fdset);
			}

			if (keep_running && FD_ISSET(REFSock6.GetSocket(), &fdset))
			{
				socklen_t fromlen = sizeof(struct sockaddr_storage);
				int length = REFSock6.Read(buffer, 1000, fromDst4);
				ProcessREF(buffer, length);
				FD_CLR (REFSock6.GetSocket(), &fdset);
			}

			if (keep_running && FD_ISSET(DCSSock6.GetSocket(), &fdset))
			{
				socklen_t fromlen = sizeof(struct sockaddr_storage);
				int length = DCSSock6.Read(buffer, 1000, fromDst4);
				ProcessDCS(buffer, length);
				FD_CLR(DCSSock6.GetSocket(), &fdset);
			}
		}

		if (keep_running && FD_ISSET(ToGate.GetFD(), &fdset))
		{
			unsigned char your[3] = { 'C', 'C', 'C' };
			SDSVT dsvt;
			int length = ToGate.Read(dsvt.title, 56);

			if ((length==56 || length==27) && 0==memcmp(dsvt.title,"DSVT", 4U) && dsvt.id==0x20U && (dsvt.config==0x10U || dsvt.config==0x20U))
			{

				if (length == 56)
				{
					if (qso_details)
						printf("START from local g2: streamID=%04x, flags=%02x:%02x:%02x, my=%.8s/%.4s, ur=%.8s, rpt1=%.8s, rpt2=%.8s, %d bytes on %s\n", ntohs(dsvt.streamid), dsvt.hdr.flag[0], dsvt.hdr.flag[1], dsvt.hdr.flag[2], dsvt.hdr.mycall, dsvt.hdr.sfx, dsvt.hdr.urcall, dsvt.hdr.rpt1, dsvt.hdr.rpt2, length, togate.c_str());

					// save mycall
					char call[CALL_SIZE + 1];
					memcpy(call, dsvt.hdr.mycall, 8);
					call[8] = '\0';

					int i = -1;
					if (dsvt.hdr.rpt1[7] == 'A')
						i = 0;
					else if (dsvt.hdr.rpt1[7] == 'B')
						i = 1;
					else if (dsvt.hdr.rpt1[7] == 'C')
						i = 2;

					if (i >= 0)
					{
						// save the first char of urcall
						your[i] = dsvt.hdr.urcall[0];	// used by rptr_ack
						memcpy(dtmf_mycall[i], dsvt.hdr.mycall, 8);
						dtmf_mycall[i][8] = '\0';

						new_group[i] = true;
						GPS_seen[i] = false;

						/* Last Heard */
						//put user into tmp1
						char tmp1[CALL_SIZE + 1];
						memcpy(tmp1, dsvt.hdr.mycall, 8);
						tmp1[8] = '\0';

						// delete the user if exists
						for (auto dt_lh_pos=dt_lh_list.begin(); dt_lh_pos!=dt_lh_list.end();  dt_lh_pos++)
						{
							if (strcmp(dt_lh_pos->second.c_str(), tmp1) == 0)
							{
								dt_lh_list.erase(dt_lh_pos);
								break;
							}
						}
						/* Limit?, delete oldest user */
						if (dt_lh_list.size() == LH_MAX_SIZE)
						{
							auto dt_lh_pos = dt_lh_list.begin();
							dt_lh_list.erase(dt_lh_pos);
						}
						/* add user */
						time(&tnow);
						char tmp2[36];
						sprintf(tmp2, "%ld=l%.8s", tnow, dsvt.hdr.rpt1);
						dt_lh_list[tmp2] = tmp1;

						tracing[i].streamid = dsvt.streamid;
						tracing[i].last_time = time(NULL);
					}

					if (memcmp(dsvt.hdr.urcall, "CQCQCQ", 6) && i>=0)
					{
						if (memcmp(dsvt.hdr.urcall, owner.c_str(), CALL_SIZE-1) && dsvt.hdr.urcall[0] != ' ' && dsvt.hdr.urcall[7] == 'L' && 0==memcmp(dsvt.hdr.rpt2, owner.c_str(), CALL_SIZE-1) && dsvt.hdr.rpt2[7] == 'G' && (dsvt.hdr.flag[0]==0x00 || dsvt.hdr.flag[0]==0x08 || dsvt.hdr.flag[0]==0x20 || dsvt.hdr.flag[0]==0x28))
						{
							if (
								// if there is a black list, is he in the blacklist?
								(link_blacklist.size() && link_blacklist.end()!=link_blacklist.find(call)) ||
								// or if there is an allow list, is he not in it?
								(link_unlink_user.size() && link_unlink_user.find(call)==link_unlink_user.end())
							)
							{
								printf("link request denied, unauthorized user [%s]\n", call);
							}
							else
							{
								char temp_repeater[CALL_SIZE + 1];
								memset(temp_repeater, ' ', CALL_SIZE);
								memcpy(temp_repeater, dsvt.hdr.urcall, CALL_SIZE - 2);
								temp_repeater[CALL_SIZE] = '\0';

								if ((to_remote_g2[i].cs[0] == '\0') ||   /* not linked */
										((to_remote_g2[i].cs[0] != '\0') &&  /* waiting for a link reply that may never arrive */
										 !to_remote_g2[i].is_connected))

									g2link(dsvt.hdr.rpt1[7], temp_repeater, dsvt.hdr.urcall[6]);
								else if (to_remote_g2[i].is_connected)
								{
									char linked_remote_system[CALL_SIZE + 1];
									strcpy(linked_remote_system, to_remote_g2[i].cs);
									auto space_p = strchr(linked_remote_system, ' ');
									if (space_p)
										*space_p = '\0';
									sprintf(notify_msg[i], "%c_already_linked.dat_LINKED_%s_%c", to_remote_g2[i].from_mod, linked_remote_system, to_remote_g2[i].to_mod);
								}
							}
						}
						else if (0==memcmp(dsvt.hdr.urcall, "       U", CALL_SIZE))
						{
							if (
								// if there is a black list, is he in the blacklist?
								(link_blacklist.size() && link_blacklist.end()!=link_blacklist.find(call)) ||
								// or if there is an allow list, is he not in it?
								(link_unlink_user.size() && link_unlink_user.find(call)==link_unlink_user.end())
							)
							{
								printf("unlink request denied, unauthorized user [%s]\n", call);
							}
							else
							{
								if (to_remote_g2[i].cs[0] != '\0')
								{
									if (to_remote_g2[i].addr.GetPort() == rmt_ref_port)
									{
										/* Check to see if any other local bands are linked to that same IP */
										int j;
										for (j=0; j<3; j++)
										{
											if (j != i)
											{
												if (to_remote_g2[j].addr==to_remote_g2[i].addr && to_remote_g2[j].addr.GetPort()==rmt_ref_port)
												{
													printf("Info: Local %c is also linked to %s (different module) %c\n", to_remote_g2[j].from_mod, to_remote_g2[j].cs, to_remote_g2[j].to_mod);
													break;
												}
											}
										}

										if (j == 3)
										{
											/* nothing else is linked there, send DISCONNECT */
											queryCommand[0] = 5;
											queryCommand[1] = 0;
											queryCommand[2] = 24;
											queryCommand[3] = 0;
											queryCommand[4] = 0;
											REFWrite(queryCommand, 5, to_remote_g2[i].addr);
										}
									}
									else if (to_remote_g2[i].addr.GetPort() == rmt_xrf_port)
									{
										char unlink_request[CALL_SIZE + 3];
										strcpy(unlink_request, owner.c_str());
										unlink_request[8] = to_remote_g2[i].from_mod;
										unlink_request[9] = ' ';
										unlink_request[10] = '\0';

										for (int j=0; j<5; j++)
											XRFWrite(unlink_request, CALL_SIZE+3, to_remote_g2[i].addr);
									}
									else
									{
										char cmd_2_dcs[23];
										strcpy(cmd_2_dcs, owner.c_str());
										cmd_2_dcs[8] = to_remote_g2[i].from_mod;
										cmd_2_dcs[9] = ' ';
										cmd_2_dcs[10] = '\0';
										memcpy(cmd_2_dcs + 11, to_remote_g2[i].cs, 8);

										for (int j=0; j<5; j++)
											DCSWrite(cmd_2_dcs, 19, to_remote_g2[i].addr);
									}

									printf("Unlinked from [%s] mod %c\n", to_remote_g2[i].cs, to_remote_g2[i].to_mod);
									sprintf(notify_msg[i], "%c_unlinked.dat_UNLINKED", to_remote_g2[i].from_mod);
									qnDB.DeleteLS(to_remote_g2[i].addr.GetAddress());
									/* now zero out this entry */
									to_remote_g2[i].cs[0] = '\0';
									to_remote_g2[i].addr.Clear();
									to_remote_g2[i].from_mod = to_remote_g2[i].to_mod = ' ';
									to_remote_g2[i].countdown = 0;
									to_remote_g2[i].is_connected = false;
									to_remote_g2[i].in_streamid = 0x0;
								}
								else
								{
									sprintf(notify_msg[i], "%c_already_unlinked.dat_UNLINKED", dsvt.hdr.rpt1[7]);
								}
							}
						}
						else if (0 == memcmp(dsvt.hdr.urcall, "       I", CALL_SIZE))
						{
							if (to_remote_g2[i].is_connected)
							{
								char linked_remote_system[CALL_SIZE + 1];
								strcpy(linked_remote_system, to_remote_g2[i].cs);
								auto space_p = strchr(linked_remote_system, ' ');
								if (space_p)
									*space_p = '\0';
								sprintf(notify_msg[i], "%c_linked.dat_LINKED_%s_%c", to_remote_g2[i].from_mod, linked_remote_system, to_remote_g2[i].to_mod);
							}
							else
							{
								sprintf(notify_msg[i], "%c_id.dat_%s_NOT_LINKED", dsvt.hdr.rpt1[7], owner.c_str());
							}
						}
						else if (0==memcmp(dsvt.hdr.urcall, "      ", 6) && dsvt.hdr.urcall[7]=='X')  	// execute a script
						{
							if (dsvt.hdr.urcall[6] != ' ')  	// there has to be a char here
							{
								if (admin.size()>0 && admin.end()==admin.find(call))   // only admins (if defined) can execute scripts
								{
									printf("%s not found in admin list, ignoring script %c request\n", call, dsvt.hdr.urcall[6]);
								}
								else
								{
									char system_cmd[128];
									memset(system_cmd, '\0', sizeof(system_cmd));
									snprintf(system_cmd, 127, "%s/exec_%c.sh %s %c &", BIN_DIR, dsvt.hdr.urcall[6], call, dsvt.hdr.rpt1[7]);
									printf("Executing %s\n", system_cmd);
									system(system_cmd);
								}
							}
						}
						else if (0==memcmp(dsvt.hdr.urcall, "      ", 6) && dsvt.hdr.urcall[6]=='D')   // only ADMIN can block dongle users
						{
							if (admin.size()>0 && admin.end()==admin.find(call))
							{
								printf("%s not found in admin list, ignoring dongle gate request\n", call);
							}
							else
							{
								if (dsvt.hdr.urcall[7] == '1')
								{
									max_dongles = saved_max_dongles;
									printf("Dongle connections are now allowed by %s\n", call);
								}
								else if (dsvt.hdr.urcall[7] == '0')
								{
									inbound_list.clear();
									max_dongles = 0;
									printf("Dongle connections are now disallowed by %s\n", call);
								}
							}
						}
						else if (0==memcmp(dsvt.hdr.urcall, "       F", CALL_SIZE))   // only ADMIN can reload gwys.txt
						{
							if (admin.size()>0 && admin.end()==admin.find(call))
							{
								printf("%s not found in admin list, ignoring gwys read request\n", call);
							}
							else
							{
								loadG[i] = true;
							}
						}
					}

					/* send data to the donglers */
					SREFDSVT rdsvt;
					if (inbound_list.size() > 0)
					{
						memset(rdsvt.head, 0U, 58U);
						rdsvt.head[0] = 58U;
						rdsvt.head[1] = 0x80U;

						memcpy(rdsvt.dsvt.title, dsvt.title, 56);
						memcpy(rdsvt.dsvt.hdr.rpt1, owner.c_str(), CALL_SIZE);
						rdsvt.dsvt.hdr.rpt1[7] = dsvt.hdr.rpt1[7];
						memcpy(rdsvt.dsvt.hdr.rpt2, owner.c_str(), CALL_SIZE);
						rdsvt.dsvt.hdr.rpt2[7] = 'G';
						memcpy(rdsvt.dsvt.hdr.urcall, "CQCQCQ  ", 8);
						calcPFCS(rdsvt.dsvt.title, 56);

						for (auto pos = inbound_list.begin(); pos != inbound_list.end(); pos++)
						{
							SINBOUND *inbound = (SINBOUND *)pos->second;
							for (int j=0; j<5; j++)
								REFWrite(rdsvt.head, 58, inbound->addr);
						}
					}

					if (i >= 0)
					{
						/* do we have to broadcast ? */
						/* make sure the source is linked to xrf */
						if (to_remote_g2[i].is_connected && 0==memcmp(to_remote_g2[i].cs, "XRF", 3) && 0==memcmp(dsvt.hdr.rpt2, owner.c_str(), CALL_SIZE-1) && dsvt.hdr.rpt2[7]=='G' && 0==memcmp(dsvt.hdr.urcall, "CQCQCQ", 6))
						{
							brd_from_rptr_idx = 0;
							auto streamid_raw = ntohs(dsvt.streamid);

							for (int j=0; j<3; j++)
							{
								if (j!=i && to_remote_g2[j].is_connected && 0==memcmp(to_remote_g2[j].cs, to_remote_g2[i].cs, 8) && to_remote_g2[j].to_mod==to_remote_g2[i].to_mod && to_remote_g2[j].to_mod!='E')
								{
									memcpy(fromrptr_torptr_brd.title, dsvt.title, 56);

									if (++streamid_raw == 0)
										streamid_raw++;
									fromrptr_torptr_brd.streamid = htons(streamid_raw);

									memcpy(fromrptr_torptr_brd.hdr.rpt1, owner.c_str(), CALL_SIZE);
									fromrptr_torptr_brd.hdr.rpt1[7] = to_remote_g2[j].from_mod;
									memcpy(fromrptr_torptr_brd.hdr.rpt2, owner.c_str(), CALL_SIZE);
									fromrptr_torptr_brd.hdr.rpt2[7] = 'G';

									memcpy(fromrptr_torptr_brd.hdr.urcall, "CQCQCQ  ", CALL_SIZE);

									calcPFCS(fromrptr_torptr_brd.title, 56);

									ToGate.Write(fromrptr_torptr_brd.title, 56);

									brd_from_rptr.from_rptr_streamid = dsvt.streamid;
									brd_from_rptr.to_rptr_streamid[brd_from_rptr_idx] = fromrptr_torptr_brd.streamid;
									brd_from_rptr_idx++;
								}
							}
						}

						if (to_remote_g2[i].is_connected)
						{
							if (0==memcmp(dsvt.hdr.rpt2, owner.c_str(), 7) && 0==memcmp(dsvt.hdr.urcall, "CQCQCQ", 6) && dsvt.hdr.rpt2[7] == 'G')
							{
								to_remote_g2[i].out_streamid = dsvt.streamid;

								if (to_remote_g2[i].addr.GetPort()==rmt_xrf_port || to_remote_g2[i].addr.GetPort()==rmt_ref_port)
								{
									SREFDSVT rdsvt;
									rdsvt.head[0] = 58U;
									rdsvt.head[1] = 0x80U;

									memcpy(rdsvt.dsvt.title, dsvt.title, 56);
									memset(rdsvt.dsvt.hdr.rpt1, ' ', CALL_SIZE);
									memcpy(rdsvt.dsvt.hdr.rpt1, to_remote_g2[i].cs, strlen(to_remote_g2[i].cs));
									rdsvt.dsvt.hdr.rpt1[7] = to_remote_g2[i].to_mod;
									memset(rdsvt.dsvt.hdr.rpt2, ' ', CALL_SIZE);
									memcpy(rdsvt.dsvt.hdr.rpt2, to_remote_g2[i].cs, strlen(to_remote_g2[i].cs));
									rdsvt.dsvt.hdr.rpt2[7] = 'G';
									memcpy(rdsvt.dsvt.hdr.urcall, "CQCQCQ  ", CALL_SIZE);
									calcPFCS(rdsvt.dsvt.title, 56);

									if (to_remote_g2[i].addr.GetPort() == rmt_xrf_port)
									{
										/* inform XRF about the source */
										rdsvt.dsvt.flagb[2] = to_remote_g2[i].from_mod;
										calcPFCS(rdsvt.dsvt.title, 56);
										for (int j=0; j<5; j++)
											XRFWrite(rdsvt.dsvt.title, 56, to_remote_g2[i].addr);
									}
									else
									{
										for (int j=0; j<5; j++)
											REFWrite(rdsvt.head, 58, to_remote_g2[i].addr);
									}
								}
								else if (to_remote_g2[i].addr.GetPort() == rmt_dcs_port)
								{
									memcpy(rptr_2_dcs[i].mycall, dsvt.hdr.mycall, CALL_SIZE);
									memcpy(rptr_2_dcs[i].sfx, dsvt.hdr.sfx, 4);
									rptr_2_dcs[i].dcs_rptr_seq = 0;
								}
							}
						}
					}
				}
				else   // length is 27
				{
					SREFDSVT rdsvt;
					rdsvt.head[0] = (dsvt.ctrl & 0x40U) ? 32U : 29U;
					rdsvt.head[1] = 0x80U;

					memcpy(rdsvt.dsvt.title, dsvt.title, 27);
					if (dsvt.ctrl & 0x40U)
						memcpy(rdsvt.dsvt.vend.textend, endbytes, 6);
					if (inbound_list.size() > 0)
					{

						for (auto pos = inbound_list.begin(); pos != inbound_list.end(); pos++)
						{
							REFWrite(rdsvt.head, rdsvt.head[0], pos->second->addr);
						}
					}

					for (int i=0; i<3; i++)
					{
						if (to_remote_g2[i].is_connected && to_remote_g2[i].out_streamid==dsvt.streamid)
						{
							/* check for broadcast */
							if (brd_from_rptr.from_rptr_streamid == dsvt.streamid)
							{
								memcpy(fromrptr_torptr_brd.title, dsvt.title, 27);
								if (brd_from_rptr.to_rptr_streamid[0])
								{
									fromrptr_torptr_brd.streamid = brd_from_rptr.to_rptr_streamid[0];
									ToGate.Write(fromrptr_torptr_brd.title, 27);
								}

								if (brd_from_rptr.to_rptr_streamid[1])
								{
									fromrptr_torptr_brd.streamid = brd_from_rptr.to_rptr_streamid[1];
									ToGate.Write(fromrptr_torptr_brd.title, 27);
								}

								if (dsvt.ctrl & 0x40U)
								{
									brd_from_rptr.from_rptr_streamid = brd_from_rptr.to_rptr_streamid[0] = brd_from_rptr.to_rptr_streamid[1] = 0x0;
									brd_from_rptr_idx = 0;
								}
							}

							if (to_remote_g2[i].addr.GetPort()==rmt_xrf_port || to_remote_g2[i].addr.GetPort()==rmt_ref_port)
							{
								if (to_remote_g2[i].addr.GetPort() == rmt_xrf_port)
								{
									/* inform XRF about the source */
									rdsvt.dsvt.flagb[2] = to_remote_g2[i].from_mod;

									XRFWrite(dsvt.title, 27, to_remote_g2[i].addr);
								}
								else if (to_remote_g2[i].addr.GetPort() == rmt_ref_port)
									REFWrite(rdsvt.head, rdsvt.head[0], to_remote_g2[i].addr);
							}
							else if (to_remote_g2[i].addr.GetPort() == rmt_dcs_port)
							{
								unsigned char dcs_buf[600];
								memset(dcs_buf, 0x0, 600);
								dcs_buf[0] = dcs_buf[1] = dcs_buf[2] = '0';
								dcs_buf[3] = '1';
								dcs_buf[4] = dcs_buf[5] = dcs_buf[6] = 0x0;
								memcpy(dcs_buf + 7, to_remote_g2[i].cs, 8);
								dcs_buf[14] = to_remote_g2[i].to_mod;
								memcpy(dcs_buf + 15, owner.c_str(), CALL_SIZE);
								dcs_buf[22] = to_remote_g2[i].from_mod;
								memcpy(dcs_buf + 23, "CQCQCQ  ", 8);
								memcpy(dcs_buf + 31, rptr_2_dcs[i].mycall, 8);
								memcpy(dcs_buf + 39, rptr_2_dcs[i].sfx, 4);
								memcpy(dcs_buf + 43, &dsvt.streamid, 2);
								dcs_buf[45] = dsvt.ctrl;  /* cycle sequence */
								memcpy(dcs_buf + 46, dsvt.vasd.voice, 12);

								dcs_buf[58] = (rptr_2_dcs[i].dcs_rptr_seq >> 0)  & 0xff;
								dcs_buf[59] = (rptr_2_dcs[i].dcs_rptr_seq >> 8)  & 0xff;
								dcs_buf[60] = (rptr_2_dcs[i].dcs_rptr_seq >> 16) & 0xff;

								rptr_2_dcs[i].dcs_rptr_seq++;

								dcs_buf[61] = 0x01;
								dcs_buf[62] = 0x00;

								DCSWrite(dcs_buf, 100, to_remote_g2[i].addr);
							}

							if (dsvt.ctrl & 0x40U)
							{
								to_remote_g2[i].out_streamid = 0x0;
							}
							break;
						}
					}

					for (int i=0; i<3; i++)
					{
						if (tracing[i].streamid == dsvt.streamid)
						{
							/* update the last time RF user talked */
							tracing[i].last_time = time(NULL);

							if (dsvt.ctrl & 0x40U)
							{
								if (qso_details)
									printf("END from local g2: streamID=%04x, %d bytes\n", ntohs(dsvt.streamid), length);

								if ('\0' == notify_msg[i][0])
								{
									if (bool_rptr_ack && ' ' != your[i])
										rptr_ack(i);
								}

								memset(dtmf_mycall[i], 0, sizeof(dtmf_mycall[i]));
								new_group[i] = true;
								GPS_seen[i] = false;

								tracing[i].streamid = 0x0;
							}
							else
							{
								if (!GPS_seen[i])
								{
									memcpy(tmp_txt, dsvt.vasd.text, 3);

									if (tmp_txt[0]!=0x55 || tmp_txt[1]!=0x2d || tmp_txt[2]!=0x16)
									{
										if (new_group[i])
										{
											tmp_txt[0] = tmp_txt[0] ^ 0x70;
											header_type = tmp_txt[0] & 0xf0;
											// header				squelch
											if (header_type== 0x50 || header_type==0xc0)
												new_group[i] = false;
											else if (header_type == 0x30)   /* GPS or GPS id or APRS */
											{
												GPS_seen[i] = true;
												new_group[i] = false;

												char tmp1[CALL_SIZE + 1];
												memcpy(tmp1, dtmf_mycall[i], 8);
												tmp1[8] = '\0';

												// delete the user if exists and it is a local RF entry
												p_tmp2 = NULL;
												char tmp2[36];
												for (auto dt_lh_pos = dt_lh_list.begin(); dt_lh_pos != dt_lh_list.end();  dt_lh_pos++)
												{
													if (strcmp((char *)dt_lh_pos->second.c_str(), tmp1) == 0)
													{
														strcpy(tmp2, (char *)dt_lh_pos->first.c_str());
														p_tmp2 = strstr(tmp2, "=l");
														if (p_tmp2)
														{
															dt_lh_list.erase(dt_lh_pos);
															break;
														}
													}
												}
												/* we have tmp1 and tmp2, we have the user and it is already been removed */
												/* add the user with gps indicator g */
												if (p_tmp2)
												{
													*(p_tmp2 + 1) = 'g';
													dt_lh_list[tmp2] = tmp1;
												}
											}
											else if (header_type == 0x40)   /* ABC text */
												new_group[i] = false;
											else
												new_group[i] = false;
										}
										else
											new_group[i] = true;
									}
								}
							}
							break;
						}
					}
				}
			}
			FD_CLR (ToGate.GetFD(), &fdset);
		}
		for (int i=0; i<3 && keep_running; i++)
		{
			if (notify_msg[i][0] && 0x0U == tracing[i].streamid)
			{
				PlayAudioNotifyThread(notify_msg[i]);
				notify_msg[i][0] = '\0';
			}
			if (loadG[i] && 0x0U == tracing[i].streamid)
			{
				LoadGateways(gwys);
				loadG[i] = false;
				if (bool_rptr_ack)
					rptr_ack(i);
			}
		}
	}
}

void CQnetLink::PlayAudioNotifyThread(char *msg)
{
	if (! announce)
		return;

	if (msg[0]<'A' || msg[0]>'C')
	{
		fprintf(stderr, "Improper module in msg '%s'\n", msg);
		return;
	}

	SECHO edata;

	edata.is_linked = (NULL == strstr(msg, "_linked.dat_LINKED_")) ? false : true;
	char *p = strstr(msg, ".dat");
	if (NULL == p)
	{
		fprintf(stderr, "Improper AMBE data file in msg '%s'\n", msg);
		return;
	}
	if ('_' == p[4])
	{
		std::string message(p+5);
		message.resize(20, ' ');
		strcpy(edata.message, message.c_str());
		for (int i=0; i<20; i++)
		{
			if ('_' == edata.message[i])
				edata.message[i] = ' ';
		}
	}
	else
	{
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

	try
	{
		std::async(std::launch::async, &CQnetLink::AudioNotifyThread, this, std::ref(edata));
	}
	catch (const std::exception &e)
	{
		printf ("Failed to start AudioNotifyThread(). Exception: %s\n", e.what());
	}
	return;
}

void CQnetLink::AudioNotifyThread(SECHO &edata)
{
	char mod = edata.header.hdr.rpt1[7];

	if ((mod != 'A') && (mod != 'B') && (mod != 'C'))
	{
		fprintf(stderr, "Invalid module %c in %s\n", mod, edata.file);
		return;
	}

	sleep(delay_before);

	printf("sending File:[%s], mod:[%c], RADIO_ID=[%s]\n", edata.file, mod, edata.message);

	struct stat sbuf;
	if (stat(edata.file, &sbuf))
	{
		fprintf(stderr, "can't stat %s\n", edata.file);
		return;
	}

	if (sbuf.st_size % 9)
		printf("Warning %s file size is %ld (not a multiple of 9)!\n", edata.file, sbuf.st_size);
	int ambeblocks = (int)sbuf.st_size / 9;


	FILE *fp = fopen(edata.file, "rb");
	if (!fp)
	{
		fprintf(stderr, "Failed to open file %s for reading\n", edata.file);
		return;
	}

	ToGate.Write(edata.header.title, 56);

	edata.header.config = 0x20U;

	int count;
	const unsigned char sdsync[3] = { 0x55U, 0x2DU, 0x16U };
	const unsigned char sdsilence[3] = { 0x16U, 0x29U, 0xF5U };
	for (count=0; count<ambeblocks && keep_running; count++)
	{
		int nread = fread(edata.header.vasd.voice, 9, 1, fp);
		if (nread == 1)
		{
			edata.header.ctrl = (unsigned char)(count % 21);
			if (0x0U == edata.header.ctrl)
			{
				memcpy(edata.header.vasd.text, sdsync, 3);
			}
			else
			{
				switch (count)
				{
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
			ToGate.Write(edata.header.title, 27);
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
	while (isspace(*rit))
	{
		say.resize(say.size()-1);
		rit = say.rbegin();
	}

	// play it
	for (auto it=say.begin(); it!=say.end(); it++)
	{
		bool lastch = (it+1 == say.end());
		unsigned long offset = 0;
		int size = 0;
		if ('A' <= *it && *it <= 'Z')
			offset = speak[*it - 'A' + (lastch ? 26 : 0)];
		else if ('1' <= *it && *it <= '9')
			offset = speak[*it - '1' + 52];
		else if ('0' == *it)
			offset = speak[61];
		if (offset)
		{
			size = (int)(offset % 1000UL);
			offset = (offset / 1000UL) * 9UL;
		}
		if (0 == size)
			continue;
		if (fseek(fp, offset, SEEK_SET))
		{
			fprintf(stderr, "fseek to %ld error!\n", offset);
			return;
		}
		for (int i=0; i<size; i++)
		{
			edata.header.ctrl = count++ % 21;
			int nread = fread(edata.header.vasd.voice, 9, 1, fp);
			if (nread == 1)
			{
				memcpy(edata.header.vasd.text, edata.header.ctrl ? sdsilence : sdsync, 3);
				if (i+1==size && lastch)
					edata.header.ctrl |= 0x40U;	// signal the last voiceframe (of the last character)
				ToGate.Write(edata.header.title, 27);
				std::this_thread::sleep_for(std::chrono::milliseconds(delay_between));
			}
		}
	}
	fclose(fp);
	return;
}

bool CQnetLink::Init(const char *cfgfile)
{
	tzset();
	setvbuf(stdout, (char *)NULL, _IOLBF, 0);
	memset(tracing, 0, 3 * sizeof(struct tracing_tag));
	memset(dtmf_mycall, 0, 3 * (CALL_SIZE+1));
	memset(old_sid, 0, 6);

	int rc = regcomp(&preg, "^(([1-9][A-Z])|([A-Z][0-9])|([A-Z][A-Z][0-9]))[0-9A-Z]*[A-Z][ ]*[ A-RT-Z]$", REG_EXTENDED | REG_NOSUB);
	if (rc != 0)
	{
		printf("The IRC regular expression is NOT valid\n");
		return true;
	}

	for (int i=0; i<3; i++)
	{
		notify_msg[i][0] = '\0';
		to_remote_g2[i].cs[0] = '\0';
		to_remote_g2[i].addr.Clear();
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
	if (ReadConfig(cfgfile))
	{
		printf("Failed to process config file %s\n", cfgfile);
		return true;
	}
	// open sqlite
	std::string fname(CFG_DIR);
	fname.append("/qn.db");
	if (qnDB.Open(fname.c_str()))
		return true;
	qnDB.ClearLS();

	/* create our server */
	if (srv_open())
	{
		printf("srv_open() failed\n");
		return true;
	}

	LoadGateways(gwys);

	std::string index(announce_dir);
	index.append("/index.dat");
	std::ifstream indexfile(index.c_str(), std::ifstream::in);
	if (indexfile)
	{
		for (int i=0; i<62; i++)
		{
			std::string name, offset, size;
			indexfile >> name >> offset >> size;
			if (name.size() && offset.size() && size.size())
			{
				unsigned long of = std::stoul(offset);
				unsigned long sz = std::stoul(size);
				speak.push_back(1000U * of + sz);
			}
		}
		indexfile.close();
	}
	if (62 == speak.size())
	{
		printf("read %d indicies from %s\n", (unsigned int)speak.size(), index.c_str());
	}
	else
	{
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
	for (int i=0; i<3; i++)
	{
		if (to_remote_g2[i].cs[0] != '\0')
		{
			if (to_remote_g2[i].addr.GetPort() == rmt_ref_port)
				REFWrite(queryCommand, 5, to_remote_g2[i].addr);
			else if (to_remote_g2[i].addr.GetPort() == rmt_xrf_port)
			{
				strcpy(unlink_request, owner.c_str());
				unlink_request[8] = to_remote_g2[i].from_mod;
				unlink_request[9] = ' ';
				unlink_request[10] = '\0';
				for (int j=0; j<5; j++)
					XRFWrite(unlink_request, CALL_SIZE+3, to_remote_g2[i].addr);
			}
			else
			{
				strcpy(cmd_2_dcs, owner.c_str());
				cmd_2_dcs[8] = to_remote_g2[i].from_mod;
				cmd_2_dcs[9] = ' ';
				cmd_2_dcs[10] = '\0';
				memcpy(cmd_2_dcs + 11, to_remote_g2[i].cs, 8);

				for (int j=0; j<5; j++)
					DCSWrite(cmd_2_dcs, 19, to_remote_g2[i].addr);
			}
		}
		to_remote_g2[i].cs[0] = '\0';
		to_remote_g2[i].addr.Clear();
		to_remote_g2[i].from_mod = to_remote_g2[i].to_mod = ' ';
		to_remote_g2[i].countdown = 0;
		to_remote_g2[i].is_connected = false;
		to_remote_g2[i].in_streamid = to_remote_g2[i].out_streamid = 0x0;
	}

	/* tell inbound dongles we are down */
	for (auto pos = inbound_list.begin(); pos != inbound_list.end(); pos++)
	{
		SINBOUND *inbound = (SINBOUND *)pos->second;
		qnDB.DeleteLS(pos->first.c_str());
		REFWrite(queryCommand, 5, inbound->addr);
	}
	inbound_list.clear();

	srv_close();

	return;
}

int main(int argc, char **argv)
{
	if (argc != 2)
	{
		printf("Usage: %s configuration_file\n", argv[0]);
		return 1;
	}
	CQnetLink qnlink;
	if (qnlink.Init(argv[1]))
		return 1;
	printf("QnetLink %s initialized...entering processing loop\n", LINK_VERSION);
	qnlink.Process();
	printf("QnetLink exiting\n");
	qnlink.Shutdown();
}
