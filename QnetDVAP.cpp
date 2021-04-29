/*
 *   Copyright (C) 2010,2011 by Scott Lawson KI4LKF
 *
 *   Copyright (C) 2015,2020,2021 by Thomas A. Early N7TAE
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

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <sys/file.h>

#include <atomic>
#include <future>
#include <exception>
#include <thread>
#include <string>
#include <csignal>

#include "DVAPDongle.h"
#include "QnetTypeDefs.h"
#include "Random.h"
#include "UnixPacketSock.h"
#include "QnetConfigure.h"
#include "Timer.h"
#include "DStarDecode.h"
#include "QnetDVAP.h"

#define DVAP_VERSION "QnetDVAP-220429"

#define CALL_SIZE 8
#define IP_SIZE 15

void CQnetDVAP::calcPFCS(unsigned char *packet, unsigned char *pfcs)
{
	unsigned short crc_dstar_ffff = 0xffff;
	unsigned short tmp, short_c;
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

	for (int i = 0; i < 39 ; i++)
	{
		short_c = 0x00ff & (unsigned short)packet[i];
		tmp = (crc_dstar_ffff & 0x00ff) ^ short_c;
		crc_dstar_ffff = (crc_dstar_ffff >> 8) ^ crc_tabccitt[tmp];
	}
	crc_dstar_ffff =  ~crc_dstar_ffff;
	tmp = crc_dstar_ffff;

	pfcs[0] = (unsigned char)(crc_dstar_ffff & 0xff);
	pfcs[1] = (unsigned char)((tmp >> 8) & 0xff);

	return;
}

/* process configuration file */
bool CQnetDVAP::ReadConfig(const char *cfgFile)
{
	CQnetConfigure cfg;

	printf("Reading file %s\n", cfgFile);
	if (cfg.Initialize(cfgFile))
		return true;

	const std::string estr; // an empty string
	std::string type;
	std::string dvap_path("module_");
	if (0 > assigned_module)
	{
		// we need to find the lone dvap module
		for (int i=0; i<3; i++)
		{
			std::string test(dvap_path);
			test.append(1, 'a'+i);
			if (cfg.KeyExists(test))
			{
				cfg.GetValue(test, estr, type, 1, 16);
				if (type.compare("dvap"))
					continue;	// this ain't it!
				dvap_path.assign(test);
				assigned_module = i;
				break;
			}
		}
		if (0 > assigned_module)
		{
			fprintf(stderr, "Error: no 'dvap' module found\n!");
			return true;
		}
	}
	else
	{
		// make sure dvap module is defined
		dvap_path.append(1, 'a' + assigned_module);
		if (cfg.KeyExists(dvap_path))
		{
			cfg.GetValue(dvap_path, estr, type, 1, 16);
			if (type.compare("dvap"))
			{
				fprintf(stderr, "%s = %s is not 'dvap' type!\n", dvap_path.c_str(), type.c_str());
				return true;
			}
		}
		else
		{
			fprintf(stderr, "Module '%c' is not defined.\n", 'a'+assigned_module);
			return true;
		}
	}
	RPTR_MOD = 'A' + assigned_module;
	cfg.GetValue("gateway_tomodem"+std::string(1, 'a'+assigned_module), estr, togate, 1, FILENAME_MAX);
	if (cfg.KeyExists(dvap_path+"_callsign"))
	{
		if (cfg.GetValue(dvap_path+"_callsign", type, RPTR, 3, 6))
			return true;
	}
	if (cfg.GetValue("ircddb_login", estr, OWNER, 3, 6))
		return true;
	if (RPTR.empty())
		RPTR.assign(OWNER);

	for (unsigned long i=0; i<RPTR.length(); i++)
	{
		if (islower(RPTR.at(i)))
			RPTR.at(i) = toupper(RPTR.at(i));
	}
	for (unsigned long i=0; i<OWNER.length(); i++)
	{
		if (islower(OWNER.at(i)))
			OWNER.at(i) = toupper(OWNER.at(i));
	}
	RPTR.resize(CALL_SIZE, ' ');
	OWNER.resize(CALL_SIZE, ' ');

	cfg.GetValue(dvap_path+"_serial_number", type, MODULE_SERIAL_NUMBER, 0, 10);
	cfg.GetValue(dvap_path+"_device", type, MODULE_DEVICE, 0, 32);
	if (0==MODULE_DEVICE.size() && 0==MODULE_SERIAL_NUMBER.size())
	{
		fprintf(stderr, "Either a device path or a serial number must be specifed for a DVAP\n");
		return true;
	}
	double f;
	cfg.GetValue(dvap_path+"_frequency", type, f, 100.0, 1400.0);
	MODULE_FREQUENCY = (int)(1.0e6*f);
	cfg.GetValue(dvap_path+"_power", type, MODULE_POWER, -12, 10);
	cfg.GetValue(dvap_path+"_squelch", type, MODULE_SQUELCH, -128, -45);
	cfg.GetValue(dvap_path+"_offset", type, MODULE_OFFSET, -2000, 2000);
	cfg.GetValue(dvap_path+"_packet_wait", type, MODULE_PACKET_WAIT, 6, 100);
	cfg.GetValue(dvap_path+"_acknowledge", type, MODULE_ACKNOWLEDGE);

	dvap_path.assign("timing_timeout_");
	cfg.GetValue(dvap_path+"remote_g2", estr, TIMING_TIMEOUT_REMOTE_G2, 1, 10);
	cfg.GetValue(dvap_path+"local_rptr", estr, TIMING_TIMEOUT_LOCAL_RPTR, 1.0, 10.0);
	dvap_path.assign("timing_play_");
	cfg.GetValue(dvap_path+"delay", estr, TIMING_PLAY_DELAY, 9, 25);
	cfg.GetValue(dvap_path+"wait", estr, TIMING_PLAY_WAIT, 1, 10);


	inactiveMax = (TIMING_TIMEOUT_REMOTE_G2 * 1000) / MODULE_PACKET_WAIT;
	printf("Max loops = %d\n", inactiveMax);

	/* convert to Microseconds */
	MODULE_PACKET_WAIT *= 1000;

	dvap_path.assign("log_");
	cfg.GetValue(dvap_path+"qso", estr, LOG_QSO);
	cfg.GetValue(dvap_path+"debug", estr, LOG_DEBUG);

	return false;
}

void CQnetDVAP::ReadFromGateway()
{
	unsigned short streamid = 0U;
	int inactive = 0;
	int len = 0;
	fd_set readfd;
	struct timeval tv;
	short seq_no = 0;
	unsigned char sync_codes[3] = {0x55, 0x2d, 0x16};
	SDSVT dsvt;
	unsigned char frame_pos_to_dvap = 0;
	unsigned char seq_to_dvap = 0;
	unsigned char silence[12] = { 0x9e,0x8d,0x32,0x88,0x26,0x1a,0x3f,0x61,0xe8,0x70,0x4f,0x93 };

	bool written_to_q = false;
	unsigned char ctrl_in = 0x80;

	while (keep_running)
	{
		written_to_q = false;
		len = 0;
		tv.tv_sec = 0;
		tv.tv_usec = MODULE_PACKET_WAIT;
		FD_ZERO (&readfd);
		int fd = ToGate.GetFD();
		FD_SET (fd, &readfd);
		select(fd + 1, &readfd, NULL, NULL, &tv);

		if (FD_ISSET(fd, &readfd))
		{
			len = ToGate.Read(dsvt.title, 56);
			if (len == 56)
			{
				if (busy20000)
				{
					FD_CLR (fd, &readfd);
					continue;
				}

				if ('G' == dsvt.hdr.rpt1[7])
				{
					unsigned char tmp[8];
					memcpy(tmp, dsvt.hdr.rpt1, 8);
					memcpy(dsvt.hdr.rpt1, dsvt.hdr.rpt2, 8);
					memcpy(dsvt.hdr.rpt2, tmp, 8);
				}

				/* check the module and gateway */
				if (dsvt.hdr.rpt1[7] != RPTR_MOD)
				{
					FD_CLR(fd, &readfd);
					break;
				}
				memcpy(dsvt.hdr.rpt2, OWNER.c_str(), 7);
				dsvt.hdr.rpt2[7] = 'G';

				if (RPTR.compare(OWNER))
				{
					// restriction mode
					memcpy(dsvt.hdr.rpt1, RPTR.c_str(), 7);
					memcpy(dsvt.hdr.rpt2, RPTR.c_str(), 7);

					if (memcmp(dsvt.hdr.mycall, OWNER.c_str(), 7) == 0)
					{
						/* this is an ACK back */
						memcpy(dsvt.hdr.mycall, RPTR.c_str(), 7);
					}
				}

				if ((dsvt.hdr.flag[0] != 0x00) &&
						(dsvt.hdr.flag[0] != 0x01) &&
						(dsvt.hdr.flag[0] != 0x08) &&
						(dsvt.hdr.flag[0] != 0x20) &&
						(dsvt.hdr.flag[0] != 0x28) &&
						(dsvt.hdr.flag[0] != 0x40))
				{
					FD_CLR(fd, &readfd);
					break;
				}

				if (memcmp(dsvt.title, "DSVT", 4) || dsvt.id!=0x20 || dsvt.config!=0x10)
				{
					FD_CLR(fd, &readfd);
					break;
				}

				busy20000 = true;

				ctrl_in = 0x80;
				written_to_q = true;
				if (LOG_QSO)
					printf("Start G2: streamid=%04x, flags=%02x:%02x:%02x, my=%.8s, sfx=%.4s, ur=%.8s, rpt1=%.8s, rpt2=%.8s\n", ntohs(dsvt.streamid), dsvt.hdr.flag[0], dsvt.hdr.flag[1], dsvt.hdr.flag[2], dsvt.hdr.mycall, dsvt.hdr.sfx, dsvt.hdr.urcall, dsvt.hdr.rpt1, dsvt.hdr.rpt2);

				/* save the streamid that is winning */
				streamid = dsvt.streamid;

				if (dsvt.hdr.flag[0] != 0x01)
				{

					if (dsvt.hdr.flag[0] == 0x00)
						dsvt.hdr.flag[0] = 0x40;
					else if (dsvt.hdr.flag[0] == 0x08)
						dsvt.hdr.flag[0] = 0x48;
					else if (dsvt.hdr.flag[0] == 0x20)
						dsvt.hdr.flag[0] = 0x60;
					else if (dsvt.hdr.flag[0] == 0x28)
						dsvt.hdr.flag[0] = 0x68;
					else
						dsvt.hdr.flag[0] = 0x40;
				}
				dsvt.hdr.flag[1] = dsvt.hdr.flag[2] = 0x00;

				// write the header packet to the dvap here
				while ((space < 1) && keep_running)
					usleep(5);
				SDVAP_REGISTER dr;
				dr.header = 0xa02f;
				dr.frame.streamid = streamid = dsvt.streamid;
				dr.frame.framepos = 0x80;
				dr.frame.seq = 0;
				//memset(dvp_buf + 6, ' ', 41);
				for (int f=0; f<3; f++)
					dr.frame.hdr.flag[f] = dsvt.hdr.flag[0];
				memcpy(dr.frame.hdr.rpt1, dsvt.hdr.rpt1, 8);
				memcpy(dr.frame.hdr.rpt2, dsvt.hdr.rpt2, 8);
				memcpy(dr.frame.hdr.urcall, dsvt.hdr.urcall, 8);
				memcpy(dr.frame.hdr.mycall, dsvt.hdr.mycall, 8);
				memcpy(dr.frame.hdr.sfx, dsvt.hdr.sfx, 4);
				calcPFCS(dr.frame.hdr.flag, dr.frame.hdr.pfcs);
				frame_pos_to_dvap = 0;
				seq_to_dvap = 0;
				dongle.SendRegister(dr);

				inactive = 0;
				seq_no = 0;
			}
			else if (len == 27)
			{
				if (busy20000)
				{
					if (dsvt.streamid == streamid)
					{
						if (dsvt.ctrl == ctrl_in)
						{
							/* do not update written_to_q, ctrl_in */
							; // printf("dup\n");
						}
						else
						{
							ctrl_in = dsvt.ctrl;
							written_to_q = true;

							if (seq_no == 0)
							{
								dsvt.vasd.text[0] = 0x55;
								dsvt.vasd.text[1] = 0x2d;
								dsvt.vasd.text[2] = 0x16;
							}
							else
							{
								if ((dsvt.vasd.text[0] == 0x55) && (dsvt.vasd.text[1] == 0x2d) && (dsvt.vasd.text[2] == 0x16))
								{
									dsvt.vasd.text[0] = 0x70;
									dsvt.vasd.text[1] = 0x4f;
									dsvt.vasd.text[2] = 0x93;
								}
							}

							// write the audio packet to the dvap here
							while ((space < 1) && keep_running)
								usleep(5);
							SDVAP_REGISTER dr;
							dr.header = 0xc012u;
							if (memcmp(dsvt.vasd.text, sync_codes, 3) == 0)
								frame_pos_to_dvap = 0;
							dr.frame.streamid = streamid;
							dr.frame.framepos = frame_pos_to_dvap;
							if ((dsvt.ctrl & 0x40) != 0)
								dr.frame.framepos |= 0x40U;
							dr.frame.seq = seq_to_dvap;
							memcpy(&dr.frame.vad.voice, dsvt.vasd.voice, 12);
							dongle.SendRegister(dr);
							frame_pos_to_dvap ++;
							seq_to_dvap ++;

							inactive = 0;

							seq_no ++;
							if (seq_no == 21)
								seq_no = 0;

							if ((dsvt.ctrl & 0x40) != 0)
							{
								if (LOG_QSO)
									printf("End G2: streamid=%04x\n", ntohs(dsvt.streamid));

								streamid = 0;

								inactive = 0;
								FD_CLR (fd, &readfd);
								// maybe put a sleep here to prevent fast voice-overs

								busy20000 = false;
								break;
							}
						}
					}
				}
				else     // busy20000 is false
				{
					FD_CLR (fd, &readfd);
					break;
				}
			}
			else  	// len is not 56 or 27
			{
				if (!busy20000)
				{
					FD_CLR (fd, &readfd);
					break;
				}
			}
			FD_CLR (fd, &readfd);
		}

		// If we received a dup or select() timed out or streamids dont match,
		// then written_to_q is false
		if (!written_to_q)  	// we could also end up here if we are busy and we received a non-standard packet size
		{
			if (busy20000)
			{
				if (++inactive >= inactiveMax)
				{
					if (LOG_QSO)
						printf("G2 Timeout...\n");

					streamid = 0;

					inactive = 0;
					// maybe put a sleep here to prevent fast voice-overs

					busy20000 = false;
					break;
				}
				else  	// inactive too long
				{
					if (space == 127)
					{
						if (LOG_DEBUG)
							fprintf(stderr, "sending silent frame where: len=%d, inactive=%d\n", len, inactive);
						if (seq_no == 0)
						{
							silence[9]  = 0x55;
							silence[10] = 0x2d;
							silence[11] = 0x16;
						}
						else
						{
							silence[9]  = 0x70;
							silence[10] = 0x4f;
							silence[11] = 0x93;
						}

						SDVAP_REGISTER dr;
						dr.header = 0xc012u;
						if (memcmp(silence + 9, sync_codes, 3) == 0)
							frame_pos_to_dvap = 0;
						dr.frame.streamid = streamid;
						dr.frame.framepos = frame_pos_to_dvap;
						dr.frame.seq = seq_to_dvap;
						memcpy(&dr.frame.vad.voice, silence, 12);
						dongle.SendRegister(dr);
						frame_pos_to_dvap ++;
						seq_to_dvap++;

						seq_no++;
						if (seq_no == 21)
							seq_no = 0;
					}
				}
			}
			else	// busy20000 is false
				break;
		}
	}
	return;
}

void CQnetDVAP::RptrAckThread(SDVAP_ACK_ARG *parg)
{
	char mycall[8];
	memcpy(mycall, parg->mycall, 8);
	float ber = parg->ber;

	char RADIO_ID[21];

	sprintf(RADIO_ID, "%20.2f", ber);
	memcpy(RADIO_ID, "BER%", 4);

	unsigned char silence[12] = { 0x9e,0x8d,0x32,0x88,0x26,0x1a,0x3f,0x61,0xe8,0x70,0x4f,0x93 };

	sleep(TIMING_PLAY_WAIT);

	uint16_t sid = Random.NewStreamID();

	// HEADER
	while ((space < 1) && keep_running)
		usleep(5);
	SDVAP_REGISTER dr;
	dr.header = 0xa02fu;
	dr.frame.streamid = sid;
	dr.frame.framepos = 0x80;
	dr.frame.seq = 0;
	dr.frame.hdr.flag[0] = 0x01;
	dr.frame.hdr.flag[1] = dr.frame.hdr.flag[2] = 0x00;
	memcpy(dr.frame.hdr.rpt2, RPTR_and_MOD, 8);
	memcpy(dr.frame.hdr.rpt1, RPTR_and_G, 8);
	memcpy(dr.frame.hdr.urcall, mycall, 8);
	memcpy(dr.frame.hdr.mycall, RPTR_and_MOD, 8);
	memcpy(dr.frame.hdr.sfx, (unsigned char *)"DVAP", 4);
	calcPFCS(dr.frame.hdr.flag, dr.frame.hdr.pfcs);
	dongle.SendRegister(dr);
	std::this_thread::sleep_for(std::chrono::milliseconds(TIMING_PLAY_DELAY));

	// SYNC
	dr.header = 0xc012u;
	dr.frame.streamid = sid;
	for (int i=0; i<10; i++)
	{
		while ((space < 1) && keep_running)
			usleep(5);
		dr.frame.framepos = dr.frame.seq = i;
		switch (i)
		{
		case 0:
			silence[9] = 0x55;
			silence[10] = 0x2d;
			silence[11] = 0x16;
			break;
		case 1:
			silence[9]  = '@' ^ 0x70;
			silence[10] = RADIO_ID[0] ^ 0x4f;
			silence[11] = RADIO_ID[1] ^ 0x93;
			break;
		case 2:
			silence[9]  = RADIO_ID[2] ^ 0x70;
			silence[10] = RADIO_ID[3] ^ 0x4f;
			silence[11] = RADIO_ID[4] ^ 0x93;
			break;
		case 3:
			silence[9]  = 'A' ^ 0x70;
			silence[10] = RADIO_ID[5] ^ 0x4f;
			silence[11] = RADIO_ID[6] ^ 0x93;
			break;
		case 4:
			silence[9]  = RADIO_ID[7] ^ 0x70;
			silence[10] = RADIO_ID[8] ^ 0x4f;
			silence[11] = RADIO_ID[9] ^ 0x93;
			break;
		case 5:
			silence[9]  = 'B' ^ 0x70;
			silence[10] = RADIO_ID[10] ^ 0x4f;
			silence[11] = RADIO_ID[11] ^ 0x93;
			break;
		case 6:
			silence[9]  = RADIO_ID[12] ^ 0x70;
			silence[10] = RADIO_ID[13] ^ 0x4f;
			silence[11] = RADIO_ID[14] ^ 0x93;
			break;
		case 7:
			silence[9]  = 'C' ^ 0x70;
			silence[10] = RADIO_ID[15] ^ 0x4f;
			silence[11] = RADIO_ID[16] ^ 0x93;
			break;
		case 8:
			silence[9]  = RADIO_ID[17] ^ 0x70;
			silence[10] = RADIO_ID[18] ^ 0x4f;
			silence[11] = RADIO_ID[19] ^ 0x93;
			break;
		case 9:
			silence[0] = 0x55;
			silence[1] = 0xc8;
			silence[2] = 0x7a;
			silence[9] = 0x55;
			silence[10] = 0x55;
			silence[11] = 0x55;
			dr.frame.framepos |= 0x40;
			break;
		}
		memcpy(&dr.frame.vad.voice, silence, 12);
		dongle.SendRegister(dr);
		if (i < 9)
			std::this_thread::sleep_for(std::chrono::milliseconds(TIMING_PLAY_DELAY));
	}
	return;
}

void CQnetDVAP::ReadDVAPThread()
{
	REPLY_TYPE reply;
	SDSVT dsvt;
	SDVAP_REGISTER dr;
	CTimer last_RF_time;
	bool dvap_busy = false;
	// bool ptt = false;
	bool the_end = true;
	bool ok = true;
	int i = 0;
	u_int16_t streamid_raw = 0;
	short int sequence = 0;
	char mycall[8];
	short int status_cntr = 3000;

	int num_dv_frames = 0;
	int num_bit_errors = 0;

	while (keep_running)
	{

		// local RF user went away ?
		if (dvap_busy)
		{
			if (last_RF_time.time() > TIMING_TIMEOUT_LOCAL_RPTR)
				dvap_busy = false;
		}

		// read from the dvap and process
		reply = dongle.GetReply(dr);
		if (reply == RT_ERR)
		{
			printf("Detected ERROR event from DVAP dongle, stopping...n");
			break;
		}
		else if (reply == RT_STOP)
		{
			printf("Detected STOP event from DVAP dongle, stopping...\n");
			break;
		}
		else if (reply == RT_START)
		{
			printf("Detected START event from DVAP dongle\n");
			// else if (reply == RT_PTT) {
			// 	ptt = (dvp_buf[4] == 0x01);
			// 	printf("Detected PTT=%s\n", ptt?"on":"off");
		}
		else if (reply == RT_STS)
		{
			space = (unsigned int)dr.param.sstr[2];
			if (status_cntr < 3000)
				status_cntr += 20;
		}
		else if (reply == RT_HDR)
		{
			num_dv_frames = 0;
			num_bit_errors = 0;

			if (LOG_QSO)
				printf("From DVAP: flags=%02x:%02x:%02x, my=%.8s, sfx=%.4s, ur=%.8s, rpt1=%.8s, rpt2=%.8s\n", dr.frame.hdr.flag[0], dr.frame.hdr.flag[1], dr.frame.hdr.flag[2], dr.frame.hdr.mycall, dr.frame.hdr.sfx, dr.frame.hdr.urcall, dr.frame.hdr.rpt1, dr.frame.hdr.rpt2);

			ok = true;

			/* Accept valid flags only */
			if (ok)
			{
				if ((dr.frame.hdr.flag[0] != 0x00) && (dr.frame.hdr.flag[0] != 0x08) &&	// net
						(dr.frame.hdr.flag[0] != 0x20) && (dr.frame.hdr.flag[0] != 0x28) &&	// flags

						(dr.frame.hdr.flag[0] != 0x40) && (dr.frame.hdr.flag[0] != 0x48) &&	// rptr
						(dr.frame.hdr.flag[0] != 0x60) && (dr.frame.hdr.flag[0] != 0x68))	// flags
					ok = false;
			}

			memcpy(dsvt.hdr.flag, dr.frame.hdr.flag, 41);	// copy the header

			/* RPT1 must always be the repeater + module */
			memcpy(dsvt.hdr.rpt1, RPTR_and_MOD, 8);
			/* copy RPT2 */
			memcpy(dsvt.hdr.rpt2, dr.frame.hdr.rpt2, 8);

			/* RPT2 must also be valid */
			if ((dsvt.hdr.rpt2[7] == 'A') ||
					(dsvt.hdr.rpt2[7] == 'B') ||
					(dsvt.hdr.rpt2[7] == 'C') ||
					(dsvt.hdr.rpt2[7] == 'G'))
				memcpy(dsvt.hdr.rpt2, RPTR.c_str(), 7);
			else
				memset(dsvt.hdr.rpt2, ' ', 8);

			if ((memcmp(dsvt.hdr.urcall, "CQCQCQ", 6) != 0) && (dsvt.hdr.rpt2[0] != ' '))
				memcpy(dsvt.hdr.rpt2,  RPTR_and_G, 8);

			/* 8th in rpt1, rpt2 must be diff */
			if (dsvt.hdr.rpt2[7] == dsvt.hdr.rpt1[7])
				memset(dsvt.hdr.rpt2, ' ', 8);

			/*
			   Are we restricting the RF user ?
			   If RPTR is OWNER, then any RF user can talk.
			   If RPTR is not OWNER,
			   that means that mycall, rpt1, rpt2 must be equal to RPTR
			     otherwise we drop the rf data
			*/
			if (RPTR.compare(OWNER))
			{
				if (memcmp(dsvt.hdr.mycall, RPTR.c_str(), CALL_SIZE) != 0)
				{
					printf("mycall=[%.8s], not equal to %s\n", dsvt.hdr.mycall, RPTR.c_str());
					ok = false;
				}
			}
			else if (memcmp(dsvt.hdr.mycall, "        ", 8) == 0)
			{
				printf("Invalid value for mycall=[%.8s]\n", dsvt.hdr.mycall);
				ok = false;
			}

			if (ok)
			{
				for (i = 0; i < 8; i++)
				{
					if (!isupper(dsvt.hdr.mycall[i]) &&
							!isdigit(dsvt.hdr.mycall[i]) &&
							(dsvt.hdr.mycall[i] != ' '))
					{
						memset(dsvt.hdr.mycall, ' ', 8);
						ok = false;
						printf("Invalid value for MYCALL\n");
						break;
					}
				}

				for (i = 0; i < 4; i++)
				{
					if (!isupper(dsvt.hdr.sfx[i]) &&
							!isdigit(dsvt.hdr.sfx[i]) &&
							(dsvt.hdr.sfx[i] != ' '))
					{
						memset(dsvt.hdr.sfx, ' ', 4);
						break;
					}
				}

				for (i = 0; i < 8; i++)
				{
					if (!isupper(dsvt.hdr.urcall[i]) &&
							!isdigit(dsvt.hdr.urcall[i]) &&
							(dsvt.hdr.urcall[i] != ' ') &&
							(dsvt.hdr.urcall[i] != '/'))
					{
						memcpy(dsvt.hdr.urcall, "CQCQCQ  ", 8);
						break;
					}
				}

				/*** what if YRCALL is all spaces, we can NOT allow that ***/
				if (memcmp(dsvt.hdr.urcall, "        ", 8) == 0)
					memcpy(dsvt.hdr.urcall, "CQCQCQ  ", 8);

				/* change the rptr flags to net flags */
				if (dr.frame.hdr.flag[0] == 0x40)
					dsvt.hdr.flag[0] = 0x00;
				else if (dr.frame.hdr.flag[0] == 0x48)
					dsvt.hdr.flag[0] = 0x08;
				else if (dr.frame.hdr.flag[0] == 0x60)
					dsvt.hdr.flag[0] = 0x20;
				else if (dr.frame.hdr.flag[0] == 0x68)
					dsvt.hdr.flag[0] = 0x28;
				else
					dsvt.hdr.flag[0] = 0x00;
				dsvt.hdr.flag[1] = dsvt.hdr.flag[2] = 0x00;

				// Before we send the data to the local gateway,
				// set RPT1, RPT2 to be the local gateway
				memcpy(dsvt.hdr.rpt1, OWNER.c_str(), 7);
				if (dsvt.hdr.rpt2[7] != ' ')
					memcpy(dsvt.hdr.rpt2, OWNER.c_str(), 7);

				memcpy(dsvt.title, "DSVT", 4);
				dsvt.config = 0x10U;
				dsvt.id = 0x20;
				streamid_raw = Random.NewStreamID();
				dsvt.streamid = streamid_raw;
				dsvt.ctrl = 0x80;
				sequence = 0;
				calcPFCS((unsigned char *)&(dsvt.hdr), dsvt.hdr.pfcs);
				ToGate.Write(dsvt.title, 56);

				// local RF user keying up, start timer
				dvap_busy = true;
				last_RF_time.start();

				// save mycall for the ack later
				memcpy(mycall, dr.frame.hdr.mycall, 8);

			}
		}
		else if (reply == RT_DAT)
		{
			/* have we already received a header ? */
			if (dvap_busy)
			{
				the_end = ((dr.frame.framepos & 0x40) == 0x40);

				dsvt.config = 0x20U;
				dsvt.ctrl = sequence++;
				if (the_end)
					dsvt.ctrl = sequence | 0x40;
				memcpy(&dsvt.vasd, &dr.frame.vad.voice, 12);
				ToGate.Write(dsvt.title, 27);

				int ber_data[3];
				int ber_errs = decode.Decode(dsvt.vasd.voice, ber_data);
				if (ber_data[0] != 0xf85)
				{
					num_bit_errors += ber_errs;
					num_dv_frames++;
				}

				if (sequence > 0x14)
					sequence = 0;

				// local RF user still talking, update timer
				last_RF_time.start();
				if (the_end)
				{
					// local RF user stopped talking
					dvap_busy = false;
					SDVAP_ACK_ARG dvap_ack_arg;
					dvap_ack_arg.ber = (num_dv_frames==0) ? 0.f : 100.f * (float)num_bit_errors / (float)(num_dv_frames * 24);
					if (LOG_QSO)
						printf("End of dvap audio,  ber=%.02f\n", dvap_ack_arg.ber);

					if (MODULE_ACKNOWLEDGE && !busy20000)
					{
						memcpy(dvap_ack_arg.mycall, mycall, 8);
						try
						{
							std::async(std::launch::async, &CQnetDVAP::RptrAckThread, this, &dvap_ack_arg);
						}
						catch (const std::exception &e)
						{
							printf("Failed to start RptrAckThread(). Exception: %s\n", e.what());
						}
					}
				}
			}
		}
		usleep(1000);
		status_cntr--;
		if (status_cntr < 0)
			break;
	}

	/* stop dvap */
	dongle.Stop();
	close(serfd);

	printf("ReadDVAPThread exiting\n");

	keep_running = false;
	return;
}

bool CQnetDVAP::Init(const char *file, const int amod)
{
	assigned_module = amod;

	if (ReadConfig(file))
	{
		printf("Failed to process config file %s\n", file);
		return true;
	}

	if (RPTR.length() != 8)
	{
		printf("Bad RPTR value, length must be exactly 8 bytes\n");
		return true;
	}
	if ((RPTR_MOD != 'A') && (RPTR_MOD != 'B') && (RPTR_MOD != 'C'))
	{
		printf("Bad RPTR_MOD value, must be one of A or B or C\n");
		return true;
	}

	if (RPTR_MOD == 'A')
		SND_TERM_ID = 0x03;
	else if (RPTR_MOD == 'B')
		SND_TERM_ID = 0x01;
	else if (RPTR_MOD == 'C')
		SND_TERM_ID = 0x02;

	strcpy(RPTR_and_G, RPTR.c_str());
	RPTR_and_G[7] = 'G';

	strcpy(RPTR_and_MOD, RPTR.c_str());
	RPTR_and_MOD[7] = RPTR_MOD;

	/* open dvp */
	if (!dongle.Initialize(MODULE_DEVICE.c_str(), MODULE_SERIAL_NUMBER.c_str(), MODULE_FREQUENCY, MODULE_OFFSET, MODULE_POWER, MODULE_SQUELCH))
		return true;

	if (ToGate.Open(togate.c_str(), this))
	{
		dongle.Stop();
		close(serfd);
		return true;
	}
	printf("DVAP opened and initialized!\n");
	return false;
}

void CQnetDVAP::Run()
{
	CTimer ackpoint;
	std::future<void> readthread;
	try
	{
		readthread = std::async(std::launch::async, &CQnetDVAP::ReadDVAPThread, this);
	}
	catch (const std::exception &e)
	{
		printf("Unable to start ReadDVAPThread(). Exception: %s\n", e.what());
		keep_running = false;
	}
	printf("Started ReadDVAPThread()\n");

	int cnt = 0;
	while (keep_running)
	{
		if (ackpoint.time() > 2.5)
		{
			int rc = dongle.KeepAlive();
			if (rc < 0)
			{
				cnt ++;
				if (cnt > 5)
				{
					printf("Could not send KEEPALIVE signal to dvap 5 times...exiting\n");
					keep_running = false;
				}
			}
			else
				cnt = 0;
			ackpoint.start();
		}
		ReadFromGateway();
	}

	readthread.get();
	ToGate.Close();
	printf("QnetDVAP exiting\n");
	return;
}

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	printf("dvap_rptr VERSION %s\n", DVAP_VERSION);

	if (argc != 2)
	{
		fprintf(stderr, "Usage: %s dvap_rptr.cfg\n", argv[0]);
		return EXIT_FAILURE;
	}

	if ('-' == argv[1][0])
	{
		printf("\nQnetDVAP Version #%s Copyright (C) 2018-2020 by Thomas A. Early N7TAE\n", DVAP_VERSION);
		printf("QnetDVAP comes with ABSOLUTELY NO WARRANTY; see the LICENSE for details.\n");
		printf("This is free software, and you are welcome to distribute it\nunder certain conditions that are discussed in the LICENSE file.\n\n");
		return EXIT_SUCCESS;
	}

	const char *qn = strstr(argv[0], "qndvap");
	if (NULL == qn)
	{
		fprintf(stderr, "Error finding 'qndvap' in %s!\n", argv[0]);
		return EXIT_FAILURE;
	}
	qn += 6;

	int mod;
	switch (*qn)
	{
	case NULL:
		mod = -1;
		break;
	case 'a':
		mod = 0;
		break;
	case 'b':
		mod = 1;
		break;
	case 'c':
		mod = 2;
		break;
	default:
		fprintf(stderr, "ERROR: '%s' is not a valid module\nassigned module must be a, b or c\n", argv[1]);
		return 1;
	}

	CQnetDVAP dvap;
	if (dvap.Init(argv[1], mod))
		return EXIT_FAILURE;
	dvap.Run();
	return EXIT_SUCCESS;
}
