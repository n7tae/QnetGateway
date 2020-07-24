/*
 *   Copyright (C) 2010 by Scott Lawson KI4LKF
 *   Copyright (C) 2018-2020 by Thomas A. Early N7TAE
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
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <string>

#include "QnetTypeDefs.h"
#include "Random.h"
#include "QnetConfigure.h"
#include "UnixDgramSocket.h"

#define VERSION "v523"

#ifndef CFG_DIR
#define CFG_DIR "/usr/local/etc"
#endif

static int module;
static time_t tNow = 0;
static short streamid_raw = 0;
static std::string REPEATER, togateway;
static int PLAY_WAIT, PLAY_DELAY;

static unsigned char silence[9] = { 0x9E, 0x8D, 0x32, 0x88, 0x26, 0x1A, 0x3F, 0x61, 0xE8 };


static unsigned short crc_tabccitt[256] =
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

static CQnetConfigure cfg;

static bool ReadCfgFile()
{
	const std::string estr;
	std::string type;
	std::string path = "module_";
	path.append(1, 'a'+module);

	if (! cfg.KeyExists(path))
	{
		fprintf(stderr, "%s not defined!\n", path.c_str());
		return true;
	}
	cfg.GetValue(path, estr, type, 1, 16);

	cfg.GetValue(path+"_callsign", type, REPEATER, 0, 6);
	if (REPEATER.length() < 4)
	{
		if (cfg.GetValue("ircddb_login", estr, REPEATER, 3, 6))
		{
			fprintf(stderr, "no Callsign for the repeater was found!\n");
			return true;
		}
	}
	cfg.GetValue("gateway_fromremote", estr, togateway, 1, FILENAME_MAX);

	cfg.GetValue("timing_play_wait", estr, PLAY_WAIT, 1, 10);
	cfg.GetValue("timing_play_delay", estr, PLAY_DELAY, 15, 25);
	return false;
}

static void calcPFCS(unsigned char rawbytes[56])
{
	unsigned short crc_dstar_ffff = 0xffff;
	unsigned short tmp, short_c;
	short int i;

	for (i = 15; i < 54 ; i++)
	{
		short_c = 0x00ff & (unsigned short)rawbytes[i];
		tmp = (crc_dstar_ffff & 0x00ff) ^ short_c;
		crc_dstar_ffff = (crc_dstar_ffff >> 8) ^ crc_tabccitt[tmp];
	}
	crc_dstar_ffff =  ~crc_dstar_ffff;
	tmp = crc_dstar_ffff;

	rawbytes[54] = (unsigned char)(crc_dstar_ffff & 0xff);
	rawbytes[55] = (unsigned char)((tmp >> 8) & 0xff);
	return;
}

static void ToUpper(std::string &str)
{
	for (unsigned int i=0; i<str.size(); i++)
		if (islower(str[i]))
			str[i] = toupper(str[i]);
}

int main(int argc, char *argv[])
{
	if (argc != 4)
	{
		fprintf(stderr, "Usage: %s <module> <mycall> <yourcall>\n", argv[0]);
		fprintf(stderr, "Example: %s c n7tae xrf757al\n", argv[0]);
		fprintf(stderr, "Where...\n");
		fprintf(stderr, "        c is the local repeater module\n");
		fprintf(stderr, "        n7tae is the value of mycall\n");
		fprintf(stderr, "        xrf757al is the value of yourcall, in this case this is a Link command\n\n");
		return 0;
	}

	switch (argv[1][0])
	{
	case '0':
	case 'a':
	case 'A':
		module = 0;
		break;
	case '1':
	case 'b':
	case 'B':
		module = 1;
		break;
	case '2':
	case 'c':
	case 'C':
		module = 2;
		break;
	default:
		fprintf(stderr, "module must be 0, a, A, 1, b, B, 2, c or C, not %s\n", argv[1]);
		return 1;
	}

	std::string cfgfile(CFG_DIR);
	cfgfile += "/qn.cfg";
	if (cfg.Initialize(cfgfile.c_str()))
		return 1;

	if (ReadCfgFile())
		return 1;

	if (REPEATER.size() > 6)
	{
		printf("repeaterCallsign can not be more than 6 characters, %s is invalid\n", REPEATER.c_str());
		return 1;
	}
	ToUpper(REPEATER);

	if (strlen(argv[2]) > 8)
	{
		printf("MYCALL can not be more than 8 characters, %s is invalid\n", argv[2]);
		return 1;
	}
	std::string mycall(argv[2]);
	ToUpper(mycall);


	if (strlen(argv[3]) > 8)
	{
		printf("YOURCALL can not be more than 8 characters, %s is invalid\n", argv[3]);
		return 1;
	}
	std::string yourcall(argv[3]);
	ToUpper(yourcall);
	// replace underscores with spaces
	auto pos = yourcall.find_first_of('_');
	while (yourcall.npos != pos)
	{
		yourcall[pos] = ' ';
		pos = yourcall.find_first_of('_');
	}

	unsigned long int delay = PLAY_DELAY * 1000;
	sleep(PLAY_WAIT);

	std::string RADIO_ID("QnetRemote ");
	RADIO_ID.append(VERSION);
	RADIO_ID.resize(20, ' ');

	time(&tNow);
	CRandom Random;
	CUnixDgramWriter ToGateway;
	ToGateway.SetUp(togateway.c_str());

	SDSVT pkt;
	memcpy(pkt.title, "DSVT", 4);
	pkt.config = 0x10U;
	memset(pkt.flaga, 0U, 3U);
	pkt.id = 0x20U;
	pkt.flagb[0] = 0x0U;
	pkt.flagb[1] = 0x1U;
	if (module == 0)
		pkt.flagb[2] = 0x3U;
	else if (module == 1)
		pkt.flagb[2] = 0x1U;
	else if (module == 2)
		pkt.flagb[2] = 0x2U;
	else
		pkt.flagb[3] = 0x0U;
	streamid_raw = Random.NewStreamID();
	pkt.streamid = htons(streamid_raw);
	pkt.ctrl = 0x80;
	pkt.hdr.flag[0] = pkt.hdr.flag[1] = pkt.hdr.flag[2] = 0x00;

	REPEATER.resize(7, ' ');
	memcpy(pkt.hdr.rpt2, REPEATER.c_str(), 8);
	pkt.hdr.rpt2[7] = 'G';
	memcpy(pkt.hdr.rpt1, REPEATER.c_str(), 8);
	pkt.hdr.rpt1[7] = 'A' + module;
	mycall.resize(8, ' ');
	memcpy(pkt.hdr.mycall, mycall.c_str(), 8);
	memcpy(pkt.hdr.sfx, "QNET", 4);
	if (yourcall.size() < 3)
		yourcall = std::string(8-yourcall.size(), ' ') + yourcall;	// right justify 1 or 2 letter commands
	else
		yourcall.resize(8, ' ');
	memcpy(pkt.hdr.urcall, yourcall.c_str(), 8);

	calcPFCS(pkt.title);
	// send the header
	if (56 !=  ToGateway.Write(pkt.title, 56))
	{
		printf("%s: ERROR: Couldn't send header!\n", argv[0]);
		return 1;
	}

	// prepare and send 10 voice packets
	pkt.config = 0x20U;
	memcpy(pkt.vasd.voice, silence, 9);

	for (int i=0; i<10; i++)
	{
		/* start sending silence + text */
		pkt.ctrl = i;

		switch (i)
		{
		case 0:	// sync voice frame
			pkt.vasd.text[0] = 0x55;
			pkt.vasd.text[1] = 0x2d;
			pkt.vasd.text[2] = 0x16;
			break;
		case 1:
			pkt.vasd.text[0] = '@' ^ 0x70;
			pkt.vasd.text[1] = RADIO_ID[0] ^ 0x4f;
			pkt.vasd.text[2] = RADIO_ID[1] ^ 0x93;
			break;
		case 2:
			pkt.vasd.text[0] = RADIO_ID[2] ^ 0x70;
			pkt.vasd.text[1] = RADIO_ID[3] ^ 0x4f;
			pkt.vasd.text[2] = RADIO_ID[4] ^ 0x93;
			break;
		case 3:
			pkt.vasd.text[0] = 'A' ^ 0x70;
			pkt.vasd.text[1] = RADIO_ID[5] ^ 0x4f;
			pkt.vasd.text[2] = RADIO_ID[6] ^ 0x93;
			break;
		case 4:
			pkt.vasd.text[0] = RADIO_ID[7] ^ 0x70;
			pkt.vasd.text[1] = RADIO_ID[8] ^ 0x4f;
			pkt.vasd.text[2] = RADIO_ID[9] ^ 0x93;
			break;
		case 5:
			pkt.vasd.text[0] = 'B' ^ 0x70;
			pkt.vasd.text[1] = RADIO_ID[10] ^ 0x4f;
			pkt.vasd.text[2] = RADIO_ID[11] ^ 0x93;
			break;
		case 6:
			pkt.vasd.text[0] = RADIO_ID[12] ^ 0x70;
			pkt.vasd.text[1] = RADIO_ID[13] ^ 0x4f;
			pkt.vasd.text[2] = RADIO_ID[14] ^ 0x93;
			break;
		case 7:
			pkt.vasd.text[0] = 'C' ^ 0x70;
			pkt.vasd.text[1] = RADIO_ID[15] ^ 0x4f;
			pkt.vasd.text[2] = RADIO_ID[16] ^ 0x93;
			break;
		case 8:
			pkt.vasd.text[0] = RADIO_ID[17] ^ 0x70;
			pkt.vasd.text[1] = RADIO_ID[18] ^ 0x4f;
			pkt.vasd.text[2] = RADIO_ID[19] ^ 0x93;
			break;
		case 9:	// terminal voice packet
			pkt.ctrl |= 0x40;
			pkt.vasd.text[0] = 0x70;
			pkt.vasd.text[1] = 0x4f;
			pkt.vasd.text[2] = 0x93;
			break;
		}

		if (27 != ToGateway.Write(pkt.title, 27))
		{
			printf("%s: ERROR: could not send voice packet %d\n", argv[0], i);
			return 1;
		}
		usleep(delay);
	}
	return 0;
}
