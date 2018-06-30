/*
 *   Copyright (C) 2010 by Scott Lawson KI4LKF
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
#include <libconfig.h++>

#include "QnetTypeDefs.h"
#include "Random.h"

using namespace libconfig;

#define VERSION "v3.1"

int sockDst = -1;
struct sockaddr_in toDst;
FILE *fp = NULL;
time_t tNow = 0;
short streamid_raw = 0;
int moduleport[3] = { 0, 0, 0 };
std::string moduleip[3];
std::string REPEATER;
int PORT, PLAY_WAIT, PLAY_DELAY;
bool is_icom = false;

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



void calcPFCS(unsigned char rawbytes[58])
{
	unsigned short crc_dstar_ffff = 0xffff;
	unsigned short tmp, short_c;
	short int i;

	for (i = 17; i < 56 ; i++) {
		short_c = 0x00ff & (unsigned short)rawbytes[i];
		tmp = (crc_dstar_ffff & 0x00ff) ^ short_c;
		crc_dstar_ffff = (crc_dstar_ffff >> 8) ^ crc_tabccitt[tmp];
	}
	crc_dstar_ffff =  ~crc_dstar_ffff;
	tmp = crc_dstar_ffff;

	rawbytes[56] = (unsigned char)(crc_dstar_ffff & 0xff);
	rawbytes[57] = (unsigned char)((tmp >> 8) & 0xff);
	return;

}

bool dst_open(const char *ip, const short port)
{
	sockDst = socket(PF_INET,SOCK_DGRAM,0);
	if (sockDst == -1) {
		printf("Failed to create DSTAR socket\n");
		return true;
	}
	fcntl(sockDst,F_SETFL,O_NONBLOCK);

	int reuse = 1;
	if (setsockopt(sockDst,SOL_SOCKET,SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) == -1) {
		close(sockDst);
		sockDst = -1;
		printf("setsockopt DSTAR REUSE failed\n");
		return true;
	}
	memset(&toDst,0,sizeof(struct sockaddr_in));
	toDst.sin_family = AF_INET;
	toDst.sin_port = htons(port);
	toDst.sin_addr.s_addr = inet_addr(ip);

	if (bind(sockDst, (struct sockaddr *)&toDst, sizeof(struct sockaddr_in)) != 0) {
		printf("Failed to bind %s:%d, errno=%d, %s\n", ip, port, errno, strerror(errno));
		close(sockDst);
		sockDst = -1;
		return true;
	}
	return false;
}

void dst_close()
{
	if (sockDst != -1) {
		close(sockDst);
		sockDst = -1;
	}
	return;
}

bool get_value(const Config &cfg, const char *path, int &value, int min, int max, int default_value)
{
	if (cfg.lookupValue(path, value)) {
		if (value < min || value > max)
			value = default_value;
	} else
		value = default_value;
	printf("%s = [%d]\n", path, value);
	return true;
}

bool get_value(const Config &cfg, const char *path, double &value, double min, double max, double default_value)
{
	if (cfg.lookupValue(path, value)) {
		if (value < min || value > max)
			value = default_value;
	} else
		value = default_value;
	printf("%s = [%lg]\n", path, value);
	return true;
}

bool get_value(const Config &cfg, const char *path, bool &value, bool default_value)
{
	if (! cfg.lookupValue(path, value))
		value = default_value;
	printf("%s = [%s]\n", path, value ? "true" : "false");
	return true;
}

bool get_value(const Config &cfg, const char *path, std::string &value, int min, int max, const char *default_value)
{
	if (cfg.lookupValue(path, value)) {
		int l = value.length();
		if (l<min || l>max) {
			printf("%s is invalid\n", path);
			return false;
		}
	} else
		value = default_value;
	printf("%s = [%s]\n", path, value.c_str());
	return true;
}

/* process configuration file */
bool read_config(const char *cfgFile)
{
	Config cfg;

	printf("Reading file %s\n", cfgFile);
	// Read the file. If there is an error, report it and exit.
	try {
		cfg.readFile(cfgFile);
	} catch(const FileIOException &fioex) {
		printf("Can't read %s\n", cfgFile);
		return true;
	} catch(const ParseException &pex) {
		printf("Parse error at %s:%d - %s\n", pex.getFile(), pex.getLine(), pex.getError());
		return true;
	}

	if (! get_value(cfg, "ircddb.login", REPEATER, 3, 6, "UNDEFINED"))
		return true;
	REPEATER.resize(6, ' ');
	printf("REPEATER=[%s]\n", REPEATER.c_str());

	for (short int m=0; m<3; m++) {
		std::string path = "module.";
		path += m + 'a';
		std::string type;
		if (cfg.lookupValue(std::string(path+".type").c_str(), type)) {
			if (strcasecmp(type.c_str(), "dvap") && strcasecmp(type.c_str(), "dvrptr") && strcasecmp(type.c_str(), "mmdvm") && strcasecmp(type.c_str(), "icom")) {
				printf("module type '%s' is invalid\n", type.c_str());
				return true;
			}
			is_icom = strcasecmp(type.c_str(), "icom") ? false : true;
			get_value(cfg, std::string(path+".port").c_str(), moduleport[m], 1000, 65535, is_icom ? 20000 : 19998+m);
			if (! get_value(cfg, std::string(path+".ip").c_str(), moduleip[m], 7, 15, is_icom ? "172.16.0.20" : "127.0.0.1"))
				return true;
		}
	}
	if (0==moduleport[0] && 0==moduleport[1] && 0==moduleport[2]) {
		printf("No repeaters defined!\n");
		return true;
	}

	get_value(cfg, "timing.play.wait", PLAY_WAIT, 1, 10, 2);

	get_value(cfg, "timing.play.delay", PLAY_DELAY, 9, 25, 19);

	return false;
}

void ToUpper(std::string &str)
{
	for (unsigned int i=0; i<str.size(); i++)
		if (islower(str[i]))
			str[i] = toupper(str[i]);
}

int main(int argc, char *argv[])
{
	unsigned short rlen = 0;
	static unsigned short G2_COUNTER = 0;
	size_t nread = 0;
	SDSVT dsvt;
	SDSTR dstr;
	char RADIO_ID[21];
	short int TEXT_idx = 0;

	if (argc != 4) {
		printf("Usage: %s <module> <mycall> <dvtoolFile>\n", argv[0]);
		printf("Where...\n");
		printf("        module is one of your modules\n");
		printf("        mycall is your personal callsign\n");
		printf("        dvtoolFile is a dvtool file\n");
		return 0;
	}

	std::string cfgfile(CFG_DIR);
	cfgfile += "/qn.cfg";
	if (read_config(cfgfile.c_str()))
		return 1;

	if (REPEATER.size() > 6) {
		printf("repeaterCallsign can not be more than 6 characters, %s is invalid\n", REPEATER.c_str());
		return 1;
	}
	ToUpper(REPEATER);

	char module = argv[1][0];
	if (islower(module))
		module = toupper(module);
	if ((module != 'A') && (module != 'B') && (module != 'C')) {
		printf("module must be one of A B C\n");
		return 1;
	}

	PORT = moduleport[module - 'A'];
	std::string IP_ADDRESS(moduleip[module - 'A']);
	if (0 == PORT) {
		printf("module %c has no port defined!\n", module);
		return 1;
	}

	if (strlen(argv[2]) > 8) {
		printf("MYCALL can not be more than 8 characters, %s is invalid\n", argv[2]);
		return 1;
	}
	std::string mycall(argv[2]);
	ToUpper(mycall);

	fp = fopen(argv[3], "rb");
	if (!fp) {
		printf("Failed to open file %s for reading\n", argv[3]);
		return 1;
	}

	/* DVTOOL + 4 byte num_of_records */
	unsigned char buf[10];
	nread = fread(buf, 10, 1, fp);
	if (nread != 1) {
		printf("Cant read first 10 bytes\n");
		fclose(fp);
		return 1;
	}
	if (0 != memcmp(buf, "DVTOOL", 6)) {
		printf("DVTOOL signature not found in %s\n", argv[3]);
		fclose(fp);
		return 1;
	}

	memset(RADIO_ID, ' ', 20);
	RADIO_ID[20] = '\0';

	memcpy(RADIO_ID, "QnetVoice", 9);

	unsigned long int delay = PLAY_DELAY * 1000L;
	sleep(PLAY_WAIT);

	time(&tNow);
	CRandom Random;

	short int sport = (short int)PORT;
	if (dst_open(IP_ADDRESS.c_str(), sport))
		return 1;
	printf("Opened %s:%u for writing\n", IP_ADDRESS.c_str(), sport);

	// Read and reformat and write packets
	while (true) {
		/* 2 byte length */
		nread = fread(&rlen, 2, 1, fp);
		if (nread != 1) {
			printf("End-Of-File\n");
			break;
		}
		if (rlen == 56)
			streamid_raw = Random.NewStreamID();
		else if (rlen == 27)
			;
		else {
			printf("Wrong packet size!\n");
			return 1;
		}

		/* read the packet */
		nread = fread(dsvt.title, rlen, 1, fp);
		printf("Read %d byte packet from %s\n", (int)nread*rlen, argv[3]);
		if (rlen == 56)
			printf("rpt1=%.8s rpt2=%.8s urcall=%.8s, mycall=%.8s, sfx=%.4s\n",
			dsvt.hdr.rpt1, dsvt.hdr.rpt2, dsvt.hdr.urcall, dsvt.hdr.mycall, dsvt.hdr.sfx);
		else
			printf("streamid=%04X counter=%02X\n", dsvt.streamid, dsvt.counter);
		if (nread == 1) {
			if (memcmp(dsvt.title, "DSVT", 4) != 0) {
				printf("DVST title not found\n");
				return 1;
			}

			if (dsvt.id != 0x20) {
				printf("Not Voice type\n");
				return 1;
			}

			if (dsvt.config!=0x10 && dsvt.config!=0x20) {
				printf("Not a valid record type\n");
				return 1;
			}

			dstr.counter = htons(G2_COUNTER++);
			if (rlen == 56) {
				memcpy(dstr.pkt_id, "DSTR", 4);
				dstr.flag[0] = 0x73;
				dstr.flag[1] = 0x12;
				dstr.flag[2] = 0x00;
				dstr.remaining = 0x30;
				dstr.vpkt.icm_id = 0x20;
				dstr.vpkt.dst_rptr_id = dsvt.flagb[0];
				dstr.vpkt.snd_rptr_id = dsvt.flagb[1];
				//dstr.vpkt.snd_term_id = dsvt.flagb[2];
				if (module == 'A')
					dstr.vpkt.snd_term_id = 0x03;
				else if (module == 'B')
					dstr.vpkt.snd_term_id = 0x01;
				else if (module == 'C')
					dstr.vpkt.snd_term_id = 0x02;
				else
					dstr.vpkt.snd_term_id = 0x00;
				dstr.vpkt.streamid = htons(streamid_raw);
				dstr.vpkt.ctrl = dsvt.counter;
				for (int i=0; i<3; i++)
					dstr.vpkt.hdr.flag[i] = dsvt.hdr.flag[i];
				memset(dstr.vpkt.hdr.flag+3, ' ', 36);
				memcpy(dstr.vpkt.hdr.flag+3, REPEATER.c_str(), REPEATER.size());
				dstr.vpkt.hdr.r1[7] = module;
				memcpy(dstr.vpkt.hdr.r1, REPEATER.c_str(), REPEATER.size());
				dstr.vpkt.hdr.r2[7] = 'G';
				memcpy(dstr.vpkt.hdr.ur, "CQCQCQ", 6);	/* yrcall */
				memcpy(dstr.vpkt.hdr.my, mycall.c_str(), mycall.size());
				memcpy(dstr.vpkt.hdr.nm, "QNET", 4);
				calcPFCS(dstr.pkt_id);
			} else {
				dstr.remaining = 0x13;
				dstr.vpkt.ctrl = dsvt.counter;
				memcpy(dstr.vpkt.vasd.voice, dsvt.vasd.voice, 12);

				if ((dstr.vpkt.vasd.text[0] != 0x55) || (dstr.vpkt.vasd.text[1] != 0x2d) || (dstr.vpkt.vasd.text[2] != 0x16)) {
					if (TEXT_idx == 0) {
						dstr.vpkt.vasd.text[0] = '@' ^ 0x70;
						dstr.vpkt.vasd.text[1] = RADIO_ID[TEXT_idx++] ^ 0x4f;
						dstr.vpkt.vasd.text[2] = RADIO_ID[TEXT_idx++] ^ 0x93;
					} else if (TEXT_idx == 2) {
						dstr.vpkt.vasd.text[0] = RADIO_ID[TEXT_idx++] ^ 0x70;
						dstr.vpkt.vasd.text[1] = RADIO_ID[TEXT_idx++] ^ 0x4f;
						dstr.vpkt.vasd.text[2] = RADIO_ID[TEXT_idx++] ^ 0x93;
					} else if (TEXT_idx == 5) {
						dstr.vpkt.vasd.text[0] = 'A' ^ 0x70;
						dstr.vpkt.vasd.text[1] = RADIO_ID[TEXT_idx++] ^ 0x4f;
						dstr.vpkt.vasd.text[2] = RADIO_ID[TEXT_idx++] ^ 0x93;
					} else if (TEXT_idx == 7) {
						dstr.vpkt.vasd.text[0] = RADIO_ID[TEXT_idx++] ^ 0x70;
						dstr.vpkt.vasd.text[1] = RADIO_ID[TEXT_idx++] ^ 0x4f;
						dstr.vpkt.vasd.text[2] = RADIO_ID[TEXT_idx++] ^ 0x93;
					} else if (TEXT_idx == 10) {
						dstr.vpkt.vasd.text[0] = 'B' ^ 0x70;
						dstr.vpkt.vasd.text[1] = RADIO_ID[TEXT_idx++] ^ 0x4f;
						dstr.vpkt.vasd.text[2] = RADIO_ID[TEXT_idx++] ^ 0x93;
					} else if (TEXT_idx == 12) {
						dstr.vpkt.vasd.text[0] = RADIO_ID[TEXT_idx++] ^ 0x70;
						dstr.vpkt.vasd.text[1] = RADIO_ID[TEXT_idx++] ^ 0x4f;
						dstr.vpkt.vasd.text[2] = RADIO_ID[TEXT_idx++] ^ 0x93;
					} else if (TEXT_idx == 15) {
						dstr.vpkt.vasd.text[0] = 'C' ^ 0x70;
						dstr.vpkt.vasd.text[1] = RADIO_ID[TEXT_idx++] ^ 0x4f;
						dstr.vpkt.vasd.text[2] = RADIO_ID[TEXT_idx++] ^ 0x93;
					} else if (TEXT_idx == 17) {
						dstr.vpkt.vasd.text[0] = RADIO_ID[TEXT_idx++] ^ 0x70;
						dstr.vpkt.vasd.text[1] = RADIO_ID[TEXT_idx++] ^ 0x4f;
						dstr.vpkt.vasd.text[2] = RADIO_ID[TEXT_idx++] ^ 0x93;
					} else {
						dstr.vpkt.vasd.text[0] = 0x70;
						dstr.vpkt.vasd.text[1] = 0x4f;
						dstr.vpkt.vasd.text[2] = 0x93;
					}
				}
			}

			int sent = sendto(sockDst, dstr.pkt_id, rlen + 2,0, (struct sockaddr *)&toDst, sizeof(toDst));
			if (sent == 58)
				printf("Sent DSTR HDR ur=%.8s r1=%.8s r2=%.8s my=%.8s/%.4s\n",
				dstr.vpkt.hdr.ur, dstr.vpkt.hdr.r1, dstr.vpkt.hdr.r2, dstr.vpkt.hdr.my, dstr.vpkt.hdr.nm);
			else if (sent == 29)
				printf("Sent DSTR DATA streamid=%04X, ctrl=%02X\n", dstr.vpkt.streamid, dstr.vpkt.ctrl);
			else
				printf("ERROR: sendto returned %d!\n", sent);
		}
		usleep(delay);
	}
	dst_close();
	fclose(fp);
	return 0;
}
