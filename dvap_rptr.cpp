/*
 *   Copyright (C) 2010, 2011 by Scott Lawson KI4LKF
 *
 *   Copyright (C) 2015 by Thomas A. Early AC2IE
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

/***
   KI4LKF, AC2IE
***/

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <sys/file.h>
#include "versions.h"

#include <atomic>
#include <future>
#include <exception>
#include <string>
#include <libconfig.h++>
using namespace libconfig;

#include "DVAPDongle.h"

#define VERSION DVAP_VERSION
#define CALL_SIZE 8
#define RPTR_SIZE 8
#define IP_SIZE 15

// we need to be sure these structures don't have any dead space
#pragma pack(push, 1)
// for communicating with the g2 gateway
typedef struct pkt_tag {
	unsigned char pkt_id[4];
	unsigned char nothing1[2];
	unsigned char flag[2];
	unsigned char nothing2[2];
	union {
		struct {
			unsigned char mycall[8];
			unsigned char rpt[8];
		} spkt;
		struct {
			struct {
				unsigned char icm_id;
				unsigned char dst_rptr_id;
				unsigned char snd_rptr_id;
				unsigned char snd_term_id;
				uint16_t streamid;
				unsigned char ctrl;
			} myicm;
			union {
				struct {
					unsigned char flag[3];
					unsigned char rpt1[8];
					unsigned char rpt2[8];
					unsigned char urcall[8];
					unsigned char mycall[8];
					unsigned char sfx[4];
					unsigned char pfcs[2];
				} hdr;	// 41 byte header
				struct {
					unsigned char voice[9];
					unsigned char text[3];
				} vasd;	// 12 byte voice and slow data
			};
		} vpkt;
	};
} SPKT;
#pragma pack(pop)

typedef struct dvap_ack_arg_tag {
	char mycall[8];
	float ber;
} SDVAP_ACK_ARG;


/* Default configuration data */
static char RPTR[RPTR_SIZE + 1];
static char OWNER[RPTR_SIZE + 1];
static char RPTR_MOD;
static char RPTR_VIRTUAL_IP[IP_SIZE + 1];
static int RPTR_PORT;
static char G2_INTERNAL_IP[IP_SIZE + 1];
static int G2_PORT;
static char DVP_SERIAL[64]; /* APxxxxxx */
static u_int32_t DVP_FREQ; /* between 144000000 and 148000000 */
static int16_t DVP_PWR; /* between  -12 and 10 */
static char DVP_SQL; /* between  -128 and -45 */
static int16_t DVP_OFF; /* between -2000 and 2000 */
static int WAIT_FOR_PACKETS;   /* wait 25 ms in reading from local G2 */
static int REMOTE_TIMEOUT;  /* 1 second */
static int DELAY_BETWEEN;
static int DELAY_BEFORE;
static bool RPTR_ACK;
static char INVALID_YRCALL_KEY[CALL_SIZE + 1];
static int inactiveMax = 25;

/* helper data */
static unsigned char SND_TERM_ID;
static char RPTR_and_G[9];
static char RPTR_and_MOD[9];
static int insock = -1;
static struct sockaddr_in outaddr;
static int serfd = -1;
static bool busy20000 = false;
std::atomic<bool> keep_running(true);

static unsigned int space = 0;
static unsigned int aseed = 0;

/* helper routines */
void traceit(const char *fmt,...);
static int read_config(const char *cfgFile);
static void sig_catch(int signum);
static int open_sock();
static void readFrom20000();
static void calcPFCS(unsigned char *packet, unsigned char *pfcs);
static void ReadDVAPThread();
static void RptrAckThread(SDVAP_ACK_ARG *parg);

/*** BER stuff ***/
extern void dstar_dv_init();
extern int dstar_dv_decode(const unsigned char *d, int data[3]);

CDVAPDongle dongle;

static void calcPFCS(unsigned char *packet, unsigned char *pfcs)
{
	unsigned short crc_dstar_ffff = 0xffff;
	unsigned short tmp, short_c;
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

	for (int i = 0; i < 39 ; i++) {
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

static void sig_catch(int signum)
{
	if ((signum == SIGTERM) || (signum == SIGINT)  || (signum == SIGHUP))
		keep_running = false;
	exit(0);
}

/* log the event */
void traceit(const char *fmt,...)
{
	time_t ltime;
	struct tm mytm;
	const int TRACE_BFSZ = 256;
	char trace_buf[TRACE_BFSZ];

	time(&ltime);
	localtime_r(&ltime,&mytm);

	snprintf(trace_buf,TRACE_BFSZ - 1,"%02d/%02d/%02d %02d:%02d:%02d:",
	         mytm.tm_mon+1,mytm.tm_mday,mytm.tm_year % 100,
	         mytm.tm_hour,mytm.tm_min,mytm.tm_sec);

	va_list args;
	va_start(args,fmt);
	vsnprintf(trace_buf + strlen(trace_buf), TRACE_BFSZ - strlen(trace_buf) - 1, fmt, args);
	va_end(args);

	fprintf(stdout, "%s", trace_buf);
	return;
}

bool get_value(const Config &cfg, const char *path, int &value, int min, int max, int default_value)
{
	if (cfg.lookupValue(path, value)) {
		if (value < min || value > max)
			value = default_value;
	} else
		value = default_value;
	traceit("%s = [%d]\n", path, value);
	return true;
}

bool get_value(const Config &cfg, const char *path, double &value, double min, double max, double default_value)
{
	if (cfg.lookupValue(path, value)) {
		if (value < min || value > max)
			value = default_value;
	} else
		value = default_value;
	traceit("%s = [%lg]\n", path, value);
	return true;
}

bool get_value(const Config &cfg, const char *path, bool &value, bool default_value)
{
	if (! cfg.lookupValue(path, value))
		value = default_value;
	traceit("%s = [%s]\n", path, value ? "true" : "false");
	return true;
}

bool get_value(const Config &cfg, const char *path, std::string &value, int min, int max, const char *default_value)
{
	if (cfg.lookupValue(path, value)) {
		int l = value.length();
		if (l<min || l>max) {
			traceit("%s is invalid\n", path, value.c_str());
			return false;
		}
	} else
		value = default_value;
	traceit("%s = [%s]\n", path, value.c_str());
	return true;
}

/* process configuration file */
static int read_config(const char *cfgFile)
{
	int i;
	Config cfg;

	traceit("Reading file %s\n", cfgFile);
	// Read the file. If there is an error, report it and exit.
	try {
		cfg.readFile(cfgFile);
	}
	catch(const FileIOException &fioex) {
		traceit("Can't read %s\n", cfgFile);
		return 1;
	}
	catch(const ParseException &pex) {
		traceit("Parse error at %s:%d - %s\n", pex.getFile(), pex.getLine(), pex.getError());
		return 1;
	}

	std::string dvap_path, value;
	for (i=0; i<3; i++) {
		dvap_path = "module.";
		dvap_path += ('a' + i);
		if (cfg.lookupValue(dvap_path + ".type", value)) {
			if (0 == strcasecmp(value.c_str(), "dvap"))
				break;
		}
	}
	if (i >= 3) {
		traceit("dvap not defined in any module!\n");
		return 1;
	}
	RPTR_MOD = 'A' + i;

	if (cfg.lookupValue(std::string(dvap_path+".callsign").c_str(), value) || cfg.lookupValue("ircddb.login", value)) {
		int l = value.length();
		if (l<3 || l>CALL_SIZE-2) {
			traceit("Call '%s' is invalid length!\n", value.c_str());
			return 1;
		} else {
			for (i=0; i<l; i++) {
				if (islower(value[i]))
					value[i] = toupper(value[i]);
			}
			value.resize(CALL_SIZE, ' ');
		}
		strcpy(RPTR, value.c_str());
		traceit("%s.login = [%s]\n", dvap_path.c_str(), RPTR);
	} else {
		traceit("%s.login is not defined!\n", dvap_path.c_str());
		return 1;
	}
	
	if (cfg.lookupValue("ircddb.login", value)) {
		int l = value.length();
		if (l<3 || l>CALL_SIZE-2) {
			traceit("Call '%s' is invalid length!\n", value.c_str());
			return 1;
		} else {
			for (i=0; i<l; i++) {
				if (islower(value[i]))
					value[i] = toupper(value[i]);
			}
			value.resize(CALL_SIZE, ' ');
		}
		strcpy(OWNER, value.c_str());
		traceit("ircddb.login = [%s]\n", OWNER);
	} else {
		traceit("ircddb.login is not defined!\n");
		return 1;
	}

	if (get_value(cfg, std::string(dvap_path+".invalid_prefix").c_str(), value, 1, CALL_SIZE, "XXX")) {
		if (islower(value[i]))
			value[i] = toupper(value[i]);
		value.resize(CALL_SIZE, ' ');
		strcpy(INVALID_YRCALL_KEY, value.c_str());
	} else
		return 1;

	if (get_value(cfg, std::string(dvap_path+".internal_ip").c_str(), value, 7, IP_SIZE, "0.0.0.0"))
		strcpy(RPTR_VIRTUAL_IP, value.c_str());
	else
		return 1;

	i = 19998 + (RPTR_MOD - 'A');
	get_value(cfg, std::string(dvap_path+".port").c_str(), RPTR_PORT, 10000, 65535, i);

	if (get_value(cfg, "gateway.ip", value, 7, IP_SIZE, "127.0.0.1"))
		strcpy(G2_INTERNAL_IP, value.c_str());
	else {
		traceit("gateway.ip '%s' is invalid!\\n", value.c_str());
		return 1;
	}

	get_value(cfg, "gateway.internal.port", G2_PORT, 10000, 65535, 19000);

	if (get_value(cfg, std::string(dvap_path+".serial_number").c_str(), value, 8, 10, "APXXXXXX"))
		strcpy(DVP_SERIAL, value.c_str());
	else {
		traceit("%s.serial_number '%s' is invalid!\n", dvap_path.c_str(), value.c_str());
		return 1;
	}

	double f;
	get_value(cfg, std::string(dvap_path+".frequency").c_str(), f, 100.0, 1400.0, 145.5);
	DVP_FREQ = (u_int32_t)(1.0e6*f);

	get_value(cfg, std::string(dvap_path+".power").c_str(), i, -12, 10, 10);
	DVP_PWR = (int16_t)i;

	get_value(cfg, std::string(dvap_path+".squelch").c_str(), i, -128, -45, -100);
	DVP_SQL = (char)i;

	get_value(cfg, std::string(dvap_path+".offset").c_str(), i, -2000, 2000, 0.0);
	DVP_OFF = (int16_t)i;

	get_value(cfg, std::string(dvap_path+".packet_wait").c_str(), WAIT_FOR_PACKETS, 6, 100, 25);

	get_value(cfg, "timing.timeout.remote_g2", REMOTE_TIMEOUT, 1, 10, 2);

	get_value(cfg, "timing.play.delay", DELAY_BETWEEN, 9, 25, 19);

	get_value(cfg, "timing.play.wait", DELAY_BEFORE, 1, 10, 2);

	get_value(cfg, std::string(dvap_path+".acknowledge").c_str(), RPTR_ACK, false);

	inactiveMax = (REMOTE_TIMEOUT * 1000) / WAIT_FOR_PACKETS;
	traceit("Max loops = %d\n", inactiveMax);

	/* convert to Microseconds */
	WAIT_FOR_PACKETS *= 1000;

	return 0;
}

static int open_sock()
{
	struct  sockaddr_in inaddr;

	insock = socket(PF_INET, SOCK_DGRAM, 0);
	if (insock == -1) {
		traceit("Failed to create insock, error=%d, message=%s\n",errno,strerror(errno));
		return -1;
	}

	memset(&inaddr, 0, sizeof(inaddr));
	inaddr.sin_family = AF_INET;
	inaddr.sin_port = htons(RPTR_PORT);
	inaddr.sin_addr.s_addr = inet_addr(RPTR_VIRTUAL_IP);
	int rc = bind(insock, (struct sockaddr *)&inaddr, sizeof(inaddr));
	if (rc == -1) {
		traceit("Failed to bind server socket, error=%d, message=%s\n", errno,strerror(errno));
		close(insock);
		insock = -1;
		return -1;
	}
	fcntl(insock, F_SETFL, O_NONBLOCK);

	memset(&outaddr, 0, sizeof(outaddr));
	outaddr.sin_family = AF_INET;
	outaddr.sin_port = htons(G2_PORT);
	outaddr.sin_addr.s_addr = inet_addr(G2_INTERNAL_IP);

	return 0;
}

static void readFrom20000()
{
	struct  sockaddr_in from;
	socklen_t fromlen;
	int len;
	fd_set  readfd;
	struct  timeval tv;
	int inactive = 0;
	short seq_no = 0;
	uint16_t streamid;
	unsigned char sync_codes[3] = {0x55, 0x2d, 0x16};
	SPKT net_buf;
	unsigned short stream_id_to_dvap = 0;
	unsigned char frame_pos_to_dvap = 0;
	unsigned char seq_to_dvap = 0;
	unsigned char silence[12] = { 0x4e,0x8d,0x32,0x88,0x26,0x1a,0x3f,0x61,0xe8,0x70,0x4f,0x93 };

	bool written_to_q = false;
	unsigned char ctrl_in = 0x80;

	while (keep_running) {
		written_to_q = false;

		tv.tv_sec = 0;
		tv.tv_usec = WAIT_FOR_PACKETS;
		fromlen = sizeof(struct sockaddr);
		FD_ZERO (&readfd);
		FD_SET (insock, &readfd);
		select(insock + 1, &readfd, NULL, NULL, &tv);

		if (FD_ISSET(insock, &readfd)) {
			len = recvfrom(insock, (char *)&net_buf, 58, 0, (struct sockaddr *)&from, &fromlen);
			if (len == 58) {
				if (busy20000) {
					FD_CLR (insock, &readfd);
					continue;
				}

				/* check the module and gateway */
				if (net_buf.vpkt.hdr.rpt1[7] != RPTR_MOD) {
					FD_CLR(insock, &readfd);
					break;
				}
				memcpy(net_buf.vpkt.hdr.rpt2, OWNER, 7);
				net_buf.vpkt.hdr.rpt2[7] = 'G';

				if (memcmp(RPTR, OWNER, RPTR_SIZE) != 0) {
					// restriction mode
					memcpy(net_buf.vpkt.hdr.rpt2, RPTR, 7);
					memcpy(net_buf.vpkt.hdr.rpt1, RPTR, 7);

					if (memcmp(net_buf.vpkt.hdr.mycall, OWNER, 7) == 0) {
						/* this is an ACK back */
						memcpy(net_buf.vpkt.hdr.mycall, RPTR, 7);
					}
				}

				if ((net_buf.vpkt.hdr.flag[0] != 0x00) &&
				        (net_buf.vpkt.hdr.flag[0] != 0x01) &&
				        (net_buf.vpkt.hdr.flag[0] != 0x08) &&
				        (net_buf.vpkt.hdr.flag[0] != 0x20) &&
				        (net_buf.vpkt.hdr.flag[0] != 0x28) &&
				        (net_buf.vpkt.hdr.flag[0] != 0x40)) {
					FD_CLR(insock, &readfd);
					break;
				}

				if ((memcmp(net_buf.pkt_id, "DSTR", 4) != 0) ||
				        (net_buf.flag[0] != 0x73) ||
				        (net_buf.flag[1] != 0x12) ||
				        (net_buf.vpkt.myicm.icm_id != 0x20)) { /* voice type */
					FD_CLR(insock, &readfd);
					break;
				}

				busy20000 = true;

				ctrl_in = 0x80;
				written_to_q = true;

				traceit("Start G2: streamid=%04x, flags=%02x:%02x:%02x, my=%.8s, sfx=%.4s, ur=%.8s, rpt1=%.8s, rpt2=%.8s\n",
				        net_buf.vpkt.myicm.streamid,
				        net_buf.vpkt.hdr.flag[0], net_buf.vpkt.hdr.flag[1], net_buf.vpkt.hdr.flag[2],
				        net_buf.vpkt.hdr.mycall, net_buf.vpkt.hdr.sfx, net_buf.vpkt.hdr.urcall,
				        net_buf.vpkt.hdr.rpt1, net_buf.vpkt.hdr.rpt2);

				/* save the streamid that is winning */
				streamid = net_buf.vpkt.myicm.streamid;

				if (net_buf.vpkt.hdr.flag[0] != 0x01) {

					if (net_buf.vpkt.hdr.flag[0] == 0x00)
						net_buf.vpkt.hdr.flag[0] = 0x40;
					else if (net_buf.vpkt.hdr.flag[0] == 0x08)
						net_buf.vpkt.hdr.flag[0] = 0x48;
					else if (net_buf.vpkt.hdr.flag[0] == 0x20)
						net_buf.vpkt.hdr.flag[0] = 0x60;
					else if (net_buf.vpkt.hdr.flag[0] == 0x28)
						net_buf.vpkt.hdr.flag[0] = 0x68;
					else
						net_buf.vpkt.hdr.flag[0] = 0x40;
				}
				net_buf.vpkt.hdr.flag[1] = net_buf.vpkt.hdr.flag[2] = 0x00;

				// write the header packet to the dvap here
				while ((space < 1) && keep_running)
					usleep(5);
				SDVAP_REGISTER dr;
				stream_id_to_dvap = (rand_r(&aseed) % 65535U) + 1U;
				dr.header = 0xa02f;
				dr.frame.streamid = stream_id_to_dvap;
				dr.frame.framepos = 0x80;
				dr.frame.seq = 0;
				//memset(dvp_buf + 6, ' ', 41);
				for (int f=0; f<3; f++)
					dr.frame.hdr.flag[f] = net_buf.vpkt.hdr.flag[0];
				memcpy(dr.frame.hdr.rpt1, net_buf.vpkt.hdr.rpt2, 8);
				memcpy(dr.frame.hdr.rpt2, net_buf.vpkt.hdr.rpt1, 8);
				memcpy(dr.frame.hdr.urcall, net_buf.vpkt.hdr.urcall, 8);
				memcpy(dr.frame.hdr.mycall, net_buf.vpkt.hdr.mycall, 8);
				memcpy(dr.frame.hdr.sfx, net_buf.vpkt.hdr.sfx, 4);
				calcPFCS(dr.frame.hdr.flag, dr.frame.hdr.pfcs);
				frame_pos_to_dvap = 0;
				seq_to_dvap = 0;
				dongle.SendRegister(dr);

				inactive = 0;
				seq_no = 0;
			} else if (len == 29) {
				if (busy20000) {
					if (net_buf.vpkt.myicm.streamid == streamid) {
						if (net_buf.vpkt.myicm.ctrl == ctrl_in) {
							/* do not update written_to_q, ctrl_in */
							; // traceit("dup\n");
						} else {
							ctrl_in = net_buf.vpkt.myicm.ctrl;
							written_to_q = true;

							if (seq_no == 0) {
								net_buf.vpkt.vasd.text[0] = 0x55;
								net_buf.vpkt.vasd.text[1] = 0x2d;
								net_buf.vpkt.vasd.text[2] = 0x16;
							} else {
								if ((net_buf.vpkt.vasd.text[0] == 0x55) &&
									(net_buf.vpkt.vasd.text[1] == 0x2d) &&
									(net_buf.vpkt.vasd.text[2] == 0x16)) {
									net_buf.vpkt.vasd.text[0] = 0x70;
									net_buf.vpkt.vasd.text[1] = 0x4f;
									net_buf.vpkt.vasd.text[2] = 0x93;
								}
							}

							// write the audio packet to the dvap here
							while ((space < 1) && keep_running)
								usleep(5);
							SDVAP_REGISTER dr;
							dr.header = 0xc012u;
							if (memcmp(net_buf.vpkt.vasd.text, sync_codes, 3) == 0)
								frame_pos_to_dvap = 0;
							dr.frame.streamid = stream_id_to_dvap;
							dr.frame.framepos = frame_pos_to_dvap;
							if ((net_buf.vpkt.myicm.ctrl & 0x40) != 0)
								dr.frame.framepos |= 0x40U;
							dr.frame.seq = seq_to_dvap;
							memcpy(&dr.frame.vad.voice, net_buf.vpkt.vasd.voice, 12);
							dongle.SendRegister(dr);
							frame_pos_to_dvap ++;
							seq_to_dvap ++;

							inactive = 0;

							seq_no ++;
							if (seq_no == 21)
								seq_no = 0;

							if ((net_buf.vpkt.myicm.ctrl & 0x40) != 0) {
								traceit("End G2: streamid=%04x\n", net_buf.vpkt.myicm.streamid);

								streamid = 0;

								inactive = 0;
								FD_CLR (insock, &readfd);
								// maybe put a sleep here to prevent fast voice-overs

								busy20000 = false;
								break;
							}
						}
					}
				} else {
					FD_CLR (insock, &readfd);
					break;
				}
			} else {
				if (!busy20000) {
					FD_CLR (insock, &readfd);
					break;
				}
			}
			FD_CLR (insock, &readfd);
		}

		// If we received a dup or select() timed out or streamids dont match,
		// then written_to_q is false
		if (!written_to_q) {
			if (busy20000) {
				if (++inactive == inactiveMax) {
					traceit("G2 Timeout...\n");

					streamid = 0;

					inactive = 0;
					// maybe put a sleep here to prevent fast voice-overs

					busy20000 = false;
					break;
				} else {
					if (space == 127) {
						if (seq_no == 0) {
							silence[9]  = 0x55;
							silence[10] = 0x2d;
							silence[11] = 0x16;
						} else {
							silence[9]  = 0x70;
							silence[10] = 0x4f;
							silence[11] = 0x93;
						}

						SDVAP_REGISTER dr;
						dr.header = 0xc012u;
						if (memcmp(silence + 9, sync_codes, 3) == 0)
							frame_pos_to_dvap = 0;
						dr.frame.streamid = stream_id_to_dvap;
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
			} else
				break;
		}
	}
	return;
}

int main(int argc, const char **argv)
{
	struct sigaction act;
	int rc = -1;
	time_t tnow = 0;
	time_t ackpoint = 0;
	short cnt = 0;

	setvbuf(stdout, NULL, _IOLBF, 0);
	traceit("dvap_rptr VERSION %s\n", VERSION);

	if (argc != 2) {
		traceit("Usage:  dvap_rptr dvap_rptr.cfg\n");
		return 1;
	}

	rc = read_config(argv[1]);
	if (rc != 0) {
		traceit("Failed to process config file %s\n", argv[1]);
		return 1;
	}

	if (strlen(RPTR) != 8) {
		traceit("Bad RPTR value, length must be exactly 8 bytes\n");
		return 1;
	}
	if ((RPTR_MOD != 'A') && (RPTR_MOD != 'B') && (RPTR_MOD != 'C')) {
		traceit("Bad RPTR_MOD value, must be one of A or B or C\n");
		return 1;
	}

	if (RPTR_MOD == 'A')
		SND_TERM_ID = 0x03;
	else if (RPTR_MOD == 'B')
		SND_TERM_ID = 0x01;
	else if (RPTR_MOD == 'C')
		SND_TERM_ID = 0x02;

	strcpy(RPTR_and_G, RPTR);
	RPTR_and_G[7] = 'G';

	strcpy(RPTR_and_MOD, RPTR);
	RPTR_and_MOD[7] = RPTR_MOD;

	time(&tnow);
	aseed = tnow + getpid();

	act.sa_handler = sig_catch;
	sigemptyset(&act.sa_mask);
	if (sigaction(SIGTERM, &act, 0) != 0) {
		traceit("sigaction-TERM failed, error=%d\n", errno);
		return 1;
	}
	if (sigaction(SIGHUP, &act, 0) != 0) {
		traceit("sigaction-HUP failed, error=%d\n", errno);
		return 1;
	}
	if (sigaction(SIGINT, &act, 0) != 0) {
		traceit("sigaction-INT failed, error=%d\n", errno);
		return 1;
	}

	/* open dvp */
	if (!dongle.Initialize(DVP_SERIAL, DVP_FREQ, DVP_OFF, DVP_PWR, DVP_SQL))
		return 1;

	rc = open_sock();
	if (rc != 0) {
		dongle.Stop();
		close(serfd);
		return 1;
	}
	traceit("DVAP opened and initialized!\n");
	dstar_dv_init();

	std::future<void> readthread;
	try {
		readthread = std::async(std::launch::async, ReadDVAPThread);
	} catch (const std::exception &e) {
		traceit("Unable to start ReadDVAPThread(). Exception: %s\n", e.what());
		keep_running = false;
	}
	traceit("Started ReadDVAPThread()\n");
	
	while (keep_running) {
		time(&tnow);
		if ((tnow - ackpoint) > 2) {
			rc = dongle.KeepAlive();
			if (rc < 0) {
				cnt ++;
				if (cnt > 5) {
					traceit("Could not send KEEPALIVE signal to dvap 5 times...exiting\n");
					keep_running = false;
				}
			} else
				cnt = 0;
			ackpoint = tnow;
		}
		readFrom20000();
	}

	readthread.get();
	close(insock);
	traceit("dvap_rptr exiting\n");
	return 0;
}

static void RptrAckThread(SDVAP_ACK_ARG *parg)
{
	char mycall[8];
	memcpy(mycall, parg->mycall, 8);
	float ber = parg->ber;

	char RADIO_ID[21];

	sprintf(RADIO_ID, "%20.2f", ber);
	memcpy(RADIO_ID, "BER%", 4);

	struct sigaction act;
	time_t tnow = 0;
	unsigned char silence[12] = { 0x4e,0x8d,0x32,0x88,0x26,0x1a,0x3f,0x61,0xe8,0x70,0x4f,0x93 };
	unsigned int aseed_ack = 0;
	struct timespec nanos;

	act.sa_handler = sig_catch;
	sigemptyset(&act.sa_mask);
	if (sigaction(SIGTERM, &act, 0) != 0) {
		traceit("sigaction-TERM failed, error=%d\n", errno);
		return;
	}
	if (sigaction(SIGHUP, &act, 0) != 0) {
		traceit("sigaction-HUP failed, error=%d\n", errno);
		return;
	}
	if (sigaction(SIGINT, &act, 0) != 0) {
		traceit("sigaction-INT failed, error=%d\n", errno);
		return;
	}

	sleep(DELAY_BEFORE);

	time(&tnow);
	aseed_ack = tnow + getpid();

	uint16_t stream_id_to_dvap = (rand_r(&aseed_ack) % 65535U) + 1U;

	// HEADER
	while ((space < 1) && keep_running)
		usleep(5);
	SDVAP_REGISTER dr;
	dr.header = 0xa02fu;
	dr.frame.streamid = stream_id_to_dvap;
	dr.frame.framepos = 0x80;
	dr.frame.seq = 0;
	dr.frame.hdr.flag[0] = 0x01;
	dr.frame.hdr.flag[1] = dr.frame.hdr.flag[2] = 0x00;
	memcpy(dr.frame.hdr.rpt1, RPTR_and_MOD, 8);
	memcpy(dr.frame.hdr.rpt2, RPTR_and_G, 8);
	memcpy(dr.frame.hdr.urcall, mycall, 8);
	memcpy(dr.frame.hdr.mycall, RPTR_and_MOD, 8);
	memcpy(dr.frame.hdr.sfx, (unsigned char *)"    ", 4);
	calcPFCS(dr.frame.hdr.flag, dr.frame.hdr.pfcs);
	dongle.SendRegister(dr);
	nanos.tv_sec = 0;
	nanos.tv_nsec = DELAY_BETWEEN * 1000000;
	nanosleep(&nanos,0);

	// SYNC
	dr.header = 0xc012u;
	dr.frame.streamid = stream_id_to_dvap;
	for (int i=0; i<10; i++) {
		while ((space < 1) && keep_running)
			usleep(5);
		dr.frame.framepos = dr.frame.seq = i;
		switch (i) {
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
		if (i < 9) {
			nanos.tv_sec = 0;
			nanos.tv_nsec = DELAY_BETWEEN * 1000000;
			nanosleep(&nanos,0);
		}
	}
	return;
}

static void ReadDVAPThread()
{
	REPLY_TYPE reply;
	SPKT net_buf;
	SPKT spack;
	SDVAP_REGISTER dr;
	time_t tnow = 0;
	time_t S_ctrl_msg_time = 0;
	unsigned short C_COUNTER = 0;
	time_t last_RF_time = 0;
	struct sigaction act;
	bool dvap_busy = false;
	// bool ptt = false;
	bool the_end = true;
	bool ok = true;
	int i = 0;
	u_int16_t streamid_raw = 0;
	short int sequence = 0;
	char mycall[8];
	short int status_cntr = 3000;
	char temp_yrcall[CALL_SIZE + 1];
	char *temp_ptr = NULL;

	int num_dv_frames = 0;
	int num_bit_errors = 0;

	act.sa_handler = sig_catch;
	sigemptyset(&act.sa_mask);
	if (sigaction(SIGTERM, &act, 0) != 0) {
		traceit("sigaction-TERM failed, error=%d\n", errno);
		keep_running = false;
		return;
	}
	if (sigaction(SIGHUP, &act, 0) != 0) {
		traceit("sigaction-HUP failed, error=%d\n", errno);
		keep_running = false;
		return;
	}
	if (sigaction(SIGINT, &act, 0) != 0) {
		traceit("sigaction-INT failed, error=%d\n", errno);
		keep_running = false;
		return;
	}

	/* prepare the S server status packet */
	memcpy(spack.pkt_id, "DSTR", 4);
	spack.nothing1[0] = 0x00;
	spack.nothing1[1] = 0x00;
	spack.flag[0] = 0x73;
	spack.flag[1] = 0x21;
	spack.nothing2[0] = 0x00;
	spack.nothing2[1] = 0x10;

	while (keep_running) {
		time(&tnow);

		/* send the S packet if needed */
		if ((tnow - S_ctrl_msg_time) > 60) {
			spack.nothing1[1] = (unsigned char)(C_COUNTER & 0xff);
			spack.nothing1[0] = ((C_COUNTER >> 8) & 0xff);
			memcpy(spack.spkt.mycall, OWNER, 7);
			spack.spkt.mycall[7] = 'S';
			memcpy(spack.spkt.rpt, OWNER, 7);
			spack.spkt.rpt[7] = 'S';
			sendto(insock, spack.pkt_id, 26, 0, (struct sockaddr *)&outaddr, sizeof(outaddr));
			C_COUNTER++;
			S_ctrl_msg_time = tnow;
		}

		// local RF user went away ?
		if (dvap_busy) {
			time(&tnow);
			if ((tnow - last_RF_time) > 1)
				dvap_busy = false;
		}

		// read from the dvap and process
		reply = dongle.GetReply(dr);
		if (reply == RT_ERR) {
			traceit("Detected ERROR event from DVAP dongle, stopping...n");
			break;
		} else if (reply == RT_STOP) {
			traceit("Detected STOP event from DVAP dongle, stopping...\n");
			break;
		} else if (reply == RT_START) {
			traceit("Detected START event from DVAP dongle\n");
		// else if (reply == RT_PTT) {
		// 	ptt = (dvp_buf[4] == 0x01);
		// 	traceit("Detected PTT=%s\n", ptt?"on":"off");
		} else if (reply == RT_STS) {
			space = (unsigned int)dr.param.sstr[2];
			if (status_cntr < 3000)
				status_cntr += 20;
		} else if (reply == RT_HDR) {
			num_dv_frames = 0;
			num_bit_errors = 0;

			traceit("From DVAP: flags=%02x:%02x:%02x, my=%.8s, sfx=%.4s, ur=%.8s, rpt1=%.8s, rpt2=%.8s\n",
			        dr.frame.hdr.flag[0], dr.frame.hdr.flag[1], dr.frame.hdr.flag[2],
			        dr.frame.hdr.mycall, dr.frame.hdr.sfx, dr.frame.hdr.urcall,
			        dr.frame.hdr.rpt2, dr.frame.hdr.rpt1);

			ok = true;

			/* Accept valid flags only */
			if (ok) {
				if ((dr.frame.hdr.flag[0] != 0x00) && (dr.frame.hdr.flag[0] != 0x08) &&	// net
					(dr.frame.hdr.flag[0] != 0x20) && (dr.frame.hdr.flag[0] != 0x28) &&	// flags
					
					(dr.frame.hdr.flag[0] != 0x40) && (dr.frame.hdr.flag[0] != 0x48) &&	// rptr
					(dr.frame.hdr.flag[0] != 0x60) && (dr.frame.hdr.flag[0] != 0x68))	// flags
					ok = false;
			}

			/* Reject those stupid STN stations */
			if (ok) {
				memcpy(temp_yrcall, dr.frame.hdr.urcall, CALL_SIZE);
				temp_yrcall[CALL_SIZE] = '\0';
				temp_ptr = strstr(temp_yrcall, INVALID_YRCALL_KEY);
				if (temp_ptr == temp_yrcall) { // found it at first position
					traceit("YRCALL value [%s] starts with the INVALID_YRCALL_KEY [%s], resetting to CQCQCQ\n",
					        temp_yrcall, INVALID_YRCALL_KEY);
					memcpy(dr.frame.hdr.urcall, "CQCQCQ  ", 8);
				}
			}

			memcpy(&net_buf.vpkt.hdr, dr.frame.hdr.flag, 41);	// copy the header

			/* RPT1 must always be the repeater + module */
			memcpy(net_buf.vpkt.hdr.rpt2, RPTR_and_MOD, 8);
			/* copy RPT2 */
			memcpy(net_buf.vpkt.hdr.rpt1, dr.frame.hdr.rpt1, 8);

			/* RPT2 must also be valid */
			if ((net_buf.vpkt.hdr.rpt1[7] == 'A') ||
				(net_buf.vpkt.hdr.rpt1[7] == 'B') ||
				(net_buf.vpkt.hdr.rpt1[7] == 'C') ||
				(net_buf.vpkt.hdr.rpt1[7] == 'G'))
				memcpy(net_buf.vpkt.hdr.rpt1, RPTR, 7);
			else
				memset(net_buf.vpkt.hdr.rpt1, ' ', 8);

			if ((memcmp(net_buf.vpkt.hdr.urcall, "CQCQCQ", 6) != 0) && (net_buf.vpkt.hdr.rpt1[0] != ' '))
				memcpy(net_buf.vpkt.hdr.rpt1,  RPTR_and_G, 8);

			/* 8th in rpt1, rpt2 must be diff */
			if (net_buf.vpkt.hdr.rpt1[7] == net_buf.vpkt.hdr.rpt2[7])
				memset(net_buf.vpkt.hdr.rpt1, ' ', 8);

			/*
			   Are we restricting the RF user ?
			   If RPTR is OWNER, then any RF user can talk.
			   If RPTR is not OWNER,
			   that means that mycall, rpt1, rpt2 must be equal to RPTR
			     otherwise we drop the rf data
			*/
			if (memcmp(RPTR, OWNER, RPTR_SIZE) != 0) {
				if (memcmp(net_buf.vpkt.hdr.mycall, RPTR, RPTR_SIZE) != 0) {
					traceit("mycall=[%.8s], not equal to %s\n", net_buf.vpkt.hdr.mycall, RPTR);
					ok = false;
				}
			} else if (memcmp(net_buf.vpkt.hdr.mycall, "        ", 8) == 0) {
				traceit("Invalid value for mycall=[%.8s]\n", net_buf.vpkt.hdr.mycall);
				ok = false;
			}

			if (ok) {
				for (i = 0; i < 8; i++) {
					if (!isupper(net_buf.vpkt.hdr.mycall[i]) &&
					        !isdigit(net_buf.vpkt.hdr.mycall[i]) &&
					        (net_buf.vpkt.hdr.mycall[i] != ' ')) {
						memset(net_buf.vpkt.hdr.mycall, ' ', 8);
						ok = false;
						traceit("Invalid value for MYCALL\n");
						break;
					}
				}

				for (i = 0; i < 4; i++) {
					if (!isupper(net_buf.vpkt.hdr.sfx[i]) &&
					        !isdigit(net_buf.vpkt.hdr.sfx[i]) &&
					        (net_buf.vpkt.hdr.sfx[i] != ' ')) {
						memset(net_buf.vpkt.hdr.sfx, ' ', 4);
						break;
					}
				}

				for (i = 0; i < 8; i++) {
					if (!isupper(net_buf.vpkt.hdr.urcall[i]) &&
					        !isdigit(net_buf.vpkt.hdr.urcall[i]) &&
					        (net_buf.vpkt.hdr.urcall[i] != ' ') &&
					        (net_buf.vpkt.hdr.urcall[i] != '/')) {
						memcpy(net_buf.vpkt.hdr.urcall, "CQCQCQ  ", 8);
						break;
					}
				}

				/*** what if YRCALL is all spaces, we can NOT allow that ***/
				if (memcmp(net_buf.vpkt.hdr.urcall, "        ", 8) == 0)
					memcpy(net_buf.vpkt.hdr.urcall, "CQCQCQ  ", 8);

				/* change the rptr flags to net flags */
				if (dr.frame.hdr.flag[0] == 0x40)
					net_buf.vpkt.hdr.flag[0] = 0x00;
				else if (dr.frame.hdr.flag[0] == 0x48)
					net_buf.vpkt.hdr.flag[0] = 0x08;
				else if (dr.frame.hdr.flag[0] == 0x60)
					net_buf.vpkt.hdr.flag[0] = 0x20;
				else if (dr.frame.hdr.flag[0] == 0x68)
					net_buf.vpkt.hdr.flag[0] = 0x28;
				else
					net_buf.vpkt.hdr.flag[0] = 0x00;
				net_buf.vpkt.hdr.flag[1] = net_buf.vpkt.hdr.flag[2] = 0x00;

				/* for icom g2 */
				spack.nothing1[1] = (unsigned char)(C_COUNTER & 0xff);
				spack.nothing1[0] = ((C_COUNTER >> 8) & 0xff);
				memcpy(spack.spkt.mycall, net_buf.vpkt.hdr.mycall, 8);
				memcpy(spack.spkt.rpt, OWNER, 7);
				spack.spkt.rpt[7] = RPTR_MOD;
				sendto(insock, spack.pkt_id, 26, 0, (struct sockaddr *)&outaddr, sizeof(outaddr));
				C_COUNTER++;

				// Before we send the data to the local gateway,
				// set RPT1, RPT2 to be the local gateway
				memcpy(net_buf.vpkt.hdr.rpt2, OWNER, 7);
				if (net_buf.vpkt.hdr.rpt1[7] != ' ')
					memcpy(net_buf.vpkt.hdr.rpt1, OWNER, 7);

				memcpy(net_buf.pkt_id, "DSTR", 4);
				net_buf.nothing1[0] = ((C_COUNTER >> 8) & 0xff);
				net_buf.nothing1[1] = (unsigned char)(C_COUNTER & 0xff);
				net_buf.flag[0] = 0x73;
				net_buf.flag[1] = 0x12;
				net_buf.nothing2[0] = 0x00;
				net_buf.nothing2[1] = 0x30;
				net_buf.vpkt.myicm.icm_id = 0x20;
				net_buf.vpkt.myicm.dst_rptr_id = 0x00;
				net_buf.vpkt.myicm.snd_rptr_id = 0x01;
				net_buf.vpkt.myicm.snd_term_id = SND_TERM_ID;
				streamid_raw = (rand_r(&aseed) % 65535U) + 1U;
				net_buf.vpkt.myicm.streamid = streamid_raw;
				net_buf.vpkt.myicm.ctrl = 0x80;
				sequence = 0;
				calcPFCS((unsigned char *)&(net_buf.vpkt.hdr), net_buf.vpkt.hdr.pfcs);
				sendto(insock, &net_buf, 58, 0, (struct sockaddr *)&outaddr, sizeof(outaddr));
				C_COUNTER ++;

				// local RF user keying up, start timer
				dvap_busy = true;
				time(&last_RF_time);

				// save mycall for the ack later
				memcpy(mycall, dr.frame.hdr.mycall, 8);

			}
		} else if (reply == RT_DAT) {
			/* have we already received a header ? */
			if (dvap_busy) {
				the_end = ((dr.frame.framepos & 0x40) == 0x40);

				net_buf.nothing1[0] = ((C_COUNTER >> 8) & 0xff);
				net_buf.nothing1[1] = (unsigned char)(C_COUNTER & 0xff);
				net_buf.nothing2[1] = 0x13;
				net_buf.vpkt.myicm.ctrl = sequence++;
				if (the_end)
					net_buf.vpkt.myicm.ctrl = sequence | 0x40;
				memcpy(&net_buf.vpkt.vasd, &dr.frame.vad.voice, 12);
				sendto(insock, &net_buf, 29, 0, (struct sockaddr *)&outaddr, sizeof(outaddr));

				int ber_data[3];
				int ber_errs = dstar_dv_decode(net_buf.vpkt.vasd.voice, ber_data);
				if (ber_data[0] != 0xf85) {
					num_bit_errors += ber_errs;
					num_dv_frames++;
				}

				C_COUNTER++;
				if (sequence > 0x14)
					sequence = 0;

				// local RF user still talking, update timer
				time(&last_RF_time);
				if (the_end) {
					// local RF user stopped talking
					dvap_busy = false;
					static SDVAP_ACK_ARG dvap_ack_arg;
					dvap_ack_arg.ber = (num_dv_frames==0) ? 0.f : 100.f * (float)num_bit_errors / (float)(num_dv_frames * 24);
					traceit("End of dvap audio,  ber=%.02f\n", dvap_ack_arg.ber);

					if (RPTR_ACK && !busy20000) {
						memcpy(dvap_ack_arg.mycall, mycall, 8);
						try {
							std::async(std::launch::async, RptrAckThread, &dvap_ack_arg);
						} catch (const std::exception &e) {
							traceit("Failed to start RptrAckThread(). Exception: %s\n", e.what());
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

	traceit("ReadDVAPThread exiting\n");

	keep_running = false;
	return;
}
