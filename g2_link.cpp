
/*
 *   Copyright (C) 2010 by Scott Lawson KI4LKF
 *   Additional:
 *   Copyright (C) 2015 by Thomas A. Early N7TAE
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
#include <time.h>

#include <regex.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <future>
#include <exception>
#include <atomic>
/* Required for Binary search trees using C++ STL */
#include <string>
#include <set>
#include <map>
#include <utility>
#include <libconfig.h++>
#include "versions.h"
using namespace libconfig;

/*** version number must be x.xx ***/
#define VERSION LINK_VERSION
#define CALL_SIZE 8
#define IP_SIZE 15
#define QUERY_SIZE 56
#define MAXHOSTNAMELEN 64
#define TIMEOUT 50
#define LINK_CODE 'L'
#define UNLINK_CODE 'U'
#define INFO_CODE 'I'
#define EXEC_CODE 'X'
#define DONGLE_CODE 'D'
#define FILE_REFRESH_GWYS_CODE 'F'

/* configuration data */
static std::string login_call;
static std::string owner;
static std::string to_g2_external_ip;
static std::string my_g2_link_ip;
static std::string gwys;
static std::string status_file;
static std::string announce_dir;
static bool only_admin_login;
static bool only_link_unlink;
static bool qso_details;
static bool bool_rptr_ack;
static bool announce;
static int rmt_xrf_port;
static int rmt_ref_port;
static int rmt_dcs_port;
static int my_g2_link_port;
static int to_g2_external_port;
static int delay_between;
static int delay_before;
static char link_at_startup[CALL_SIZE+1];
static unsigned int max_dongles;
static unsigned int saved_max_dongles;
static long rf_inactivity_timer[3];

static unsigned char REF_ACK[3] = { 3, 96, 0 };

// This is the data payload in the map: inbound_list
// This is for inbound dongles

struct inbound {
	char call[CALL_SIZE + 1];	// the callsign of the remote
	struct sockaddr_in sin;		// IP and port of remote
	short countdown;			// if countdown expires, the connection is terminated
	char mod;					// A B C This user talked on this module
	char client;				// dvap, dvdongle
};

// the Key in this inbound_list map is the unique IP address of the remote
typedef std::map<std::string, inbound *> inbound_type;
static inbound_type inbound_list;

typedef std::set<std::string> admin_type;
static admin_type admin;

typedef std::set<std::string> link_unlink_user_type;
static link_unlink_user_type link_unlink_user;

#define LH_MAX_SIZE 39
typedef std::map<std::string, std::string> dt_lh_type;
static dt_lh_type dt_lh_list;

static struct {
	char to_call[CALL_SIZE + 1];
	struct sockaddr_in toDst4;
	char from_mod;
	char to_mod;
	short countdown;
	bool is_connected;
	unsigned char in_streamid[2];  // incoming from remote systems
	unsigned char out_streamid[2]; // outgoing to remote systems
} to_remote_g2[3];

// broadcast for data arriving from xrf to local rptr
static struct {
	unsigned char xrf_streamid[2];		// streamid from xrf
	unsigned char rptr_streamid[2][2];	// generated streamid to rptr(s)
} brd_from_xrf;
static unsigned char from_xrf_torptr_brd[56];
static short brd_from_xrf_idx = 0;

// broadcast for data arriving from local rptr to xrf
static struct {
	unsigned char from_rptr_streamid[2];
	unsigned char to_rptr_streamid[2][2];
} brd_from_rptr;
static unsigned char fromrptr_torptr_brd[56];
static short brd_from_rptr_idx = 0;

static struct {
	unsigned char streamid[2];
	time_t last_time;	// last time RF user talked
} tracing[3] = {
	{ {0,0}, 0 },
	{ {0,0}, 0 },
	{ {0,0}, 0 }
};

// input from remote
static int xrf_g2_sock = -1;
static int ref_g2_sock = -1;
static int dcs_g2_sock = -1;
static struct sockaddr_in fromDst4;

// After we receive it from remote g2,
// we must feed it to our local repeater.
static struct sockaddr_in toLocalg2;

// input from our own local repeater
static int rptr_sock = -1;
static struct sockaddr_in fromRptr;

static fd_set fdset;
static struct timeval tv;

static std::atomic<bool> keep_running(true);

// Used to validate incoming donglers
static regex_t preg;

const char* G2_html = "<table border=\"0\" width=\"95%\"><tr>"
                      "<td width=\"4%\"><img border=\"0\" src=g2ircddb.jpg></td>"
                      "<td width=\"96%\"><font size=\"2\">"
                      "<b>REPEATER</b> G2_IRCDDB Gateway v3.09+"
                      "</font></td>"
                      "</tr></table>";

// the map of remotes
// key is the callsign, data is the host
typedef std::map<std::string, std::string> gwy_list_type;
static gwy_list_type gwy_list;

static unsigned char queryCommand[QUERY_SIZE];

// START:  TEXT crap
static char dtmf_mycall[3][CALL_SIZE + 1] = { {""}, {""}, {""} };
static bool new_group[3] = { true, true, true };
static int header_type = 0;
static bool GPS_seen[3] = { false, false, false };
unsigned char tmp_txt[3];
static char *p_tmp2 = NULL;
// END:  TEXT crap

// this is used for the "dashboard and qso_details" to avoid processing multiple headers
static struct {
	unsigned char sid[2];
} old_sid[3] = {
	{ {0x00, 0x00} },
	{ {0x00, 0x00} },
	{ {0x00, 0x00} }
};

static bool load_gwys(const std::string &filename);
static void calcPFCS(unsigned char *packet, int len);
static void traceit(const char *fmt,...);
static bool read_config(char *);
static bool srv_open();
static void srv_close();
static void sigCatch(int signum);
static void g2link(char from_mod, char *call, char to_mod);
static void runit();
static void print_status_file();
static void send_heartbeat();
static bool resolve_rmt(char *name, int type, struct sockaddr_in *addr);
static void audio_notify(char *notify_msg);
static void rptr_ack(short i);
static void AudioNotifyThread(char *arg);
static void RptrAckThread(char *arg);

static bool resolve_rmt(char *name, int type, struct sockaddr_in *addr)
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
		traceit("getaddrinfo return error code %d for [%s]\n", rc, name);
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
static void send_heartbeat()
{
	inbound_type::iterator pos;
	inbound *inbound_ptr;
	bool removed = false;

	for (pos = inbound_list.begin(); pos != inbound_list.end(); pos++) {
		inbound_ptr = (inbound *)pos->second;
		sendto(ref_g2_sock, REF_ACK, 3, 0, (struct sockaddr *)&(inbound_ptr->sin), sizeof(struct sockaddr_in));

		if (inbound_ptr->countdown >= 0)
			inbound_ptr->countdown --;

		if (inbound_ptr->countdown < 0) {
			removed = true;
			traceit("call=%s timeout, removing %s, users=%d\n",
			        inbound_ptr->call,
			        pos->first.c_str(),
			        inbound_list.size() - 1);

			free(pos->second);
			pos->second = NULL;
			inbound_list.erase(pos);
		}
	}
	if (removed)
		print_status_file();
}

static void rptr_ack(short i)
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
		std::async(std::launch::async, RptrAckThread, mod_and_RADIO_ID[i]);
	} catch (const std::exception &e) {
		traceit("Failed to start RptrAckThread(). Exception: %s\n", e.what());
	}
	return;
}

static void RptrAckThread(char *arg)
{
	char from_mod = arg[0];
	char RADIO_ID[21];
	memcpy(RADIO_ID, arg + 1, 21);
	unsigned char buf[56];
	struct timespec nanos;
	unsigned int aseed;
	time_t tnow = 0;
	unsigned char silence[12] = { 0x4e,0x8d,0x32,0x88,0x26,0x1a,0x3f,0x61,0xe8,0x70,0x4f,0x93 };
	struct sigaction act;

	act.sa_handler = sigCatch;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	if (sigaction(SIGTERM, &act, 0) != 0) {
		traceit("sigaction-TERM failed, error=%d\n", errno);
		return;
	}
	if (sigaction(SIGINT, &act, 0) != 0) {
		traceit("sigaction-INT failed, error=%d\n", errno);
		return;
	}

	time(&tnow);
	aseed = tnow + pthread_self();

	u_int16_t streamid_raw = (::rand_r(&aseed) % 65535U) + 1U;

	sleep(delay_before);

	traceit("sending ACK+text, mod:[%c], RADIO_ID=[%s]\n", from_mod, RADIO_ID);

	memcpy(buf,"DSVT", 4);
	buf[4]  = 0x10;
	buf[5]  = 0x00;
	buf[6]  = 0x00;
	buf[7]  = 0x00;

	buf[8]  = 0x20;
	buf[9]  = 0x00;
	buf[10] = 0x01;
	buf[11] = 0x00;

	buf[12] = streamid_raw / 256U;
	buf[13] = streamid_raw % 256U;
	buf[14] = 0x80;
	buf[15] = 0x01; /* we do not want to set this to 0x01 */
	buf[16] = 0x00;
	buf[17] = 0x00;

	memcpy(buf + 18, owner.c_str(), CALL_SIZE);
	buf[25] = from_mod;

	memcpy(buf + 26,  owner.c_str(), CALL_SIZE);
	buf[33] = 'G';

	memcpy(buf + 34, "CQCQCQ  ", CALL_SIZE);

	memcpy(buf + 42, owner.c_str(), CALL_SIZE);
	buf[49] = from_mod;

	memcpy(buf + 50, "RPTR", 4);
	calcPFCS(buf,56);
	sendto(rptr_sock, buf, 56, 0, (struct sockaddr *)&toLocalg2, sizeof(toLocalg2));
	nanos.tv_sec = 0;
	nanos.tv_nsec = delay_between * 1000000;
	nanosleep(&nanos,0);

	buf[4] = 0x20;
	memcpy(buf + 15, silence, 9);

	/* start sending silence + announcement text */

	for (int i=0; i<10; i++) {
		buf[14] = (unsigned char)i;
		switch (i) {
			case 0:
				buf[24] = 0x55;
				buf[25] = 0x2d;
				buf[26] = 0x16;
				break;
			case 1:
				buf[24] = '@' ^ 0x70;
				buf[25] = RADIO_ID[0] ^ 0x4f;
				buf[26] = RADIO_ID[1] ^ 0x93;
				break;
			case 2:
				buf[24] = RADIO_ID[2] ^ 0x70;
				buf[25] = RADIO_ID[3] ^ 0x4f;
				buf[26] = RADIO_ID[4] ^ 0x93;
				break;
			case 3:
				buf[24] = 'A' ^ 0x70;
				buf[25] = RADIO_ID[5] ^ 0x4f;
				buf[26] = RADIO_ID[6] ^ 0x93;
				break;
			case 4:
				buf[24] = RADIO_ID[7] ^ 0x70;
				buf[25] = RADIO_ID[8] ^ 0x4f;
				buf[26] = RADIO_ID[9] ^ 0x93;
				break;
			case 5:
				buf[24] = 'B' ^ 0x70;
				buf[25] = RADIO_ID[10] ^ 0x4f;
				buf[26] = RADIO_ID[11] ^ 0x93;
				break;
			case 6:
				buf[24] = RADIO_ID[12] ^ 0x70;
				buf[25] = RADIO_ID[13] ^ 0x4f;
				buf[26] = RADIO_ID[14] ^ 0x93;
				break;
			case 7:
				buf[24] = 'C' ^ 0x70;
				buf[25] = RADIO_ID[15] ^ 0x4f;
				buf[26] = RADIO_ID[16] ^ 0x93;
				break;
			case 8:
				buf[24] = RADIO_ID[17] ^ 0x70;
				buf[25] = RADIO_ID[18] ^ 0x4f;
				buf[26] = RADIO_ID[19] ^ 0x93;
				break;
			case 9:
				buf[14] |= 0x40;
				memset((char *)buf + 15, 0, 9);
				buf[24] = 0x70;
				buf[25] = 0x4f;
				buf[26] = 0x93;
				break;
		}
		sendto(rptr_sock, buf, 27, 0, (struct sockaddr *)&toLocalg2, sizeof(toLocalg2));
		if (i < 9) {
			nanos.tv_sec = 0;
			nanos.tv_nsec = delay_between * 1000000;
			nanosleep(&nanos,0);
		}
	}
}

static void print_status_file()
{
	struct tm tm1;
	time_t tnow;
	short i;
	inbound *inbound_ptr;
	inbound_type::iterator pos;

	FILE *statusfp = fopen(status_file.c_str(), "w");
	if (!statusfp)
		traceit("Failed to create status file %s\n", status_file.c_str());
	else {
		setvbuf(statusfp, (char *)NULL, _IOLBF, 0);

		time(&tnow);
		localtime_r(&tnow, &tm1);

		/* print connected donglers */
		for (pos = inbound_list.begin(); pos != inbound_list.end(); pos++) {
			inbound_ptr = (inbound *)pos->second;
			fprintf(statusfp,
			        "%c,%s,%c,%s,%02d%02d%02d,%02d:%02d:%02d\n",
			        'p',
			        inbound_ptr->call,
			        'p',
			        pos->first.c_str(),
			        tm1.tm_mon+1,tm1.tm_mday,tm1.tm_year % 100,
			        tm1.tm_hour,tm1.tm_min,tm1.tm_sec);
		}

		/* print linked repeaters-reflectors */
		for (i = 0; i < 3; i++) {
			if (to_remote_g2[i].is_connected) {
				fprintf(statusfp,
				        "%c,%s,%c,%s,%02d%02d%02d,%02d:%02d:%02d\n",
				        to_remote_g2[i].from_mod,
				        to_remote_g2[i].to_call,
				        to_remote_g2[i].to_mod,
				        inet_ntoa(to_remote_g2[i].toDst4.sin_addr),
				        tm1.tm_mon+1,tm1.tm_mday,tm1.tm_year % 100,
				        tm1.tm_hour,tm1.tm_min,tm1.tm_sec);
			}
		}
		fclose(statusfp);
	}
}

/* Open text file of repeaters, reflectors */
static bool load_gwys(const std::string &filename)
{
	char inbuf[1024];
	const char *delim = " ";

	char call[CALL_SIZE + 1];
	char host[MAXHOSTNAMELEN + 1];
	char port[5 + 1];

	/* host + space + port + NULL */
	char payload[MAXHOSTNAMELEN + 1 + 5 + 1];
	unsigned short j;

	gwy_list_type::iterator gwy_pos;
	std::pair<gwy_list_type::iterator,bool> gwy_insert_pair;

	traceit("Trying to open file %s\n", filename.c_str());
	FILE *fp = fopen(filename.c_str(), "r");
	if (fp == NULL) {
		traceit("Failed to open file %s\n", filename.c_str());
		return false;
	}
	traceit("Opened file %s OK\n", filename.c_str());

	while (fgets(inbuf, 1020, fp) != NULL) {
		char *p = strchr(inbuf, '\r');
		if (p)
			*p = '\0';

		p = strchr(inbuf, '\n');
		if (p)
			*p = '\0';

		p = strchr(inbuf, '#');
		if (p) {
			traceit("Comment line:[%s]\n", inbuf);
			continue;
		}

		/* get the call */
		char *tok = strtok(inbuf, delim);
		if (!tok)
			continue;
		if ((strlen(tok) > CALL_SIZE) || (strlen(tok) < 3)) {
			traceit("Invalid call [%s]\n", tok);
			continue;
		}
		memset(call, ' ', CALL_SIZE);
		call[CALL_SIZE] = '\0';
		memcpy(call, tok, strlen(tok));
		for (j = 0; j < strlen(call); j++)
			call[j] = toupper(call[j]);
		if (strcmp(call, owner.c_str()) == 0) {
			traceit("Call [%s] will not be loaded\n", call);
			continue;
		}

		/* get the host */
		tok = strtok(NULL, delim);
		if (!tok) {
			traceit("Call [%s] has no host\n", call);
			continue;
		}
		strncpy(host,tok,MAXHOSTNAMELEN);
		host[MAXHOSTNAMELEN] = '\0';
		if (strcmp(host, "0.0.0.0") == 0) {
			traceit("call %s has invalid host %s\n", call, host);
			continue;
		}

		/* get the port */
		tok = strtok(NULL, delim);
		if (!tok) {
			traceit("Call [%s] has no port\n", call);
			continue;
		}
		if (strlen(tok) > 5) {
			traceit("call %s has invalid port [%s]\n", call, tok);
			continue;
		}
		strcpy(port, tok);

		/* at this point, we have: call host port */
		/* copy the payload(host port) */
		sprintf(payload, "%s %s", host, port);

		gwy_pos = gwy_list.find(call);
		if (gwy_pos == gwy_list.end()) {
			gwy_insert_pair = gwy_list.insert(std::pair<std::string,std::string>(call,payload));
			if (gwy_insert_pair.second)
				traceit("Added Call=[%s], payload=[%s]\n",call, payload);
			else
				traceit("Failed to add: Call=[%s], payload=[%s]\n",call, payload);
		} else
			traceit("Call [%s] is duplicate\n", call);
	}
	fclose(fp);

	traceit("Added %d gateways\n", gwy_list.size());
	return true;
}

/* compute checksum */
static void calcPFCS(unsigned char *packet, int len)
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

/* log the event */
static void traceit(const char *fmt,...)
{
	time_t ltime;
	struct tm mytm;
	const short BFSZ = 1094;
	char buf[BFSZ];

	time(&ltime);
	localtime_r(&ltime,&mytm);

	snprintf(buf,BFSZ - 1,"%02d%02d%02d at %02d:%02d:%02d:",
	         mytm.tm_mon+1,mytm.tm_mday,mytm.tm_year % 100,
	         mytm.tm_hour,mytm.tm_min,mytm.tm_sec);

	va_list args;
	va_start(args,fmt);
	vsnprintf(buf + strlen(buf), BFSZ - strlen(buf) - 1, fmt, args);
	va_end(args);

	fprintf(stdout, "%s", buf);

	return;
}

bool get_value(const Config &cfg, const char *path, int &value, int min, int max, int default_value)
{
	if (cfg.lookupValue(path, value)) {
		if (value < min || value > max)
			value = default_value;
	} else
		value = default_value;
	traceit("%s = [%u]\n", path, value);
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
static bool read_config(char *cfgFile)
{
	admin_type::iterator pos;
	link_unlink_user_type::iterator link_unlink_user_pos;
	unsigned short i;
	Config cfg;

	traceit("Reading file %s\n", cfgFile);
	// Read the file. If there is an error, report it and exit.
	try {
		cfg.readFile(cfgFile);
	}
	catch(const FileIOException &fioex) {
		traceit("Can't read %s\n", cfgFile);
		return false;
	}
	catch(const ParseException &pex) {
		traceit("Parse error at %s:%d - %s\n", pex.getFile(), pex.getLine(), pex.getError());
		return false;
	}

	std::string value;
	std::string key = "g2_link.ref_login";
	if (cfg.lookupValue(key, login_call) || cfg.lookupValue("ircddb.login", login_call)) {
		int l = login_call.length();
		if (l<3 || l>CALL_SIZE-2) {
			traceit("Call '%s' is invalid length!\n", login_call.c_str());
			return false;
		} else {
			for (i=0; i<l; i++) {
				if (islower(login_call[i]))
					login_call[i] = toupper(login_call[i]);
			}
			login_call.resize(CALL_SIZE, ' ');
			traceit("%s = [\"%s\"]\n", key.c_str(), login_call.c_str());
		}
	} else {
		traceit("%s is not defined.\n", key.c_str());
		return false;
	}

	key = "g2_link.admin";
	only_admin_login = false;
	if (cfg.exists(key)) {
		Setting &userlist = cfg.lookup(key);
		if (userlist.isArray()) {
			for (i=0; i<userlist.getLength(); i++) {
				value = (const char *)userlist[i];
				int l = value.length();
				if (l>2 && l<CALL_SIZE-2) {
					for (unsigned int j=0; j<value.length(); j++) {
						if (islower(value[j]))
							value[j] = toupper(value[j]);
					}
					value.resize(CALL_SIZE, ' ');
					if (admin.end() == admin.find(value)) {
						if (admin.insert(value).second)
							only_admin_login = true;
					} else
						traceit("could not add '%s' as user.\n", value.c_str());
				} else
					traceit("'%s' is the wrong length!\n", value.c_str());
			}
		} else {
			traceit("%s is not an array!\n", key.c_str());
			return false;
		}
		traceit("%s = [ ", key.c_str());
		for (pos=admin.begin(); pos!=admin.end(); pos++) {
			if (pos != admin.begin())
				fprintf(stdout, ", ");
			fprintf(stdout, "\"%s\"", (*pos).c_str());
		}
		fprintf(stdout, " ]\n");
	}

	key = "g2_link.link_unlink";
	only_link_unlink = false;
	if (cfg.exists(key)) {
		Setting &unlinklist = cfg.lookup(key);
		if (unlinklist.isArray()) {
			for (i=0; i<unlinklist.getLength(); i++) {
				value = (const char *)unlinklist[i];
				int l = value.length();
				if (l>2 && l<CALL_SIZE-2) {
					for (unsigned int j=0; j<value.length(); j++) {
						if (islower(value[j]))
							value[j] = toupper(value[j]);
					}
					value.resize(CALL_SIZE, ' ');
					if (link_unlink_user.end() == link_unlink_user.find(value)) {
						if (link_unlink_user.insert(value).second)
							only_link_unlink = true;
					} else
						traceit("could not add '%s' to link-unlink.\n", value.c_str());
				} else
					traceit("'%s' is the wrong length!\n", value.c_str());
			}
		} else {
			traceit("%s is not an array!\n", key.c_str());
			return false;
		}
		traceit("%s = [ ", key.c_str());
		for (link_unlink_user_pos=link_unlink_user.begin(); link_unlink_user_pos!=link_unlink_user.end(); link_unlink_user_pos++) {
			if (link_unlink_user_pos != link_unlink_user.begin())
				fprintf(stdout, ", ");
			fprintf(stdout, "\"%s\"", (*link_unlink_user_pos).c_str());
		}
		fprintf(stdout, " ]\n");
	}

	key = "ircddb.login";
	if (cfg.lookupValue(key, owner)) {
		int l = owner.length();
		if (l>2 && l<=CALL_SIZE-2) {
			for (i=0; i<l; i++) {
				if (islower(owner[i]))
					owner[i] = toupper(owner[i]);
			}
			owner.resize(CALL_SIZE, ' ');
			traceit("%s = [%s]\n", key.c_str(), owner.c_str());
		} else {
			traceit("%s '%s' is wrong size.\n", key.c_str(), owner.c_str());
			return false;
		}
	}

	get_value(cfg, "g2_link.ref_port", rmt_ref_port, 10000, 65535, 20001);
	get_value(cfg, "g2_link.xrf_port", rmt_xrf_port, 10000, 65535, 30001);
	get_value(cfg, "g2_link.dcs_port", rmt_dcs_port, 10000, 65535, 30051);

	if (! get_value(cfg, "g2_link.incoming_ip", my_g2_link_ip, 7, IP_SIZE, "0.0.0.0"))
		return false;
	get_value(cfg, "g2_link.port", my_g2_link_port, 10000, 65535, 18997);

	if (! get_value(cfg, "g2_link.g2_ircddb_ip", to_g2_external_ip, 7, IP_SIZE, "0.0.0.0"))
		return false;
	get_value(cfg, "gateway.external.port", to_g2_external_port, 10000, 65535, 40000);

	get_value(cfg, "gateway.log.qso", qso_details, true);

	if (! get_value(cfg, "file.gwys", gwys, 2, FILENAME_MAX, "/usr/local/etc/gwys.txt"))
		return false;

	if (! get_value(cfg, "file.status", status_file, 2, FILENAME_MAX, "/usr/local/etc/RPTR_STATUS.txt"))
		return false;

	get_value(cfg, "timing.play.delay", delay_between, 9, 25, 19);

	get_value(cfg, "g2_link.acknowledge", bool_rptr_ack, true);

	get_value(cfg, "g2_link.announce", announce, true);

	if (! get_value(cfg, "file.announce_dir", announce_dir, 2, FILENAME_MAX, "/usr/local/etc"))
		return false;

	get_value(cfg, "timing.play.wait", delay_before, 1, 10, 2);

	memset(link_at_startup, 0, CALL_SIZE+1);
	if (get_value(cfg, "g2_link.link_at_start", value, 5, CALL_SIZE, "NONE")) {
		if (strcasecmp(value.c_str(), "none"))
			strcpy(link_at_startup, value.c_str());
	} else
		return false;

	int maxdongle;
	get_value(cfg, "g2_link.max_dongles", maxdongle, 0, 10, 5);
	saved_max_dongles = max_dongles = (unsigned int)maxdongle;

	for (i=0; i<3; i++) {
		int timer;
		key = "timing.inactivity.";
		key += ('a' + i);
		get_value(cfg, key.c_str(), timer, 0, 300, 0);
		timer *= 60;
		rf_inactivity_timer[i] = timer;
	}
	
	return true;
}

/* create our server */
static bool srv_open()
{
	struct sockaddr_in sin;
	short i;

	/* create our XRF gateway socket */
	xrf_g2_sock = socket(PF_INET,SOCK_DGRAM,0);
	if (xrf_g2_sock == -1) {
		traceit("Failed to create gateway socket for XRF,errno=%d\n",errno);
		return false;
	}
	fcntl(xrf_g2_sock,F_SETFL,O_NONBLOCK);

	memset(&sin,0,sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(my_g2_link_ip.c_str());
	sin.sin_port = htons(rmt_xrf_port);
	if (bind(xrf_g2_sock,(struct sockaddr *)&sin,sizeof(struct sockaddr_in)) != 0) {
		traceit("Failed to bind gateway socket on port %d for XRF, errno=%d\n",
		        rmt_xrf_port ,errno);
		close(xrf_g2_sock);
		xrf_g2_sock = -1;
		return false;
	}

	/* create the dcs socket */
	dcs_g2_sock = socket(PF_INET,SOCK_DGRAM,0);
	if (dcs_g2_sock == -1) {
		traceit("Failed to create gateway socket for DCS,errno=%d\n",errno);
		close(xrf_g2_sock);
		xrf_g2_sock = -1;
		return false;
	}
	fcntl(dcs_g2_sock,F_SETFL,O_NONBLOCK);

	/* socket for REF */
	ref_g2_sock = socket(PF_INET,SOCK_DGRAM,0);
	if (ref_g2_sock == -1) {
		traceit("Failed to create gateway socket for REF, errno=%d\n",errno);
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
		traceit("Failed to bind gateway socket on port %d for REF, errno=%d\n",
		        rmt_ref_port ,errno);
		close(dcs_g2_sock);
		dcs_g2_sock = -1;
		close(xrf_g2_sock);
		xrf_g2_sock = -1;
		close(ref_g2_sock);
		ref_g2_sock = -1;
		return false;
	}

	/* create our repeater socket */
	rptr_sock = socket(PF_INET,SOCK_DGRAM,0);
	if (rptr_sock == -1) {
		traceit("Failed to create repeater socket,errno=%d\n",errno);
		close(dcs_g2_sock);
		dcs_g2_sock = -1;
		close(xrf_g2_sock);
		xrf_g2_sock = -1;
		close(ref_g2_sock);
		ref_g2_sock = -1;
		return false;
	}
	fcntl(rptr_sock,F_SETFL,O_NONBLOCK);

	memset(&sin,0,sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(my_g2_link_ip.c_str());
	sin.sin_port = htons(my_g2_link_port);
	if (bind(rptr_sock,(struct sockaddr *)&sin,sizeof(struct sockaddr_in)) != 0) {
		traceit("Failed to bind repeater socket on port %d, errno=%d\n",
		        my_g2_link_port,errno);
		close(dcs_g2_sock);
		dcs_g2_sock = -1;
		close(rptr_sock);
		rptr_sock = -1;
		close(xrf_g2_sock);
		xrf_g2_sock = -1;
		close(ref_g2_sock);
		ref_g2_sock = -1;
		return false;
	}

	/* the local G2 external runs on this IP and port */
	memset(&toLocalg2,0,sizeof(struct sockaddr_in));
	toLocalg2.sin_family = AF_INET;
	toLocalg2.sin_addr.s_addr = inet_addr(to_g2_external_ip.c_str());
	toLocalg2.sin_port = htons(to_g2_external_port);

	/* initialize all remote links */
	for (i = 0; i < 3; i++) {
		to_remote_g2[i].to_call[0] = '\0';
		memset(&(to_remote_g2[i].toDst4),0,sizeof(struct sockaddr_in));
		to_remote_g2[i].from_mod = ' ';
		to_remote_g2[i].to_mod = ' ';
		to_remote_g2[i].countdown = 0;
		to_remote_g2[i].is_connected = false;
		to_remote_g2[i].in_streamid[0] = 0x00;
		to_remote_g2[i].in_streamid[1] = 0x00;
		to_remote_g2[i].out_streamid[0] = 0x00;
		to_remote_g2[i].out_streamid[1] = 0x00;
	}
	return true;
}

/* destroy our server */
static void srv_close()
{
	if (xrf_g2_sock != -1) {
		close(xrf_g2_sock);
		traceit("Closed rmt_xrf_port\n");
	}

	if (dcs_g2_sock != -1) {
		close(dcs_g2_sock);
		traceit("Closed rmt_dcs_port\n");
	}

	if (rptr_sock != -1) {
		close(rptr_sock);
		traceit("Closed my_g2_link_port\n");
	}

	if (ref_g2_sock != -1) {
		close(ref_g2_sock);
		traceit("Closed rmt_ref_port\n");
	}

	return;
}

/* find the repeater IP by callsign and link to it */
static void g2link(char from_mod, char *call, char to_mod)
{
	short i,j, counter;

	char linked_remote_system[CALL_SIZE + 1];
	char *space_p = 0;
	char notify_msg[64];

	char host[MAXHOSTNAMELEN + 1];
	char port_s[5 + 1];
	int port_i;

	/* host + space + port + NULL */
	char payload[MAXHOSTNAMELEN + 1 + 5 + 1];
	char *p = NULL;

	gwy_list_type::iterator gwy_pos;
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
		traceit("from_mod %c invalid\n", from_mod);
		return;
	}

	memset(&to_remote_g2[i], 0, sizeof(to_remote_g2[i]));

	strcpy(to_remote_g2[i].to_call, call);
	to_remote_g2[i].to_mod = to_mod;

	if ((memcmp(call, "REF", 3) == 0) ||
	        (memcmp(call, "DCS", 3) == 0)) {
		for (counter = 0; counter < 3; counter++) {
			if (counter != i) {
				if ( (to_remote_g2[counter].to_call[0] != '\0') &&
				        (strcmp(to_remote_g2[counter].to_call,to_remote_g2[i].to_call) == 0) &&
				        (to_remote_g2[counter].to_mod == to_remote_g2[i].to_mod) )
					break;
			}
		}
		to_remote_g2[i].to_call[0] = '\0';
		to_remote_g2[i].to_mod = ' ';

		if (counter < 3) {
			traceit("Another mod(%c) is already linked to %s %c\n",
			        to_remote_g2[counter].from_mod,
			        to_remote_g2[counter].to_call,
			        to_remote_g2[counter].to_mod);

			return;
		}
	}

	gwy_pos = gwy_list.find(call);
	if (gwy_pos == gwy_list.end()) {
		traceit("%s not found in gwy list\n", call);
		return;
	}

	strcpy(payload, gwy_pos->second.c_str());

	/* extract host and port */
	p = strchr(payload, ' ');
	if (!p) {
		traceit("Invalid payload [%s] for call [%s]\n", payload, call);
		return;
	}
	*p = '\0';

	strcpy(host, payload);
	strcpy(port_s, p + 1);
	port_i = atoi(port_s);

	if (host[0] != '\0') {
		ok = resolve_rmt(host, SOCK_DGRAM, &(to_remote_g2[i].toDst4));
		if (!ok) {
			traceit("Call %s is host %s but could not resolve to IP\n",
			        call, host);
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
		to_remote_g2[i].in_streamid[0] = 0x00;
		to_remote_g2[i].in_streamid[1] = 0x00;

		/* is it XRF? */
		if (port_i == rmt_xrf_port) {
			strcpy(link_request, owner.c_str());
			link_request[8] = from_mod;
			link_request[9] = to_mod;
			link_request[10] = '\0';

			traceit("sending link request from mod %c to link with: [%s] mod %c [%s]\n",
			        to_remote_g2[i].from_mod,
			        to_remote_g2[i].to_call, to_remote_g2[i].to_mod, payload);

			for (j=0; j<5; j++)
				sendto(xrf_g2_sock, link_request, CALL_SIZE + 3, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));
		} else if (port_i == rmt_dcs_port) {
			strcpy(link_request, owner.c_str());
			link_request[8] = from_mod;
			link_request[9] = to_mod;
			link_request[10] = '\0';
			memcpy(link_request + 11, to_remote_g2[i].to_call, 8);
			strcpy(link_request + 19, G2_html);

			traceit("sending link request from mod %c to link with: [%s] mod %c [%s]\n",
			        to_remote_g2[i].from_mod,
			        to_remote_g2[i].to_call, to_remote_g2[i].to_mod, payload);
// Login form 5 to 1
			for (j=0; j<1; j++)
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
				traceit("sending link command from mod %c to: [%s] mod %c [%s]\n",
				        to_remote_g2[i].from_mod,
				        to_remote_g2[i].to_call, to_remote_g2[i].to_mod, payload);

				queryCommand[0] = 5;
				queryCommand[1] = 0;
				queryCommand[2] = 24;
				queryCommand[3] = 0;
				queryCommand[4] = 1;

				for (j = 0; j < 1; j++)
					sendto(ref_g2_sock, queryCommand, 5, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));
			} else {
				if (to_remote_g2[counter].is_connected) {
					to_remote_g2[i].is_connected = true;
					traceit("Local module %c is also connected to %s %c\n",
					        from_mod, call, to_mod);

					print_status_file();
					tracing[i].last_time = time(NULL);

					// announce it here
					strcpy(linked_remote_system, to_remote_g2[i].to_call);
					space_p = strchr(linked_remote_system, ' ');
					if (space_p)
						*space_p = '\0';
					sprintf(notify_msg, "%c_linked.dat_LINKED_%s_%c",
					        to_remote_g2[i].from_mod,
					        linked_remote_system,
					        to_remote_g2[i].to_mod);
					audio_notify(notify_msg);
				} else
					traceit("status from %s %c pending\n", to_remote_g2[i].to_call, to_remote_g2[i].to_mod);
			}
		}
	}
	return;
}

/* signal catching function */
static void sigCatch(int signum)
{
	/* do NOT do any serious work here */
	if ((signum == SIGTERM) || (signum == SIGINT))
		keep_running = false;
	return;
}

static void runit()
{
	socklen_t fromlen;
	int recvlen;
	int recvlen2;
	short i,j,k;
	char temp_repeater[CALL_SIZE + 1];
	time_t tnow = 0, hb = 0;
	int rc = 0;

	char *p = NULL;

	char notify_msg[64];
	char *space_p = 0;
	char linked_remote_system[CALL_SIZE + 1];
	char unlink_request[CALL_SIZE + 3];

	char system_cmd[FILENAME_MAX + 1];
	int max_nfds = 0;

	char tmp1[CALL_SIZE + 1];
	char tmp2[36]; // 8 for rpt1 + 24 for time_t in std::string format
	unsigned char readBuffer[100]; // 58 or 29 or 32, max is 58
	unsigned char readBuffer2[1024];
	unsigned char dcs_buf[1000];
	dt_lh_type::iterator dt_lh_pos;
	dt_lh_type::reverse_iterator r_dt_lh_pos;

	gwy_list_type::iterator gwy_pos;

	char call[CALL_SIZE + 1];
	char ip[IP_SIZE + 1];
	inbound *inbound_ptr;
	inbound_type::iterator pos;
	std::pair<inbound_type::iterator,bool> insert_pair;
	bool found = false;
	std::set<std::string>::iterator it;

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

	memset(notify_msg, '\0', sizeof(notify_msg));
	time(&hb);

	if (xrf_g2_sock > max_nfds)
		max_nfds = xrf_g2_sock;
	if (ref_g2_sock > max_nfds)
		max_nfds = ref_g2_sock;
	if (rptr_sock > max_nfds)
		max_nfds = rptr_sock;
	if (dcs_g2_sock > max_nfds)
		max_nfds = dcs_g2_sock;

	traceit("xrf=%d, dcs=%d, ref=%d, rptr=%d, MAX+1=%d\n",
	        xrf_g2_sock, dcs_g2_sock, ref_g2_sock, rptr_sock, max_nfds + 1);

	if (strlen(link_at_startup) >= 8) {
		if ((link_at_startup[0] == 'A') || (link_at_startup[0] == 'B') || (link_at_startup[0] == 'C')) {
			memset(temp_repeater, ' ', CALL_SIZE);
			memcpy(temp_repeater, link_at_startup + 1, 6);
			temp_repeater[CALL_SIZE] = '\0';
			traceit("sleep for 15 before link at startup\n");
			sleep(15);
			g2link(link_at_startup[0], temp_repeater, link_at_startup[7]);
		}
		memset(link_at_startup, '\0', sizeof(link_at_startup));
	}

	while (keep_running) {
		time(&tnow);
		if ((tnow - hb) > 0) {
			/* send heartbeat to connected donglers */
			send_heartbeat();

			/* send heartbeat to linked XRF repeaters/reflectors */
			if (to_remote_g2[0].toDst4.sin_port == htons(rmt_xrf_port))
				sendto(xrf_g2_sock, owner.c_str(), CALL_SIZE+1, 0, (struct sockaddr *)&(to_remote_g2[0].toDst4), sizeof(to_remote_g2[0].toDst4));

			if ((to_remote_g2[1].toDst4.sin_port == htons(rmt_xrf_port)) && (strcmp(to_remote_g2[1].to_call, to_remote_g2[0].to_call) != 0))
				sendto(xrf_g2_sock, owner.c_str(), CALL_SIZE+1, 0, (struct sockaddr *)&(to_remote_g2[1].toDst4), sizeof(to_remote_g2[1].toDst4));

			if ((to_remote_g2[2].toDst4.sin_port == htons(rmt_xrf_port)) &&
			        (strcmp(to_remote_g2[2].to_call, to_remote_g2[0].to_call) != 0) &&
			        (strcmp(to_remote_g2[2].to_call, to_remote_g2[1].to_call) != 0))
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

			if (to_remote_g2[1].is_connected &&
			        (to_remote_g2[1].toDst4.sin_port == htons(rmt_ref_port)) &&
			        (strcmp(to_remote_g2[1].to_call, to_remote_g2[0].to_call) != 0))
				sendto(ref_g2_sock, REF_ACK, 3, 0, (struct sockaddr *)&(to_remote_g2[1].toDst4), sizeof(to_remote_g2[1].toDst4));

			if (to_remote_g2[2].is_connected &&
			        (to_remote_g2[2].toDst4.sin_port == htons(rmt_ref_port)) &&
			        (strcmp(to_remote_g2[2].to_call, to_remote_g2[0].to_call) != 0) &&
			        (strcmp(to_remote_g2[2].to_call, to_remote_g2[1].to_call) != 0))
				sendto(ref_g2_sock, REF_ACK, 3, 0, (struct sockaddr *)&(to_remote_g2[2].toDst4), sizeof(to_remote_g2[2].toDst4));

			for (i = 0; i < 3; i++) {
				/* check for timeouts from remote */
				if (to_remote_g2[i].to_call[0] != '\0') {
					if (to_remote_g2[i].countdown >= 0)
						to_remote_g2[i].countdown--;

					if (to_remote_g2[i].countdown < 0) {
						/* maybe remote system has changed IP */
						traceit("Unlinked from [%s] mod %c, TIMEOUT...\n",
						        to_remote_g2[i].to_call, to_remote_g2[i].to_mod);

						sprintf(notify_msg, "%c_unlinked.dat_UNLINKED_TIMEOUT", to_remote_g2[i].from_mod);
						audio_notify(notify_msg);

						to_remote_g2[i].to_call[0] = '\0';
						memset(&(to_remote_g2[i].toDst4),0,sizeof(struct sockaddr_in));
						to_remote_g2[i].from_mod = ' ';
						to_remote_g2[i].to_mod = ' ';
						to_remote_g2[i].countdown = 0;
						to_remote_g2[i].is_connected = false;
						to_remote_g2[i].in_streamid[0] = 0x00;
						to_remote_g2[i].in_streamid[1] = 0x00;

						print_status_file();

					}
				}

				/*** check for RF inactivity ***/
				if (to_remote_g2[i].is_connected) {
					if (((tnow - tracing[i].last_time) > rf_inactivity_timer[i]) && (rf_inactivity_timer[i] > 0)) {
						tracing[i].last_time = 0;

						traceit("Unlinked from [%s] mod %c, local RF inactivity...\n",
						        to_remote_g2[i].to_call, to_remote_g2[i].to_mod);

						if (to_remote_g2[i].toDst4.sin_port == htons(rmt_ref_port)) {
							queryCommand[0] = 5;
							queryCommand[1] = 0;
							queryCommand[2] = 24;
							queryCommand[3] = 0;
							queryCommand[4] = 0;
							sendto(ref_g2_sock, queryCommand, 5, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));

							/* zero out any other entries here that match that system */
							for (j = 0; j < 3; j++) {
								if (j != i) {
									if ((to_remote_g2[j].toDst4.sin_addr.s_addr == to_remote_g2[i].toDst4.sin_addr.s_addr) &&
									        (to_remote_g2[j].toDst4.sin_port == htons(rmt_ref_port))) {
										to_remote_g2[j].to_call[0] = '\0';
										memset(&(to_remote_g2[j].toDst4),0,sizeof(struct sockaddr_in));
										to_remote_g2[j].from_mod = ' ';
										to_remote_g2[j].to_mod = ' ';
										to_remote_g2[j].countdown = 0;
										to_remote_g2[j].is_connected = false;
										to_remote_g2[j].in_streamid[0] = to_remote_g2[j].in_streamid[1] = 0x00;
									}
								}
							}
						} else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port)) {
							strcpy(unlink_request, owner.c_str());
							unlink_request[8] = to_remote_g2[i].from_mod;
							unlink_request[9] = ' ';
							unlink_request[10] = '\0';

							for (j = 0; j < 5; j++)
								sendto(xrf_g2_sock, unlink_request, CALL_SIZE+3, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));
						} else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_dcs_port)) {
							strcpy(cmd_2_dcs, owner.c_str());
							cmd_2_dcs[8] = to_remote_g2[i].from_mod;
							cmd_2_dcs[9] = ' ';
							cmd_2_dcs[10] = '\0';
							memcpy(cmd_2_dcs + 11, to_remote_g2[i].to_call, 8);

							for (j=0; j<2; j++)
								sendto(dcs_g2_sock, cmd_2_dcs, 19 ,0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));
						}

						sprintf(notify_msg, "%c_unlinked.dat_UNLINKED_TIMEOUT", to_remote_g2[i].from_mod);
						audio_notify(notify_msg);

						to_remote_g2[i].to_call[0] = '\0';
						memset(&(to_remote_g2[i].toDst4),0,sizeof(struct sockaddr_in));
						to_remote_g2[i].from_mod = ' ';
						to_remote_g2[i].to_mod = ' ';
						to_remote_g2[i].countdown = 0;
						to_remote_g2[i].is_connected = false;
						to_remote_g2[i].in_streamid[0] = 0x00;
						to_remote_g2[i].in_streamid[1] = 0x00;

						print_status_file();
					}
				}
			}
			time(&hb);
		}

		FD_ZERO(&fdset);
		FD_SET(xrf_g2_sock,&fdset);
		FD_SET(dcs_g2_sock,&fdset);
		FD_SET(ref_g2_sock,&fdset);
		FD_SET(rptr_sock,&fdset);
		tv.tv_sec = 0;
		tv.tv_usec = 20000;
		(void)select(max_nfds + 1,&fdset,0,0,&tv);

		if (FD_ISSET(xrf_g2_sock, &fdset)) {
			fromlen = sizeof(struct sockaddr_in);
			recvlen2 = recvfrom(xrf_g2_sock, (char *)readBuffer2, 100, 0, (struct sockaddr *)&fromDst4, &fromlen);

			strncpy(ip, inet_ntoa(fromDst4.sin_addr),IP_SIZE);
			ip[IP_SIZE] = '\0';
			strncpy(call, (char *)readBuffer2,CALL_SIZE);
			call[CALL_SIZE] = '\0';

			/* a packet of length (CALL_SIZE + 1) is a keepalive from a repeater/reflector */
			/* If it is from a dongle, it is either a keepalive or a request to connect */

			if (recvlen2 == (CALL_SIZE + 1)) {
				found = false;
				/* Find out if it is a keepalive from a repeater */
				for (i = 0; i < 3; i++) {
					if ((fromDst4.sin_addr.s_addr == to_remote_g2[i].toDst4.sin_addr.s_addr) &&
					        (to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port))) {
						found = true;
						if (!to_remote_g2[i].is_connected) {
							tracing[i].last_time = time(NULL);

							to_remote_g2[i].is_connected = true;
							traceit("Connected from: %.*s\n", recvlen2 - 1, readBuffer2);
							print_status_file();

							strcpy(linked_remote_system, to_remote_g2[i].to_call);
							space_p = strchr(linked_remote_system, ' ');
							if (space_p)
								*space_p = '\0';
							sprintf(notify_msg, "%c_linked.dat_LINKED_%s_%c",
							        to_remote_g2[i].from_mod,
							        linked_remote_system,
							        to_remote_g2[i].to_mod);
							audio_notify(notify_msg);

						}
						to_remote_g2[i].countdown = TIMEOUT;
					}
				}
			} else if (recvlen2 == (CALL_SIZE + 6)) {
				/* A packet of length (CALL_SIZE + 6) is either an ACK or a NAK from repeater-reflector */
				/* Because we sent a request before asking to link */
				
					for (i = 0; i < 3; i++) {
						if ((fromDst4.sin_addr.s_addr == to_remote_g2[i].toDst4.sin_addr.s_addr) &&
						        (to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port))) {
							if ((memcmp((char *)readBuffer2 + 10, "ACK", 3) == 0) &&
							        (to_remote_g2[i].from_mod == readBuffer2[8])) {
								if (!to_remote_g2[i].is_connected) {
									tracing[i].last_time = time(NULL);

									to_remote_g2[i].is_connected = true;
									traceit("Connected from: [%s] %c\n",
									        to_remote_g2[i].to_call, to_remote_g2[i].to_mod);
									print_status_file();

									strcpy(linked_remote_system, to_remote_g2[i].to_call);
									space_p = strchr(linked_remote_system, ' ');
									if (space_p)
										*space_p = '\0';
									sprintf(notify_msg, "%c_linked.dat_LINKED_%s_%c",
									        to_remote_g2[i].from_mod,
									        linked_remote_system,
									        to_remote_g2[i].to_mod);
									audio_notify(notify_msg);
								}
							} else if ((memcmp((char *)readBuffer2 + 10, "NAK", 3) == 0) &&
							           (to_remote_g2[i].from_mod == readBuffer2[8])) {
								traceit("Link module %c to [%s] %c is rejected\n",
								        to_remote_g2[i].from_mod, to_remote_g2[i].to_call,
								        to_remote_g2[i].to_mod);

								sprintf(notify_msg, "%c_failed_linked.dat_FAILED_TO_LINK",
								        to_remote_g2[i].from_mod);
								audio_notify(notify_msg);

								to_remote_g2[i].to_call[0] = '\0';
								memset(&(to_remote_g2[i].toDst4),0,sizeof(struct sockaddr_in));
								to_remote_g2[i].from_mod = ' ';
								to_remote_g2[i].to_mod = ' ';
								to_remote_g2[i].countdown = 0;
								to_remote_g2[i].is_connected = false;
								to_remote_g2[i].in_streamid[0] = 0x00;
								to_remote_g2[i].in_streamid[1] = 0x00;

								print_status_file();
							}
						}
					}
			} else if (recvlen2 == CALL_SIZE + 3) {
			/*
			   A packet of length (CALL_SIZE + 3) is a request
			   from a remote repeater to link-unlink with our repeater
			*/
			
				/* Check our linked repeaters/reflectors */
				for (i = 0; i < 3; i++) {
					if ((fromDst4.sin_addr.s_addr == to_remote_g2[i].toDst4.sin_addr.s_addr) &&
							(to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port))) {
						if (to_remote_g2[i].to_mod == readBuffer2[8]) {
							/* unlink request from remote repeater that we know */
							if (readBuffer2[9] == ' ') {
								traceit("Received: %.*s\n", recvlen2 - 1, readBuffer2);
								traceit("Module %c to [%s] %c is unlinked\n",
										to_remote_g2[i].from_mod,
										to_remote_g2[i].to_call, to_remote_g2[i].to_mod);

								sprintf(notify_msg, "%c_unlinked.dat_UNLINKED", to_remote_g2[i].from_mod);
								audio_notify(notify_msg);

								to_remote_g2[i].to_call[0] = '\0';
								memset(&(to_remote_g2[i].toDst4),0,sizeof(struct sockaddr_in));
								to_remote_g2[i].from_mod = ' ';
								to_remote_g2[i].to_mod = ' ';
								to_remote_g2[i].countdown = 0;
								to_remote_g2[i].is_connected = false;
								to_remote_g2[i].in_streamid[0] = 0x00;
								to_remote_g2[i].in_streamid[1] = 0x00;

								print_status_file();
							} else
								/* link request from a remote repeater that we know */
								if (
									((i == 0) && (readBuffer2[9] == 'A')) ||
									((i == 1) && (readBuffer2[9] == 'B')) ||
									((i == 2) && (readBuffer2[9] == 'C'))
								) {

									/*
									   I HAVE TO ADD CODE here to PREVENT the REMOTE NODE
									   from LINKING one of their remote modules to
									   more than one of our local modules
									*/

									traceit("Received: %.*s\n", recvlen2 - 1, readBuffer2);

									strncpy(to_remote_g2[i].to_call, (char *)readBuffer2,CALL_SIZE);
									to_remote_g2[i].to_call[CALL_SIZE] = '\0';
									memcpy(&(to_remote_g2[i].toDst4), &fromDst4, sizeof(struct sockaddr_in));
									to_remote_g2[i].toDst4.sin_port = htons(rmt_xrf_port);
									to_remote_g2[i].to_mod = readBuffer2[8];
									to_remote_g2[i].countdown = TIMEOUT;
									to_remote_g2[i].is_connected = true;
									to_remote_g2[i].in_streamid[0] = 0x00;
									to_remote_g2[i].in_streamid[1] = 0x00;

									traceit("Module %c to [%s] %c linked\n",
											readBuffer2[9],
											to_remote_g2[i].to_call, to_remote_g2[i].to_mod);

									tracing[i].last_time = time(NULL);

									print_status_file();

									/* send back an ACK */
									memcpy(readBuffer2 + 10, "ACK", 4);
									sendto(xrf_g2_sock, readBuffer2, CALL_SIZE+6, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));

									if (to_remote_g2[i].from_mod != readBuffer2[9]) {
										to_remote_g2[i].from_mod = readBuffer2[9];

										strcpy(linked_remote_system, to_remote_g2[i].to_call);
										space_p = strchr(linked_remote_system, ' ');
										if (space_p)
											*space_p = '\0';
										sprintf(notify_msg, "%c_linked.dat_LINKED_%s_%c",
												to_remote_g2[i].from_mod,
												linked_remote_system,
												to_remote_g2[i].to_mod);
										audio_notify(notify_msg);
									}
								}
						}
					}
				}

				/* link request from remote repeater that is not yet linked to our system */
				/* find out which of our local modules the remote repeater is interested in */
				i = -1;
				if (readBuffer2[9] == 'A')
					i = 0;
				else if (readBuffer2[9] == 'B')
					i = 1;
				else if (readBuffer2[9] == 'C')
					i = 2;

				/* Is this repeater listed in gwys.txt? */
				gwy_pos = gwy_list.find(call);
				if (gwy_pos == gwy_list.end()) {
					/* We did NOT find this repeater in gwys.txt, reject the incoming link request */
					traceit("Incoming link from %s,%s but not found in gwys.txt\n",call,ip);
					i = -1;
				} else {
					rc = regexec(&preg, call, 0, NULL, 0);
					if (rc != 0) {
						traceit("Invalid repeater %s,%s requesting to link\n", call, ip);
						i = -1;
					}
				}

				if (i >= 0) {
					/* Is the local repeater module linked to anything ? */
					if (to_remote_g2[i].to_mod == ' ') {
						if ((readBuffer2[8] == 'A') || (readBuffer2[8] == 'B') || (readBuffer2[8] == 'C') ||
								(readBuffer2[8] == 'D') || (readBuffer2[8] == 'E')) {
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
							to_remote_g2[i].from_mod = readBuffer2[9];
							to_remote_g2[i].to_mod = readBuffer2[8];
							to_remote_g2[i].countdown = TIMEOUT;
							to_remote_g2[i].is_connected = true;
							to_remote_g2[i].in_streamid[0] = 0x00;
							to_remote_g2[i].in_streamid[1] = 0x00;

							print_status_file();

							tracing[i].last_time = time(NULL);

							traceit("Received: %.*s\n", recvlen2 - 1, readBuffer2);
							traceit("Module %c to [%s] %c linked\n",
									to_remote_g2[i].from_mod,
									to_remote_g2[i].to_call, to_remote_g2[i].to_mod);

							strcpy(linked_remote_system, to_remote_g2[i].to_call);
							space_p = strchr(linked_remote_system, ' ');
							if (space_p)
								*space_p = '\0';
							sprintf(notify_msg, "%c_linked.dat_LINKED_%s_%c",
									to_remote_g2[i].from_mod,
									linked_remote_system,
									to_remote_g2[i].to_mod);
							audio_notify(notify_msg);

							/* send back an ACK */
							memcpy(readBuffer2 + 10, "ACK", 4);
							sendto(xrf_g2_sock, readBuffer2, CALL_SIZE+6, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));
						}
					} else {
						if (fromDst4.sin_addr.s_addr != to_remote_g2[i].toDst4.sin_addr.s_addr) {
							/* Our repeater module is linked to another repeater-reflector */
							memcpy(readBuffer2 + 10, "NAK", 4);
							fromDst4.sin_port = htons(rmt_xrf_port);
							sendto(xrf_g2_sock, readBuffer2, CALL_SIZE+6, 0, (struct sockaddr *)&fromDst4, sizeof(struct sockaddr_in));
						}
					}
				}
			} else if ( ((recvlen2 == 56) || (recvlen2 == 27)) &&
						(0 == memcmp(readBuffer2, "DSVT", 4)) &&
						((readBuffer2[4] == 0x10) || (readBuffer2[4] == 0x20)) &&
						(readBuffer2[8] == 0x20)) {
				/* reset countdown and protect against hackers */

				found = false;
				for (i = 0; i < 3; i++) {
					if ((fromDst4.sin_addr.s_addr == to_remote_g2[i].toDst4.sin_addr.s_addr) &&
							(to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port))) {
						to_remote_g2[i].countdown = TIMEOUT;
						found = true;
					}
				}

				/* process header */

				if ((recvlen2 == 56) && found) {
					memset(source_stn, ' ', 9);
					source_stn[8] = '\0';

					/* some bad hotspot programs out there using INCORRECT flag */
					if (readBuffer2[15] == 0x40)
						readBuffer2[15] = 0x00;
					else if (readBuffer2[15] == 0x48)
						readBuffer2[15] = 0x08;
					else if (readBuffer2[15] == 0x60)
						readBuffer2[15] = 0x20;
					else if (readBuffer2[15] == 0x68)
						readBuffer2[15] = 0x28;

					/* A reflector will send to us its own RPT1 */
					/* A repeater will send to us our RPT1 */

					for (i = 0; i < 3; i++) {
						if ((fromDst4.sin_addr.s_addr == to_remote_g2[i].toDst4.sin_addr.s_addr) &&
								(to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port))) {
							/* it is a reflector, reflector's rpt1 */
							if ((memcmp(readBuffer2 + 18, to_remote_g2[i].to_call, 7) == 0) &&
									(readBuffer2[25] == to_remote_g2[i].to_mod)) {
								memcpy(&readBuffer2[18], owner.c_str(), CALL_SIZE);
								readBuffer2[25] = to_remote_g2[i].from_mod;
								memcpy(&readBuffer2[34], "CQCQCQ  ", 8);

								memcpy(source_stn, to_remote_g2[i].to_call, 8);
								source_stn[7] = to_remote_g2[i].to_mod;
								break;
							} else
								/* it is a repeater, our rpt1 */
								if ((memcmp(readBuffer2 + 18, owner.c_str(), CALL_SIZE-1)) &&
										(readBuffer2[25] == to_remote_g2[i].from_mod)) {
									memcpy(source_stn, to_remote_g2[i].to_call, 8);
									source_stn[7] = to_remote_g2[i].to_mod;
									break;
								}
						}
					}

					/* somebody's crazy idea of having a personal callsign in RPT2 */
					/* we must set it to our gateway callsign */
					memcpy(&readBuffer2[26], owner.c_str(), CALL_SIZE);
					readBuffer2[33] = 'G';
					calcPFCS(readBuffer2,56);

					/* At this point, all data have our RPT1 and RPT2 */

					/* send the data to the repeater/reflector that is linked to our RPT1 */
					i = -1;
					if (readBuffer2[25] == 'A')
						i = 0;
					else if (readBuffer2[25] == 'B')
						i = 1;
					else if (readBuffer2[25] == 'C')
						i = 2;

					/* are we sure that RPT1 is our system? */
					if ((memcmp(readBuffer2 + 18, owner.c_str(), CALL_SIZE-1) == 0) && (i >= 0)) {
						/* Last Heard */
						if (memcmp(old_sid[i].sid, readBuffer2 + 12, 2) != 0) {
							if (qso_details)
								traceit("START from remote g2: streamID=%d,%d, flags=%02x:%02x:%02x, my=%.8s, sfx=%.4s, ur=%.8s, rpt1=%.8s, rpt2=%.8s, %d bytes fromIP=%s, source=%.8s\n",
										readBuffer2[12],readBuffer2[13],
										readBuffer2[15], readBuffer2[16], readBuffer2[17],
										&readBuffer2[42],
										&readBuffer2[50], &readBuffer2[34],
										&readBuffer2[18], &readBuffer2[26],
										recvlen2,inet_ntoa(fromDst4.sin_addr), source_stn);

							// put user into tmp1
							memcpy(tmp1, readBuffer2 + 42, 8);
							tmp1[8] = '\0';

							// delete the user if exists
							for (dt_lh_pos = dt_lh_list.begin(); dt_lh_pos != dt_lh_list.end();  dt_lh_pos++) {
								if (strcmp((char *)dt_lh_pos->second.c_str(), tmp1) == 0) {
									dt_lh_list.erase(dt_lh_pos);
									break;
								}
							}
							/* Limit?, delete oldest user */
							if (dt_lh_list.size() == LH_MAX_SIZE) {
								dt_lh_pos = dt_lh_list.begin();
								dt_lh_list.erase(dt_lh_pos);
							}
							// add user
							time(&tnow);
							sprintf(tmp2, "%ld=r%.6s%c%c", tnow, source_stn, source_stn[7], readBuffer2[25]);
							dt_lh_list[tmp2] = tmp1;

							memcpy(old_sid[i].sid, readBuffer2 + 12, 2);
						}

						/* relay data to our local G2 */
						sendto(rptr_sock, readBuffer2,56,0,(struct sockaddr *)&toLocalg2,sizeof(struct sockaddr_in));

						/* send data to donglers */
						/* no changes here */
						for (pos = inbound_list.begin(); pos != inbound_list.end(); pos++) {
							inbound_ptr = (inbound *)pos->second;
							if (fromDst4.sin_addr.s_addr != inbound_ptr->sin.sin_addr.s_addr) {
								readBuffer[0] = (unsigned char)(58 & 0xFF);
								readBuffer[1] = (unsigned char)(58 >> 8 & 0x1F);
								readBuffer[1] = (unsigned char)(readBuffer[1] | 0xFFFFFF80);
								memcpy(readBuffer + 2, readBuffer2, 56);

								sendto(ref_g2_sock, readBuffer, 58, 0, (struct sockaddr *)&(inbound_ptr->sin), sizeof(struct sockaddr_in));
							} else
								inbound_ptr->mod = readBuffer2[25];
						}

						/* send the data to the repeater/reflector that is linked to our RPT1 */

						/* Is there another local module linked to the remote same xrf mod ? */
						/* If Yes, then broadcast */
						k = i + 1;

						if (k < 3) {
							brd_from_xrf_idx = 0;
							streamid_raw = (readBuffer2[12] * 256U) + readBuffer2[13];

							/* We can only enter this loop up to 2 times max */
							for (j = k; j < 3; j++) {
								/* it is a remote gateway, not a dongle user */
								if ((fromDst4.sin_addr.s_addr == to_remote_g2[j].toDst4.sin_addr.s_addr) &&
										/* it is xrf */
										(to_remote_g2[j].toDst4.sin_port == htons(rmt_xrf_port)) &&
										(memcmp(to_remote_g2[j].to_call, "XRF", 3) == 0) &&
										/* it is the same xrf and xrf module */
										(memcmp(to_remote_g2[j].to_call, to_remote_g2[i].to_call, 8) == 0) &&
										(to_remote_g2[j].to_mod == to_remote_g2[i].to_mod)) {
									/* send the packet to another module of our local repeater: this is multi-link */

									/* generate new packet */
									memcpy(from_xrf_torptr_brd, readBuffer2, 56);

									/* different repeater module */
									from_xrf_torptr_brd[25] = to_remote_g2[j].from_mod;

									/* assign new streamid */
									streamid_raw ++;
									if (streamid_raw == 0)
										streamid_raw ++;
									from_xrf_torptr_brd[12] = streamid_raw / 256U;
									from_xrf_torptr_brd[13] = streamid_raw % 256U;

									calcPFCS(from_xrf_torptr_brd, 56);

									/* send the data to the local gateway/repeater */
									sendto(rptr_sock, from_xrf_torptr_brd, 56, 0, (struct sockaddr *)&toLocalg2,sizeof(struct sockaddr_in));

									/* save streamid for use with the audio packets that will arrive after this header */

									brd_from_xrf.xrf_streamid[0] = readBuffer2[12];
									brd_from_xrf.xrf_streamid[1] = readBuffer2[13];
									brd_from_xrf.rptr_streamid[brd_from_xrf_idx][0] = from_xrf_torptr_brd[12];
									brd_from_xrf.rptr_streamid[brd_from_xrf_idx][1] = from_xrf_torptr_brd[13];
									brd_from_xrf_idx ++;
								}
							}
						}

						if ((to_remote_g2[i].toDst4.sin_addr.s_addr != fromDst4.sin_addr.s_addr) &&
								to_remote_g2[i].is_connected) {
							if (to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port)) {
								if ( /*** (memcmp(readBuffer2 + 42, owner, 8) != 0) && ***/         /* block repeater announcements */
									(memcmp(readBuffer2 + 34, "CQCQCQ", 6) == 0) &&     /* CQ calls only */
									((readBuffer2[15] == 0x00)  ||                       /* normal */
									 (readBuffer2[15] == 0x08)  ||                       /* EMR */
									 (readBuffer2[15] == 0x20)  ||                       /* BK */
									 (readBuffer2[15] == 0x28)) &&                       /* EMR + BK */
									(memcmp(readBuffer2 + 26, owner.c_str(), CALL_SIZE-1) == 0) &&         /* rpt2 must be us */
									(readBuffer2[33] == 'G')) {
									to_remote_g2[i].in_streamid[0] = readBuffer2[12];
									to_remote_g2[i].in_streamid[1] = readBuffer2[13];

									/* inform XRF about the source */
									readBuffer2[11] = to_remote_g2[i].from_mod;

									memcpy((char *)readBuffer2 + 18, to_remote_g2[i].to_call, CALL_SIZE);
									readBuffer2[25] = to_remote_g2[i].to_mod;
									memcpy((char *)readBuffer2 + 26, to_remote_g2[i].to_call, CALL_SIZE);
									readBuffer2[33] = 'G';
									calcPFCS(readBuffer2, 56);

									sendto(xrf_g2_sock, readBuffer2, 56, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));
								}
							} else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_ref_port)) {
								if ( /*** (memcmp(readBuffer2 + 42, owner, 8) != 0) && ***/         /* block repeater announcements */
											(memcmp(readBuffer2 + 34, "CQCQCQ", 6) == 0) &&     /* CQ calls only */
											((readBuffer2[15] == 0x00)  ||                       /* normal */
											 (readBuffer2[15] == 0x08)  ||                       /* EMR */
											 (readBuffer2[15] == 0x20)  ||                       /* BK */
											 (readBuffer2[15] == 0x28)) &&                       /* EMR + BK */
											(memcmp(readBuffer2 + 26, owner.c_str(), CALL_SIZE-1) == 0) &&         /* rpt2 must be us */
											(readBuffer2[33] == 'G')) {
									to_remote_g2[i].in_streamid[0] = readBuffer2[12];
									to_remote_g2[i].in_streamid[1] = readBuffer2[13];

									readBuffer[0] = (unsigned char)(58 & 0xFF);
									readBuffer[1] = (unsigned char)(58 >> 8 & 0x1F);
									readBuffer[1] = (unsigned char)(readBuffer[1] | 0xFFFFFF80);

									memcpy(readBuffer + 2, readBuffer2, 56);

									memset(readBuffer + 20, ' ', CALL_SIZE);
									memcpy(readBuffer + 20, to_remote_g2[i].to_call,
										   strlen(to_remote_g2[i].to_call));
									readBuffer[27] = to_remote_g2[i].to_mod;
									memset(readBuffer + 28, ' ', CALL_SIZE);
									memcpy(readBuffer + 28, to_remote_g2[i].to_call,
										   strlen(to_remote_g2[i].to_call));
									readBuffer[35] = 'G';
									memcpy(&readBuffer[36], "CQCQCQ  ", 8);

									calcPFCS(readBuffer + 2, 56);

									sendto(ref_g2_sock, readBuffer, 58, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));
								}
							} else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_dcs_port)) {
								if ( /*** (memcmp(readBuffer2 + 42, owner, 8) != 0) && ***/         /* block repeater announcements */
										(memcmp(readBuffer2 + 34, "CQCQCQ", 6) == 0) &&     /* CQ calls only */
										((readBuffer2[15] == 0x00)  ||                       /* normal */
										 (readBuffer2[15] == 0x08)  ||                       /* EMR */
										 (readBuffer2[15] == 0x20)  ||                       /* BK */
										 (readBuffer2[15] == 0x28)) &&                       /* EMR + BK */
										(memcmp(readBuffer2 + 26, owner.c_str(), CALL_SIZE-1) == 0) &&         /* rpt2 must be us */
										(readBuffer2[33] == 'G')) {
									to_remote_g2[i].in_streamid[0] = readBuffer2[12];
									to_remote_g2[i].in_streamid[1] = readBuffer2[13];

									memcpy(xrf_2_dcs[i].mycall, readBuffer2 + 42, 8);
									memcpy(xrf_2_dcs[i].sfx, readBuffer2 + 50, 4);
									xrf_2_dcs[i].dcs_rptr_seq = 0;
								}
							}
						}
					}
				} else if (found) {
					if ((readBuffer2[14] & 0x40) != 0) {
						for (i = 0; i < 3; i++) {
							if (memcmp(old_sid[i].sid, readBuffer2 + 12, 2) == 0) {
								if (qso_details)
									traceit("END from remote g2: streamID=%d,%d, %d bytes from IP=%s\n",
											readBuffer2[12],readBuffer2[13],recvlen2,inet_ntoa(fromDst4.sin_addr));

								memset(old_sid[i].sid, 0x00, 2);

								break;
							}
						}
					}

					/* relay data to our local G2 */
					sendto(rptr_sock, readBuffer2, 27, 0, (struct sockaddr *)&toLocalg2, sizeof(struct sockaddr_in));

					/* send data to donglers */
					/* no changes here */
					for (pos = inbound_list.begin(); pos != inbound_list.end(); pos++) {
						inbound_ptr = (inbound *)pos->second;
						if (fromDst4.sin_addr.s_addr != inbound_ptr->sin.sin_addr.s_addr) {
							readBuffer[0] = (unsigned char)(29 & 0xFF);
							readBuffer[1] = (unsigned char)(29 >> 8 & 0x1F);
							readBuffer[1] = (unsigned char)(readBuffer[1] | 0xFFFFFF80);

							memcpy(readBuffer + 2, readBuffer2, 27);

							sendto(ref_g2_sock, readBuffer, 29, 0, (struct sockaddr *)&(inbound_ptr->sin), sizeof(struct sockaddr_in));
						}
					}

					/* do we have to broadcast ? */
					if (memcmp(brd_from_xrf.xrf_streamid, readBuffer2 + 12, 2) == 0) {
						memcpy(from_xrf_torptr_brd, readBuffer2, 27);

						if ((brd_from_xrf.rptr_streamid[0][0] != 0x00) ||
								(brd_from_xrf.rptr_streamid[0][1] != 0x00)) {
							from_xrf_torptr_brd[12] = brd_from_xrf.rptr_streamid[0][0];
							from_xrf_torptr_brd[13] = brd_from_xrf.rptr_streamid[0][1];
							sendto(rptr_sock, from_xrf_torptr_brd, 27, 0, (struct sockaddr *)&toLocalg2, sizeof(struct sockaddr_in));
						}

						if ((brd_from_xrf.rptr_streamid[1][0] != 0x00) ||
								(brd_from_xrf.rptr_streamid[1][1] != 0x00)) {
							from_xrf_torptr_brd[12] = brd_from_xrf.rptr_streamid[1][0];
							from_xrf_torptr_brd[13] = brd_from_xrf.rptr_streamid[1][1];
							sendto(rptr_sock, from_xrf_torptr_brd, 27, 0, (struct sockaddr *)&toLocalg2, sizeof(struct sockaddr_in));
						}

						if ((readBuffer2[14] & 0x40) != 0) {
							brd_from_xrf.xrf_streamid[0] = brd_from_xrf.xrf_streamid[1] = 0x00;
							brd_from_xrf.rptr_streamid[0][0] = brd_from_xrf.rptr_streamid[0][1] = 0x00;
							brd_from_xrf.rptr_streamid[1][0] = brd_from_xrf.rptr_streamid[1][1] = 0x00;
							brd_from_xrf_idx = 0;
						}
					}

					for (i = 0; i < 3; i++) {
						if ((to_remote_g2[i].is_connected) &&
								(to_remote_g2[i].toDst4.sin_addr.s_addr != fromDst4.sin_addr.s_addr) &&
								(memcmp(to_remote_g2[i].in_streamid, readBuffer2 + 12, 2) == 0)) {
							if (to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port)) {
								/* inform XRF about the source */
								readBuffer2[11] = to_remote_g2[i].from_mod;

								sendto(xrf_g2_sock, readBuffer2, 27, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));
							} else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_ref_port)) {
								readBuffer[0] = (unsigned char)(29 & 0xFF);
								readBuffer[1] = (unsigned char)(29 >> 8 & 0x1F);
								readBuffer[1] = (unsigned char)(readBuffer[1] | 0xFFFFFF80);

								memcpy(readBuffer + 2, readBuffer2, 27);

								sendto(ref_g2_sock, readBuffer, 29, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));
							} else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_dcs_port)) {
								memset(dcs_buf, 0x00, 600);
								dcs_buf[0] = dcs_buf[1] = dcs_buf[2] = '0';
								dcs_buf[3] = '1';
								dcs_buf[4] = dcs_buf[5] = dcs_buf[6] = 0x00;
								memcpy(dcs_buf + 7, to_remote_g2[i].to_call, 8);
								dcs_buf[14] = to_remote_g2[i].to_mod;
								memcpy(dcs_buf + 15, owner.c_str(), CALL_SIZE);
								dcs_buf[22] =  to_remote_g2[i].from_mod;
								memcpy(dcs_buf + 23, "CQCQCQ  ", 8);
								memcpy(dcs_buf + 31, xrf_2_dcs[i].mycall, 8);
								memcpy(dcs_buf + 39, xrf_2_dcs[i].sfx, 4);
								dcs_buf[43] = readBuffer2[12];  /* streamid0 */
								dcs_buf[44] = readBuffer2[13];  /* streamid1 */
								dcs_buf[45] = readBuffer2[14];  /* cycle sequence */
								memcpy(dcs_buf + 46, readBuffer2 + 15, 12);

								dcs_buf[58] = (xrf_2_dcs[i].dcs_rptr_seq >> 0)  & 0xff;
								dcs_buf[59] = (xrf_2_dcs[i].dcs_rptr_seq >> 8)  & 0xff;
								dcs_buf[60] = (xrf_2_dcs[i].dcs_rptr_seq >> 16) & 0xff;

								xrf_2_dcs[i].dcs_rptr_seq ++;

								dcs_buf[61] = 0x01;
								dcs_buf[62] = 0x00;

								sendto(dcs_g2_sock, dcs_buf, 100, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4),  sizeof(to_remote_g2[i].toDst4));
							}

							if ((readBuffer2[14] & 0x40) != 0) {
								to_remote_g2[i].in_streamid[0] = 0x00;
								to_remote_g2[i].in_streamid[1] = 0x00;
							}
							break;
						}
					}
				}
			}
			FD_CLR (xrf_g2_sock,&fdset);
		}

		if (FD_ISSET(ref_g2_sock, &fdset)) {
			fromlen = sizeof(struct sockaddr_in);
			recvlen2 = recvfrom(ref_g2_sock, (char *)readBuffer2, 100, 0, (struct sockaddr *)&fromDst4,&fromlen);

			strncpy(ip, inet_ntoa(fromDst4.sin_addr),IP_SIZE);
			ip[IP_SIZE] = '\0';

			found = false;

			/* LH */
			if ((recvlen2 == 4) &&
			        (readBuffer2[0] == 4) &&
			        (readBuffer2[1] == 192) &&
			        (readBuffer2[2] == 7) &&
			        (readBuffer2[3] == 0)) {
				unsigned short j_idx = 0;
				unsigned short k_idx = 0;
				unsigned char tmp[2];

				pos = inbound_list.find(ip);
				if (pos != inbound_list.end()) {
					inbound_ptr = (inbound *)pos->second;
					// traceit("Remote station %s %s requested LH list\n", inbound_ptr->call, ip);

					/* header is 10 bytes */

					/* reply type */
					readBuffer2[2] = 7;
					readBuffer2[3] = 0;

					/* it looks like time_t here */
					time(&tnow);
					memcpy((char *)readBuffer2 + 6, (char *)&tnow, sizeof(time_t));

					for (r_dt_lh_pos = dt_lh_list.rbegin(); r_dt_lh_pos != dt_lh_list.rend();  r_dt_lh_pos++) {
						/* each entry has 24 bytes */

						/* start at position 10 to bypass the header */
						strcpy((char *)readBuffer2 + 10 + (24 * j_idx), r_dt_lh_pos->second.c_str());
						p = strchr((char *)r_dt_lh_pos->first.c_str(), '=');
						if (p) {
							memcpy((char *)readBuffer2 + 18 + (24 * j_idx), p + 2, 8);

							/* if local or local w/gps */
							if ((p[1] == 'l') || (p[1] == 'g'))
								readBuffer2[18 + (24 * j_idx) + 6] = *(p + 1);

							*p = '\0';
							tnow = atol(r_dt_lh_pos->first.c_str());
							*p = '=';
							memcpy((char *)readBuffer2 + 26 + (24 * j_idx), &tnow, sizeof(time_t));
						} else {
							memcpy((char *)readBuffer2 + 18 + (24 * j_idx), "ERROR   ", 8);
							time(&tnow);
							memcpy((char *)readBuffer2 + 26 + (24 * j_idx), &tnow, sizeof(time_t));
						}

						readBuffer2[30 + (24 * j_idx)] = 0;
						readBuffer2[31 + (24 * j_idx)] = 0;
						readBuffer2[32 + (24 * j_idx)] = 0;
						readBuffer2[33 + (24 * j_idx)] = 0;

						j_idx++;

						/* process 39 entries at a time */
						if (j_idx == 39) {
							/* 39 * 24 = 936 + 10 header = 946 */
							readBuffer2[0] = 0xb2;
							readBuffer2[1] = 0xc3;

							/* 39 entries */
							readBuffer2[4] = 0x27;
							readBuffer2[5] = 0x00;

							sendto(ref_g2_sock, readBuffer2, 946, 0, (struct sockaddr *)&fromDst4, sizeof(struct sockaddr_in));

							j_idx = 0;
						}
					}

					if (j_idx != 0) {
						k_idx = 10 + (j_idx * 24);
						memcpy(tmp, (char *)&k_idx, 2);
						readBuffer2[0] = tmp[0];
						readBuffer2[1] = tmp[1] | 0xc0;

						memcpy(tmp, (char *)&j_idx, 2);
						readBuffer2[4] = tmp[0];
						readBuffer2[5] = tmp[1];

						sendto(ref_g2_sock, readBuffer2, k_idx, 0, (struct sockaddr *)&fromDst4, sizeof(struct sockaddr_in));
					}
				}
			/* linked repeaters request */
			} else if ((recvlen2 == 4) &&
					(readBuffer2[0] == 4) &&
					(readBuffer2[1] == 192) &&
					(readBuffer2[2] == 5) &&
					(readBuffer2[3] == 0)) {
				unsigned short i_idx = 0;
				unsigned short j_idx = 0;
				unsigned short k_idx = 0;
				unsigned char tmp[2];
				unsigned short total = 0;

				pos = inbound_list.find(ip);
				if (pos != inbound_list.end()) {
					inbound_ptr = (inbound *)pos->second;
					// traceit("Remote station %s %s requested linked repeaters list\n", inbound_ptr->call, ip);

					/* header is 8 bytes */

					/* reply type */
					readBuffer2[2] = 5;
					readBuffer2[3] = 1;

					/* we can have up to 3 linked systems */
					total = 3;
					memcpy(tmp, (char *)&total, 2);
					readBuffer2[6] = tmp[0];
					readBuffer2[7] = tmp[1];

					for (i = 0, i_idx = 0; i < 3;  i++, i_idx++) {
						/* each entry has 20 bytes */
						if (to_remote_g2[i].to_mod != ' ') {
							if (i == 0)
								readBuffer2[8 + (20 * j_idx)] = 'A';
							else if (i == 1)
								readBuffer2[8 + (20 * j_idx)] = 'B';
							else if (i == 2)
								readBuffer2[8 + (20 * j_idx)] = 'C';

							strcpy((char *)readBuffer2 + 9 + (20 * j_idx), to_remote_g2[i].to_call);
							readBuffer2[16 + (20 * j_idx)] = to_remote_g2[i].to_mod;

							readBuffer2[17 + (20 * j_idx)] = 0;
							readBuffer2[18 + (20 * j_idx)] = 0;
							readBuffer2[19 + (20 * j_idx)] = 0;
							readBuffer2[20 + (20 * j_idx)] = 0x50;
							readBuffer2[21 + (20 * j_idx)] = 0x04;
							readBuffer2[22 + (20 * j_idx)] = 0x32;
							readBuffer2[23 + (20 * j_idx)] = 0x4d;
							readBuffer2[24 + (20 * j_idx)] = 0x9f;
							readBuffer2[25 + (20 * j_idx)] = 0xdb;
							readBuffer2[26 + (20 * j_idx)] = 0x0e;
							readBuffer2[27 + (20 * j_idx)] = 0;

							j_idx++;

							if (j_idx == 39) {
								/* 20 bytes for each user, so 39 * 20 = 780 bytes + 8 bytes header = 788 */
								readBuffer2[0] = 0x14;
								readBuffer2[1] = 0xc3;

								k_idx = i_idx - 38;
								memcpy(tmp, (char *)&k_idx, 2);
								readBuffer2[4] = tmp[0];
								readBuffer2[5] = tmp[1];

								sendto(ref_g2_sock, readBuffer2,788,0, (struct sockaddr *)&fromDst4, sizeof(struct sockaddr_in));

								j_idx = 0;
							}
						}
					}

					if (j_idx != 0) {
						k_idx = 8 + (j_idx * 20);
						memcpy(tmp, (char *)&k_idx, 2);
						readBuffer2[0] = tmp[0];
						readBuffer2[1] = tmp[1] | 0xc0;

						if (i_idx > j_idx)
							k_idx = i_idx - j_idx;
						else
							k_idx = 0;

						memcpy(tmp, (char *)&k_idx, 2);
						readBuffer2[4] = tmp[0];
						readBuffer2[5] = tmp[1];

						sendto(ref_g2_sock, readBuffer2, 8+(j_idx*20), 0, (struct sockaddr *)&fromDst4, sizeof(struct sockaddr_in));
					}
				}
			/* connected user list request */
			} else if ((recvlen2 == 4) &&
					(readBuffer2[0] == 4) &&
					(readBuffer2[1] == 192) &&
					(readBuffer2[2] == 6) &&
					(readBuffer2[3] == 0)) {
				unsigned short i_idx = 0;
				unsigned short j_idx = 0;
				unsigned short k_idx = 0;
				unsigned char tmp[2];
				unsigned short total = 0;

				pos = inbound_list.find(ip);
				if (pos != inbound_list.end()) {
					inbound_ptr = (inbound *)pos->second;
					// traceit("Remote station %s %s requested connected user list\n", inbound_ptr->call, ip);

					/* header is 8 bytes */

					/* reply type */
					readBuffer2[2] = 6;
					readBuffer2[3] = 0;

					/* total connected users */
					total =  inbound_list.size();
					memcpy(tmp, (char *)&total, 2);
					readBuffer2[6] = tmp[0];
					readBuffer2[7] = tmp[1];

					for (pos = inbound_list.begin(), i_idx = 0; pos != inbound_list.end();  pos++, i_idx++) {
						/* each entry has 20 bytes */
						readBuffer2[8 + (20 * j_idx)] = ' ';
						inbound_ptr = (inbound *)pos->second;

						readBuffer2[8 + (20 * j_idx)] = inbound_ptr->mod;
						strcpy((char *)readBuffer2 + 9 + (20 * j_idx), inbound_ptr->call);

						readBuffer2[17 + (20 * j_idx)] = 0;
						/* readBuffer2[18 + (20 * j_idx)] = 0; */
						readBuffer2[18 + (20 * j_idx)] = inbound_ptr->client;
						readBuffer2[19 + (20 * j_idx)] = 0;
						readBuffer2[20 + (20 * j_idx)] = 0x0d;
						readBuffer2[21 + (20 * j_idx)] = 0x4d;
						readBuffer2[22 + (20 * j_idx)] = 0x37;
						readBuffer2[23 + (20 * j_idx)] = 0x4d;
						readBuffer2[24 + (20 * j_idx)] = 0x6f;
						readBuffer2[25 + (20 * j_idx)] = 0x98;
						readBuffer2[26 + (20 * j_idx)] = 0x04;
						readBuffer2[27 + (20 * j_idx)] = 0;

						j_idx++;

						if (j_idx == 39) {
							/* 20 bytes for each user, so 39 * 20 = 788 bytes + 8 bytes header = 788 */
							readBuffer2[0] = 0x14;
							readBuffer2[1] = 0xc3;

							k_idx = i_idx - 38;
							memcpy(tmp, (char *)&k_idx, 2);
							readBuffer2[4] = tmp[0];
							readBuffer2[5] = tmp[1];

							sendto(ref_g2_sock, readBuffer2, 788, 0, (struct sockaddr *)&fromDst4, sizeof(struct sockaddr_in));

							j_idx = 0;
						}
					}

					if (j_idx != 0) {
						k_idx = 8 + (j_idx * 20);
						memcpy(tmp, (char *)&k_idx, 2);
						readBuffer2[0] = tmp[0];
						readBuffer2[1] = tmp[1] | 0xc0;

						if (i_idx > j_idx)
							k_idx = i_idx - j_idx;
						else
							k_idx = 0;

						memcpy(tmp, (char *)&k_idx, 2);
						readBuffer2[4] = tmp[0];
						readBuffer2[5] = tmp[1];

						sendto(ref_g2_sock, readBuffer2, 8+(j_idx*20), 0, (struct sockaddr *)&fromDst4, sizeof(struct sockaddr_in));
					}
				}
			/* date request */
			} else if ((recvlen2 == 4) &&
					(readBuffer2[0] == 4) &&
					(readBuffer2[1] == 192) &&
					(readBuffer2[2] == 8) &&
					(readBuffer2[3] == 0)) {
				time_t ltime;
				struct tm tm;

				pos = inbound_list.find(ip);
				if (pos != inbound_list.end()) {
					inbound_ptr = (inbound *)pos->second;
					// traceit("Remote station %s %s requested date\n", inbound_ptr->call, ip);

					time(&ltime);
					localtime_r(&ltime,&tm);

					readBuffer2[0] = 34;
					readBuffer2[1] = 192;
					readBuffer2[2] = 8;
					readBuffer2[3] = 0;
					readBuffer2[4] = 0xb5;
					readBuffer2[5] = 0xae;
					readBuffer2[6] = 0x37;
					readBuffer2[7] = 0x4d;
					snprintf((char *)readBuffer2 + 8, 1024 - 1,
							 "20%02d/%02d/%02d %02d:%02d:%02d %5.5s",
							 tm.tm_year % 100, tm.tm_mon+1,tm.tm_mday,
							 tm.tm_hour,tm.tm_min,tm.tm_sec,
							 (tzname[0] == NULL)?"     ":tzname[0]);

					sendto(ref_g2_sock, readBuffer2, 34, 0, (struct sockaddr *)&fromDst4, sizeof(struct sockaddr_in));
				}
			/* version request */
			} else if ((recvlen2 == 4) &&
					(readBuffer2[0] == 4) &&
					(readBuffer2[1] == 192) &&
					(readBuffer2[2] == 3) &&
					(readBuffer2[3] == 0)) {
				pos = inbound_list.find(ip);
				if (pos != inbound_list.end()) {
					inbound_ptr = (inbound *)pos->second;
					// traceit("Remote station %s %s requested version\n", inbound_ptr->call, ip);

					readBuffer2[0] = 9;
					readBuffer2[1] = 192;
					readBuffer2[2] = 3;
					readBuffer2[3] = 0;
					strncpy((char *)readBuffer2 + 4, VERSION, 4);
					readBuffer2[8] = 0;

					sendto(ref_g2_sock, readBuffer2, 9, 0, (struct sockaddr *)&fromDst4, sizeof(struct sockaddr_in));
				}
			} else if ((recvlen2 == 5) &&
					   (readBuffer2[0] == 5) &&
					   (readBuffer2[1] == 0) &&
					   (readBuffer2[2] == 24) &&
					   (readBuffer2[3] == 0) &&
					   (readBuffer2[4] == 0)) {
				/* reply with the same DISCONNECT */
				sendto(ref_g2_sock, readBuffer2, 5, 0, (struct sockaddr *)&fromDst4, sizeof(struct sockaddr_in));

				for (i = 0; i < 3; i++) {
					if ((fromDst4.sin_addr.s_addr == to_remote_g2[i].toDst4.sin_addr.s_addr) &&
							(to_remote_g2[i].toDst4.sin_port == htons(rmt_ref_port))) {
						traceit("Call %s disconnected\n", to_remote_g2[i].to_call);

						to_remote_g2[i].to_call[0] = '\0';
						memset(&(to_remote_g2[i].toDst4),0,sizeof(struct sockaddr_in));
						to_remote_g2[i].from_mod = ' ';
						to_remote_g2[i].to_mod = ' ';
						to_remote_g2[i].countdown = 0;
						to_remote_g2[i].is_connected = false;
						to_remote_g2[i].in_streamid[0] = 0x00;
						to_remote_g2[i].in_streamid[1] = 0x00;
					}
				}

				pos = inbound_list.find(ip);
				if (pos != inbound_list.end()) {
					inbound_ptr = (inbound *)pos->second;
					if (memcmp(inbound_ptr->call, "1NFO", 4) != 0)
						traceit("Call %s disconnected\n", inbound_ptr->call);
					free(pos->second);
					pos->second = NULL;
					inbound_list.erase(pos);
				}
				print_status_file();
			}

			for (i = 0; i < 3; i++) {
				if ((fromDst4.sin_addr.s_addr == to_remote_g2[i].toDst4.sin_addr.s_addr) &&
				        (to_remote_g2[i].toDst4.sin_port == htons(rmt_ref_port))) {
					found = true;
					if ((recvlen2 == 5) &&
					        (readBuffer2[0] == 5) &&
					        (readBuffer2[1] == 0) &&
					        (readBuffer2[2] == 24) &&
					        (readBuffer2[3] == 0) &&
					        (readBuffer2[4] == 1)) {
						traceit("Connected to call %s\n", to_remote_g2[i].to_call);
						queryCommand[0] = 28;
						queryCommand[1] = 192;
						queryCommand[2] = 4;
						queryCommand[3] = 0;

						memcpy(queryCommand + 4, login_call.c_str(), CALL_SIZE);
						for (j = 11; j > 3; j--) {
							if (queryCommand[j] == ' ')
								queryCommand[j] = '\0';
							else
								break;
						}
						memset(queryCommand + 12, '\0', 8);
						memcpy(queryCommand + 20, "DV019999", 8);

						// ATTENTION: I should ONLY send once for each distinct
						// remote IP, so  get out of the loop immediately
						sendto(ref_g2_sock, queryCommand,28,0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));

						break;
					}
				}
			}

			for (i = 0; i < 3; i++) {
				if ((fromDst4.sin_addr.s_addr == to_remote_g2[i].toDst4.sin_addr.s_addr) &&
				        (to_remote_g2[i].toDst4.sin_port == htons(rmt_ref_port))) {
					found = true;
					if ((recvlen2 == 8) &&
					        (readBuffer2[0] == 8) &&
					        (readBuffer2[1] == 192) &&
					        (readBuffer2[2] == 4) &&
					        (readBuffer2[3] == 0)) {
						if ((readBuffer2[4] == 79) &&
						        (readBuffer2[5] == 75) &&
						        (readBuffer2[6] == 82)) {
							if (!to_remote_g2[i].is_connected) {
								to_remote_g2[i].is_connected = true;
								to_remote_g2[i].countdown = TIMEOUT;
								traceit("Login OK to call %s mod %c\n",
								        to_remote_g2[i].to_call, to_remote_g2[i].to_mod);
								print_status_file();

								tracing[i].last_time = time(NULL);

								strcpy(linked_remote_system, to_remote_g2[i].to_call);
								space_p = strchr(linked_remote_system, ' ');
								if (space_p)
									*space_p = '\0';
								sprintf(notify_msg, "%c_linked.dat_LINKED_%s_%c",
								        to_remote_g2[i].from_mod,
								        linked_remote_system,
								        to_remote_g2[i].to_mod);
								audio_notify(notify_msg);
							}
						} else if ((readBuffer2[4] == 70) &&
						           (readBuffer2[5] == 65) &&
						           (readBuffer2[6] == 73) &&
						           (readBuffer2[7] == 76)) {
							traceit("Login failed to call %s mod %c\n",
							        to_remote_g2[i].to_call, to_remote_g2[i].to_mod);

							sprintf(notify_msg, "%c_failed_linked.dat_FAILED_TO_LINK",
							        to_remote_g2[i].from_mod);
							audio_notify(notify_msg);

							to_remote_g2[i].to_call[0] = '\0';
							memset(&(to_remote_g2[i].toDst4),0,sizeof(struct sockaddr_in));
							to_remote_g2[i].from_mod = ' ';
							to_remote_g2[i].to_mod = ' ';
							to_remote_g2[i].countdown = 0;
							to_remote_g2[i].is_connected = false;
							to_remote_g2[i].in_streamid[0] = 0x00;
							to_remote_g2[i].in_streamid[1] = 0x00;
						} else if ((readBuffer2[4] == 66) &&
						           (readBuffer2[5] == 85) &&
						           (readBuffer2[6] == 83) &&
						           (readBuffer2[7] == 89)) {
							traceit("Busy or unknown status from call %s mod %c\n",
							        to_remote_g2[i].to_call, to_remote_g2[i].to_mod);

							sprintf(notify_msg, "%c_failed_linked.dat_FAILED_TO_LINK",
							        to_remote_g2[i].from_mod);
							audio_notify(notify_msg);

							to_remote_g2[i].to_call[0] = '\0';
							memset(&(to_remote_g2[i].toDst4),0,sizeof(struct sockaddr_in));
							to_remote_g2[i].from_mod = ' ';
							to_remote_g2[i].to_mod = ' ';
							to_remote_g2[i].countdown = 0;
							to_remote_g2[i].is_connected = false;
							to_remote_g2[i].in_streamid[0] = 0x00;
							to_remote_g2[i].in_streamid[1] = 0x00;
						}
					}
				}
			}

			for (i = 0; i < 3; i++) {
				if ((fromDst4.sin_addr.s_addr == to_remote_g2[i].toDst4.sin_addr.s_addr) &&
				        (to_remote_g2[i].toDst4.sin_port == htons(rmt_ref_port))) {
					found = true;
					if ((recvlen2 == 24) &&
					        (readBuffer2[0] == 24) &&
					        (readBuffer2[1] == 192) &&
					        (readBuffer2[2] == 3) &&
					        (readBuffer2[3] == 0)) {
						j = i;
						to_remote_g2[i].countdown = TIMEOUT;
					}
				}
			}

			for (i = 0; i < 3; i++) {
				if ((fromDst4.sin_addr.s_addr == to_remote_g2[i].toDst4.sin_addr.s_addr) &&
				        (to_remote_g2[i].toDst4.sin_port == htons(rmt_ref_port))) {
					found = true;
					if (recvlen2 == 3)
						to_remote_g2[i].countdown = TIMEOUT;
				}
			}

			/* find out if it is a connected dongle */
			pos = inbound_list.find(ip);
			if (pos != inbound_list.end()) {
				inbound_ptr = (inbound *)pos->second;
				found = true;
				inbound_ptr->countdown = TIMEOUT;
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
				if ((recvlen2 == 5) &&
				        (readBuffer2[0] == 5) &&
				        (readBuffer2[1] == 0) &&
				        (readBuffer2[2] == 24) &&
				        (readBuffer2[3] == 0) &&
				        (readBuffer2[4] == 1)) {
					if ((inbound_list.size() + 1) > max_dongles)
						traceit("Inbound DONGLE-p connection from %s but over the max_dongles limit of %d\n", ip, inbound_list.size());
					else
						sendto(ref_g2_sock, readBuffer2, 5, 0, (struct sockaddr *)&fromDst4, sizeof(fromDst4));
				} else if ((recvlen2 == 28) &&
				           (readBuffer2[0] == 28) &&
				           (readBuffer2[1] == 192) &&
				           (readBuffer2[2] == 4) &&
				           (readBuffer2[3] == 0)) {
					/* verify callsign */
					memcpy(call, readBuffer2 + 4, CALL_SIZE);
					call[CALL_SIZE] = '\0';
					for (i = 7; i > 0; i--) {
						if (call[i] == '\0')
							call[i] = ' ';
						else
							break;
					}

					if (memcmp(call, "1NFO", 4) != 0)
						traceit("Inbound DONGLE-p CALL=%s, ip=%s, DV=%.8s\n",
						        call, ip, readBuffer2 + 20);

					if ((inbound_list.size() + 1) > max_dongles)
						traceit("Inbound DONGLE-p connection from %s but over the max_dongles limit of %d\n",
						        ip, inbound_list.size());
					else if (only_admin_login && (admin.find(call) == admin.end()))
						traceit("Incoming call [%s] from %s not an ADMIN\n", call, ip);
					else if (regexec(&preg, call, 0, NULL, 0) != 0) {
						traceit("Invalid dongle callsign: CALL=%s,ip=%s\n", call, ip);

						readBuffer2[0] = 8;
						readBuffer2[4] = 70;
						readBuffer2[5] = 65;
						readBuffer2[6] = 73;
						readBuffer2[7] = 76;

						sendto(ref_g2_sock, readBuffer2, 8, 0, (struct sockaddr *)&fromDst4, sizeof(fromDst4));
					} else {
						/* add the dongle to the inbound list */
						inbound_ptr = (inbound *)malloc(sizeof(inbound));
						if (inbound_ptr) {
							inbound_ptr->countdown = TIMEOUT;
							memcpy((char *)&(inbound_ptr->sin),(char *)&fromDst4, sizeof(struct sockaddr_in));
							strcpy(inbound_ptr->call, call);

							inbound_ptr->mod = ' ';

							if (memcmp(readBuffer2 + 20, "AP", 2) == 0)
								inbound_ptr->client = 'A';  /* dvap */
							else if (memcmp(readBuffer2 + 20, "DV019999", 8) == 0)
								inbound_ptr->client = 'H';  /* spot */
							else
								inbound_ptr->client = 'D';  /* dongle */

							insert_pair = inbound_list.insert(std::pair<std::string, inbound *>(ip, inbound_ptr));
							if (insert_pair.second) {
								if (memcmp(inbound_ptr->call, "1NFO", 4) != 0)
									traceit("new CALL=%s, DONGLE-p, ip=%s, users=%d\n",
									        inbound_ptr->call,ip,inbound_list.size());

								readBuffer2[0] = 8;
								readBuffer2[4] = 79;
								readBuffer2[5] = 75;
								readBuffer2[6] = 82;
								readBuffer2[7] = 87;

								sendto(ref_g2_sock, readBuffer2, 8, 0, (struct sockaddr *)&fromDst4, sizeof(fromDst4));

								print_status_file();

							} else {
								traceit("failed to add CALL=%s,ip=%s\n",inbound_ptr->call,ip);
								free(inbound_ptr);
								inbound_ptr = NULL;

								readBuffer2[0] = 8;
								readBuffer2[4] = 70;
								readBuffer2[5] = 65;
								readBuffer2[6] = 73;
								readBuffer2[7] = 76;

								sendto(ref_g2_sock, readBuffer2, 8, 0, (struct sockaddr *)&fromDst4, sizeof(fromDst4));
							}
						} else {
							traceit("malloc() failed for call=%s,ip=%s\n",call,ip);

							readBuffer2[0] = 8;
							readBuffer2[4] = 70;
							readBuffer2[5] = 65;
							readBuffer2[6] = 73;
							readBuffer2[7] = 76;

							sendto(ref_g2_sock, readBuffer2, 8, 0, (struct sockaddr *)&fromDst4, sizeof(fromDst4));
						}
					}
				}
			}

			if ( ((recvlen2 == 58) ||
			        (recvlen2 == 29) ||
			        (recvlen2 == 32)) &&
			        (memcmp(readBuffer2 + 2, "DSVT", 4) == 0) &&
			        ((readBuffer2[6] == 0x10) ||
			         (readBuffer2[6] == 0x20)) &&
			        (readBuffer2[10] == 0x20)) {
				/* Is it one of the donglers or repeaters-reflectors */
				found = false;
				for (i = 0; i < 3; i++) {
					if ((fromDst4.sin_addr.s_addr == to_remote_g2[i].toDst4.sin_addr.s_addr) &&
					        (to_remote_g2[i].toDst4.sin_port == htons(rmt_ref_port))) {
						to_remote_g2[i].countdown = TIMEOUT;
						found = true;
					}
				}
				if (!found) {
					pos = inbound_list.find(ip);
					if (pos != inbound_list.end()) {
						inbound_ptr = (inbound *)pos->second;
						inbound_ptr->countdown = TIMEOUT;
						found = true;
					}
				}

				if ((recvlen2 == 58) && found) {
					memset(source_stn, ' ', 9);
					source_stn[8] = '\0';

					/* some bad hotspot programs out there using INCORRECT flag */
					if (readBuffer2[17] == 0x40)
						readBuffer2[17] = 0x00;
					else if (readBuffer2[17] == 0x48)
						readBuffer2[17] = 0x08;
					else if (readBuffer2[17] == 0x60)
						readBuffer2[17] = 0x20;
					else if (readBuffer2[17] == 0x68)
						readBuffer2[17] = 0x28;

					/* A reflector will send to us its own RPT1 */
					/* A repeater will send to us its own RPT1 */
					/* A dongleR will send to us our RPT1 */

					/* It is from a repeater-reflector, correct rpt1, rpt2 and re-compute pfcs */
					for (i = 0; i < 3; i++) {
						if ((fromDst4.sin_addr.s_addr == to_remote_g2[i].toDst4.sin_addr.s_addr) &&
						        (to_remote_g2[i].toDst4.sin_port == htons(rmt_ref_port)) &&
						        (
						            ((memcmp(readBuffer2 + 20, to_remote_g2[i].to_call, 7) == 0) &&
						             (readBuffer2[27] == to_remote_g2[i].to_mod))  ||
						            ((memcmp(readBuffer2 + 28, to_remote_g2[i].to_call, 7) == 0) &&
						             (readBuffer2[35] == to_remote_g2[i].to_mod))
						        )) {
							memcpy(&readBuffer2[20], owner.c_str(), CALL_SIZE);
							readBuffer2[27] = to_remote_g2[i].from_mod;
							memcpy(&readBuffer2[36], "CQCQCQ  ", 8);

							memcpy(source_stn, to_remote_g2[i].to_call, 8);
							source_stn[7] = to_remote_g2[i].to_mod;

							break;
						}
					}

					if (i == 3) {
						pos = inbound_list.find(ip);
						if (pos != inbound_list.end()) {
							inbound_ptr = (inbound *)pos->second;
							memcpy(source_stn, inbound_ptr->call, 8);
						}
					}

					/* somebody's crazy idea of having a personal callsign in RPT2 */
					/* we must set it to our gateway callsign */
					memcpy(&readBuffer2[28], owner.c_str(), CALL_SIZE);
					readBuffer2[35] = 'G';
					calcPFCS(readBuffer2 + 2,56);

					/* At this point, all data have our RPT1 and RPT2 */

					i = -1;
					if (readBuffer2[27] == 'A')
						i = 0;
					else if (readBuffer2[27] == 'B')
						i = 1;
					else if (readBuffer2[27] == 'C')
						i = 2;

					/* are we sure that RPT1 is our system? */
					if ((memcmp(readBuffer2 + 20, owner.c_str(), CALL_SIZE-1) == 0) && (i >= 0)) {
						/* Last Heard */
						if (memcmp(old_sid[i].sid, readBuffer2 + 14, 2) != 0) {
							if (qso_details)
								traceit("START from remote g2: streamID=%d,%d, flags=%02x:%02x:%02x, my=%.8s, sfx=%.4s, ur=%.8s, rpt1=%.8s, rpt2=%.8s, %d bytes fromIP=%s, source=%.8s\n",
								        readBuffer2[14],readBuffer2[15],
								        readBuffer2[17], readBuffer2[18], readBuffer2[19],
								        &readBuffer2[44],
								        &readBuffer2[52], &readBuffer2[36],
								        &readBuffer2[20], &readBuffer2[28],
								        recvlen2, inet_ntoa(fromDst4.sin_addr), source_stn);

							// put user into tmp1
							memcpy(tmp1, readBuffer2 + 44, 8);
							tmp1[8] = '\0';

							// delete the user if exists
							for (dt_lh_pos = dt_lh_list.begin(); dt_lh_pos != dt_lh_list.end();  dt_lh_pos++) {
								if (strcmp((char *)dt_lh_pos->second.c_str(), tmp1) == 0) {
									dt_lh_list.erase(dt_lh_pos);
									break;
								}
							}
							/* Limit?, delete oldest user */
							if (dt_lh_list.size() == LH_MAX_SIZE) {
								dt_lh_pos = dt_lh_list.begin();
								dt_lh_list.erase(dt_lh_pos);
							}
							// add user
							time(&tnow);
							sprintf(tmp2, "%ld=r%.6s%c%c", tnow, source_stn, source_stn[7], readBuffer2[27]);
							dt_lh_list[tmp2] = tmp1;

							memcpy(old_sid[i].sid, readBuffer2 + 14, 2);
						}

						/* send the data to the local gateway/repeater */
						sendto(rptr_sock, readBuffer2+2, 56, 0, (struct sockaddr *)&toLocalg2, sizeof(struct sockaddr_in));

						/* send the data to the donglers */
						for (pos = inbound_list.begin(); pos != inbound_list.end(); pos++) {
							inbound_ptr = (inbound *)pos->second;
							if (fromDst4.sin_addr.s_addr != inbound_ptr->sin.sin_addr.s_addr) {
								sendto(ref_g2_sock, readBuffer2, 58, 0, (struct sockaddr *)&(inbound_ptr->sin), sizeof(struct sockaddr_in));
							} else
								inbound_ptr->mod = readBuffer2[27];
						}

						if ((to_remote_g2[i].toDst4.sin_addr.s_addr != fromDst4.sin_addr.s_addr) &&
						        to_remote_g2[i].is_connected) {
							if ( /*** (memcmp(readBuffer2 + 44, owner, 8) != 0) && ***/         /* block repeater announcements */
							    (memcmp(readBuffer2 + 36, "CQCQCQ", 6) == 0) &&     /* CQ calls only */
							    ((readBuffer2[17] == 0x00)  ||                       /* normal */
							     (readBuffer2[17] == 0x08)  ||                       /* EMR */
							     (readBuffer2[17] == 0x20)  ||                       /* BK */
							     (readBuffer2[17] == 0x28)) &&                       /* EMR + BK */
							    (memcmp(readBuffer2 + 28, owner.c_str(), CALL_SIZE-1) == 0) &&         /* rpt2 must be us */
							    (readBuffer2[35] == 'G')) {
								to_remote_g2[i].in_streamid[0] = readBuffer2[14];
								to_remote_g2[i].in_streamid[1] = readBuffer2[15];

								if ((to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port)) ||
								        (to_remote_g2[i].toDst4.sin_port ==  htons(rmt_ref_port))) {
									memcpy((char *)readBuffer2 + 20, to_remote_g2[i].to_call, CALL_SIZE);
									readBuffer2[27] = to_remote_g2[i].to_mod;
									memcpy((char *)readBuffer2 + 28, to_remote_g2[i].to_call, CALL_SIZE);
									readBuffer2[35] = 'G';
									calcPFCS(readBuffer2 + 2, 56);

									if (to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port)) {
										/* inform XRF about the source */
										readBuffer2[13] = to_remote_g2[i].from_mod;

										sendto(xrf_g2_sock, readBuffer2 + 2, 56, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));
									} else
										sendto(ref_g2_sock, readBuffer2, 58, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));
								} else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_dcs_port)) {
									memcpy(ref_2_dcs[i].mycall, readBuffer2 + 44, 8);
									memcpy(ref_2_dcs[i].sfx, readBuffer2 + 52, 4);
									ref_2_dcs[i].dcs_rptr_seq = 0;
								}
							}
						}
					}
				} else if (found) {
					if ((readBuffer2[16] & 0x40) != 0) {
						for (i = 0; i < 3; i++) {
							if (memcmp(old_sid[i].sid, readBuffer2 + 14, 2) == 0) {
								if (qso_details)
									traceit("END from remote g2: streamID=%d,%d, %d bytes from IP=%s\n",
									        readBuffer2[14],readBuffer2[15],recvlen2,inet_ntoa(fromDst4.sin_addr));

								memset(old_sid[i].sid, 0x00, 2);

								break;
							}
						}
					}

					/* send the data to the local gateway/repeater */
					sendto(rptr_sock, readBuffer2+2, 27, 0, (struct sockaddr *)&toLocalg2, sizeof(struct sockaddr_in));

					/* send the data to the donglers */
					for (pos = inbound_list.begin(); pos != inbound_list.end(); pos++) {
						inbound_ptr = (inbound *)pos->second;
						if (fromDst4.sin_addr.s_addr != inbound_ptr->sin.sin_addr.s_addr) {
							sendto(ref_g2_sock, readBuffer2, 29, 0, (struct sockaddr *)&(inbound_ptr->sin), sizeof(struct sockaddr_in));
						}
					}

					for (i = 0; i < 3; i++) {
						if ((to_remote_g2[i].is_connected) &&
						        (to_remote_g2[i].toDst4.sin_addr.s_addr != fromDst4.sin_addr.s_addr) &&
						        (memcmp(to_remote_g2[i].in_streamid, readBuffer2 + 14, 2) == 0)) {
							if (to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port)) {
								/* inform XRF about the source */
								readBuffer2[13] = to_remote_g2[i].from_mod;

								sendto(xrf_g2_sock, readBuffer2+2, 27, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));
							} else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_ref_port))
								sendto(ref_g2_sock, readBuffer2, 29,  0,(struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));
							else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_dcs_port)) {
								memset(dcs_buf, 0x00, 600);
								dcs_buf[0] = dcs_buf[1] = dcs_buf[2] = '0';
								dcs_buf[3] = '1';
								dcs_buf[4] = dcs_buf[5] = dcs_buf[6] = 0x00;
								memcpy(dcs_buf + 7, to_remote_g2[i].to_call, 8);
								dcs_buf[14] = to_remote_g2[i].to_mod;
								memcpy(dcs_buf + 15, owner.c_str(), CALL_SIZE);
								dcs_buf[22] = to_remote_g2[i].from_mod;
								memcpy(dcs_buf + 23, "CQCQCQ  ", 8);
								memcpy(dcs_buf + 31, ref_2_dcs[i].mycall, 8);
								memcpy(dcs_buf + 39, ref_2_dcs[i].sfx, 4);
								dcs_buf[43] = readBuffer2[14];  /* streamid0 */
								dcs_buf[44] = readBuffer2[15];  /* streamid1 */
								dcs_buf[45] = readBuffer2[16];  /* cycle sequence */
								memcpy(dcs_buf + 46, readBuffer2 + 17, 12);

								dcs_buf[58] = (ref_2_dcs[i].dcs_rptr_seq >> 0)  & 0xff;
								dcs_buf[59] = (ref_2_dcs[i].dcs_rptr_seq >> 8)  & 0xff;
								dcs_buf[60] = (ref_2_dcs[i].dcs_rptr_seq >> 16) & 0xff;

								ref_2_dcs[i].dcs_rptr_seq ++;

								dcs_buf[61] = 0x01;
								dcs_buf[62] = 0x00;

								sendto(dcs_g2_sock, dcs_buf, 100, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));
							}

							if ((readBuffer2[16] & 0x40) != 0) {
								to_remote_g2[i].in_streamid[0] = 0x00;
								to_remote_g2[i].in_streamid[1] = 0x00;
							}
							break;
						}
					}
				}
			}
			FD_CLR (ref_g2_sock,&fdset);
		}

		if (FD_ISSET(dcs_g2_sock, &fdset)) {
			fromlen = sizeof(struct sockaddr_in);
			recvlen2 = recvfrom(dcs_g2_sock,(char *)dcs_buf,1000,
			                    0,(struct sockaddr *)&fromDst4,&fromlen);

			strncpy(ip, inet_ntoa(fromDst4.sin_addr),IP_SIZE);
			ip[IP_SIZE] = '\0';

			/* header, audio */
			if ((dcs_buf[0] == '0') && (dcs_buf[1] == '0') &&
			        (dcs_buf[2] == '0') && (dcs_buf[3] == '1')) {
				if (recvlen2 == 100) {
					memset(source_stn, ' ', 9);
					source_stn[8] = '\0';

					/* find out our local module */
					for (i = 0; i < 3; i++) {
						if ((to_remote_g2[i].is_connected) &&
						        (fromDst4.sin_addr.s_addr = to_remote_g2[i].toDst4.sin_addr.s_addr) &&
						        (memcmp(dcs_buf + 7, to_remote_g2[i].to_call, 7) == 0) &&
						        (to_remote_g2[i].to_mod == dcs_buf[14])) {
							memcpy(source_stn, to_remote_g2[i].to_call, 8);
							source_stn[7] = to_remote_g2[i].to_mod;
							break;
						}
					}

					/* Is it our local module */
					if (i < 3) {
						/* Last Heard */
						if (memcmp(old_sid[i].sid, dcs_buf + 43, 2) != 0) {
							if (qso_details)
								traceit("START from dcs: streamID=%d,%d, my=%.8s, sfx=%.4s, ur=%.8s, rpt1=%.8s, rpt2=%.8s, %d bytes fromIP=%s, source=%.8s\n",
								        dcs_buf[43],dcs_buf[44],
								        &dcs_buf[31],
								        &dcs_buf[39], &dcs_buf[23],
								        &dcs_buf[7], &dcs_buf[15],
								        recvlen2,inet_ntoa(fromDst4.sin_addr), source_stn);

							// put user into tmp1
							memcpy(tmp1, dcs_buf + 31, 8);
							tmp1[8] = '\0';

							// delete the user if exists
							for (dt_lh_pos = dt_lh_list.begin(); dt_lh_pos != dt_lh_list.end();  dt_lh_pos++) {
								if (strcmp((char *)dt_lh_pos->second.c_str(), tmp1) == 0) {
									dt_lh_list.erase(dt_lh_pos);
									break;
								}
							}
							/* Limit?, delete oldest user */
							if (dt_lh_list.size() == LH_MAX_SIZE) {
								dt_lh_pos = dt_lh_list.begin();
								dt_lh_list.erase(dt_lh_pos);
							}
							// add user
							time(&tnow);
							sprintf(tmp2, "%ld=r%.6s%c%c", tnow, source_stn, source_stn[7], to_remote_g2[i].from_mod);
							dt_lh_list[tmp2] = tmp1;

							memcpy(old_sid[i].sid, dcs_buf + 43, 2);
						}

						to_remote_g2[i].countdown = TIMEOUT;

						/* new stream ? */
						if ((to_remote_g2[i].in_streamid[0] != dcs_buf[43]) ||
						        (to_remote_g2[i].in_streamid[1] != dcs_buf[44])) {
							to_remote_g2[i].in_streamid[0] = dcs_buf[43];
							to_remote_g2[i].in_streamid[1] = dcs_buf[44];
							dcs_seq[i] = 0xff;

							/* generate our header */

							readBuffer2[0] = (unsigned char)(58 & 0xFF);
							readBuffer2[1] = (unsigned char)(58 >> 8 & 0x1F);
							readBuffer2[1] = (unsigned char)(readBuffer2[1] | 0xFFFFFF80);
							memcpy(readBuffer2 + 2, "DSVT", 4);
							readBuffer2[6] = 0x10;
							readBuffer2[7] = 0x00;
							readBuffer2[8] = 0x00;
							readBuffer2[9] = 0x00;
							readBuffer2[10] = 0x20;
							readBuffer2[11] = 0x00;
							readBuffer2[12] = 0x01;
							if (to_remote_g2[i].from_mod == 'A')
								readBuffer2[13] = 0x03;
							else if (to_remote_g2[i].from_mod == 'B')
								readBuffer2[13] = 0x01;
							else
								readBuffer2[13] = 0x02;
							readBuffer2[14] = dcs_buf[43];
							readBuffer2[15] = dcs_buf[44];
							readBuffer2[16] = 0x80;
							readBuffer2[17] = readBuffer2[18] = readBuffer2[19] = 0x00;
							memcpy(readBuffer2 + 20, owner.c_str(), CALL_SIZE);
							readBuffer2[27] = to_remote_g2[i].from_mod;
							memcpy(readBuffer2 + 28, owner.c_str(), CALL_SIZE);
							readBuffer2[35] = 'G';
							memcpy(readBuffer2 + 36, "CQCQCQ  ", 8);
							memcpy(readBuffer2 + 44, dcs_buf + 31, 8);
							memcpy(readBuffer2 + 52, dcs_buf + 39, 4);
							calcPFCS(readBuffer2 + 2, 56);

							/* send the header to the local gateway/repeater */
							for (j = 0; j < 5; j++)
								sendto(rptr_sock, readBuffer2+2, 56, 0, (struct sockaddr *)&toLocalg2,sizeof(struct sockaddr_in));

							/* send the data to the donglers */
							for (pos = inbound_list.begin(); pos != inbound_list.end(); pos++) {
								inbound_ptr = (inbound *)pos->second;
								for (j=0; j<5; j++)
									sendto(ref_g2_sock, readBuffer2, 58, 0, (struct sockaddr *)&(inbound_ptr->sin), sizeof(struct sockaddr_in));
							}
						}

						if ((to_remote_g2[i].in_streamid[0] == dcs_buf[43]) &&
						        (to_remote_g2[i].in_streamid[1] == dcs_buf[44]) &&
						        (dcs_seq[i] != dcs_buf[45])) {
							dcs_seq[i] = dcs_buf[45];

							readBuffer2[0] = (unsigned char)(29 & 0xFF);
							readBuffer2[1] = (unsigned char)(29 >> 8 & 0x1F);
							readBuffer2[1] = (unsigned char)(readBuffer2[1] | 0xFFFFFF80);
							memcpy(readBuffer2 + 2, "DSVT", 4);
							readBuffer2[6] = 0x20;
							readBuffer2[7] = 0x00;
							readBuffer2[8] = 0x00;
							readBuffer2[9] = 0x00;
							readBuffer2[10] = 0x20;
							readBuffer2[11] = 0x00;
							readBuffer2[12] = 0x01;
							if (to_remote_g2[i].from_mod == 'A')
								readBuffer2[13] = 0x03;
							else if (to_remote_g2[i].from_mod == 'B')
								readBuffer2[13] = 0x01;
							else
								readBuffer2[13] = 0x02;
							readBuffer2[14] = dcs_buf[43];
							readBuffer2[15] = dcs_buf[44];
							readBuffer2[16] = dcs_buf[45];
							memcpy(readBuffer2 + 17, dcs_buf + 46, 12);

							/* send the data to the local gateway/repeater */
							sendto(rptr_sock, readBuffer2+2, 27, 0, (struct sockaddr *)&toLocalg2,sizeof(struct sockaddr_in));

							/* send the data to the donglers */
							for (pos = inbound_list.begin(); pos != inbound_list.end(); pos++) {
								inbound_ptr = (inbound *)pos->second;
								sendto(ref_g2_sock, readBuffer2, 29, 0, (struct sockaddr *)&(inbound_ptr->sin), sizeof(struct sockaddr_in));
							}

							if ((dcs_buf[45] & 0x40) != 0) {
								memset(old_sid[i].sid, 0x00, 2);

								if (qso_details)
									traceit("END from dcs: streamID=%d,%d, %d bytes from IP=%s\n",
									        dcs_buf[43],dcs_buf[44], recvlen2,inet_ntoa(fromDst4.sin_addr));

								to_remote_g2[i].in_streamid[0] = 0x00;
								to_remote_g2[i].in_streamid[1] = 0x00;
								dcs_seq[i] = 0xff;
							}
						}
					}
				}
			} else if ((dcs_buf[0] == 'E') && (dcs_buf[1] == 'E') &&
			           (dcs_buf[2] == 'E') && (dcs_buf[3] == 'E'))
				;
			else if (recvlen2 == 35)
				;
			/* is this a keepalive 22 bytes */
			else if (recvlen2 == 22) {
				i = -1;
				if (dcs_buf[17] == 'A')
					i = 0;
				else if (dcs_buf[17] == 'B')
					i = 1;
				else if (dcs_buf[17] == 'C')
					i = 2;

				/* It is one of our valid repeaters */
				// DG1HT from owner 8 to 7
				if ((i >= 0) && (memcmp(dcs_buf + 9, owner.c_str(), CALL_SIZE-1) == 0)) {
					/* is that the remote system that we asked to connect to? */
					if ((fromDst4.sin_addr.s_addr == to_remote_g2[i].toDst4.sin_addr.s_addr) &&
							(to_remote_g2[i].toDst4.sin_port == htons(rmt_dcs_port)) &&
							(memcmp(to_remote_g2[i].to_call, dcs_buf, 7) == 0) &&
							(to_remote_g2[i].to_mod == dcs_buf[7])) {
						if (!to_remote_g2[i].is_connected) {
							tracing[i].last_time = time(NULL);

							to_remote_g2[i].is_connected = true;
							traceit("Connected from: %.*s\n", 8, dcs_buf);
							print_status_file();

							strcpy(linked_remote_system, to_remote_g2[i].to_call);
							space_p = strchr(linked_remote_system, ' ');
							if (space_p)
								*space_p = '\0';
							sprintf(notify_msg, "%c_linked.dat_LINKED_%s_%c",
									to_remote_g2[i].from_mod,
									linked_remote_system,
									to_remote_g2[i].to_mod);
							audio_notify(notify_msg);
						}
						to_remote_g2[i].countdown = TIMEOUT;
					}
				}
			} else if (recvlen2 == 14) {	/* is this a reply to our link/unlink request: 14 bytes */
				i = -1;
				if (dcs_buf[8] == 'A')
					i = 0;
				else if (dcs_buf[8] == 'B')
					i = 1;
				else if (dcs_buf[8] == 'C')
					i = 2;

				/* It is one of our valid repeaters */
				if ((i >= 0) && (memcmp(dcs_buf, owner.c_str(), CALL_SIZE) == 0)) {
					/* It is from a remote that we contacted */
					if ((fromDst4.sin_addr.s_addr == to_remote_g2[i].toDst4.sin_addr.s_addr) &&
							(to_remote_g2[i].toDst4.sin_port == htons(rmt_dcs_port)) &&
							(to_remote_g2[i].from_mod == dcs_buf[8])) {
						if ((to_remote_g2[i].to_mod == dcs_buf[9]) &&
								(memcmp(dcs_buf + 10, "ACK", 3) == 0)) {
							to_remote_g2[i].countdown = TIMEOUT;
							if (!to_remote_g2[i].is_connected) {
								tracing[i].last_time = time(NULL);

								to_remote_g2[i].is_connected = true;
								traceit("Connected from: %.*s\n", 8, to_remote_g2[i].to_call);
								print_status_file();

								strcpy(linked_remote_system, to_remote_g2[i].to_call);
								space_p = strchr(linked_remote_system, ' ');
								if (space_p)
									*space_p = '\0';
								sprintf(notify_msg, "%c_linked.dat_LINKED_%s_%c",
										to_remote_g2[i].from_mod,
										linked_remote_system,
										to_remote_g2[i].to_mod);
								audio_notify(notify_msg);
							}
						} else if (memcmp(dcs_buf + 10, "NAK", 3) == 0) {
							traceit("Link module %c to [%s] %c is unlinked\n",
									to_remote_g2[i].from_mod, to_remote_g2[i].to_call,
									to_remote_g2[i].to_mod);

							sprintf(notify_msg, "%c_failed_linked.dat_UNLINKED",
									to_remote_g2[i].from_mod);
							audio_notify(notify_msg);

							to_remote_g2[i].to_call[0] = '\0';
							memset(&(to_remote_g2[i].toDst4),0,sizeof(struct sockaddr_in));
							to_remote_g2[i].from_mod = ' ';
							to_remote_g2[i].to_mod = ' ';
							to_remote_g2[i].countdown = 0;
							to_remote_g2[i].is_connected = false;
							to_remote_g2[i].in_streamid[0] = 0x00;
							to_remote_g2[i].in_streamid[1] = 0x00;

							print_status_file();
						}
					}
				}
			}
			FD_CLR (dcs_g2_sock,&fdset);
		}

		if (FD_ISSET(rptr_sock, &fdset)) {
			fromlen = sizeof(struct sockaddr_in);
			recvlen = recvfrom(rptr_sock, (char *)readBuffer, 100, 0, (struct sockaddr *)&fromRptr,&fromlen);

			if ( ((recvlen == 58) || (recvlen == 29) || (recvlen == 32)) &&
			        (readBuffer[6] == 0x73) &&
			        (readBuffer[7] == 0x12) &&
			        ((memcmp(readBuffer,"DSTR", 4) == 0) || (memcmp(readBuffer,"CCS_", 4) == 0)) &&
			        (readBuffer[10] == 0x20) &&
			        (readBuffer[8] == 0x00) &&
			        ((readBuffer[9] == 0x30) || (readBuffer[9] == 0x13) || (readBuffer[9] == 0x16)) ) {

				if (recvlen == 58) {
					if (qso_details)
						traceit("START from local g2: cntr=%02x %02x, streamID=%d,%d, flags=%02x:%02x:%02x, my=%.8s, sfx=%.4s, ur=%.8s, rpt1=%.8s, rpt2=%.8s, %d bytes fromIP=%s\n",
						        readBuffer[4], readBuffer[5],
						        readBuffer[14], readBuffer[15],
						        readBuffer[17], readBuffer[18], readBuffer[19],
						        readBuffer + 44, readBuffer + 52, readBuffer + 36,
						        readBuffer + 28, readBuffer + 20, recvlen, inet_ntoa(fromRptr.sin_addr));

					/* save mycall */
					memcpy(call, readBuffer + 44, 8);
					call[8] = '\0';

					i = -1;
					if (readBuffer[35] == 'A')
						i = 0;
					else if (readBuffer[35] == 'B')
						i = 1;
					else if (readBuffer[35] == 'C')
						i = 2;

					if (i >= 0) {
						memcpy(dtmf_mycall[i], readBuffer + 44, 8);
						dtmf_mycall[i][8] = '\0';

						new_group[i] = true;
						GPS_seen[i] = false;

						/* Last Heard */

						//put user into tmp1
						memcpy(tmp1, readBuffer + 44, 8);
						tmp1[8] = '\0';

						// delete the user if exists
						for (dt_lh_pos = dt_lh_list.begin(); dt_lh_pos != dt_lh_list.end();  dt_lh_pos++) {
							if (strcmp((char *)dt_lh_pos->second.c_str(), tmp1) == 0) {
								dt_lh_list.erase(dt_lh_pos);
								break;
							}
						}
						/* Limit?, delete oldest user */
						if (dt_lh_list.size() == LH_MAX_SIZE) {
							dt_lh_pos = dt_lh_list.begin();
							dt_lh_list.erase(dt_lh_pos);
						}
						/* add user */
						time(&tnow);
						if (memcmp(readBuffer,"CCS_", 4) == 0)
							sprintf(tmp2, "%ld=r%.7s%c", tnow, "-->CCS ", readBuffer[35]);
						else
							sprintf(tmp2, "%ld=l%.8s", tnow, readBuffer + 28);
						dt_lh_list[tmp2] = tmp1;

						memcpy(readBuffer, "DSTR", 4);

						tracing[i].streamid[0] = readBuffer[14];
						tracing[i].streamid[1] = readBuffer[15];
						tracing[i].last_time = time(NULL);
					}

					if ((memcmp(readBuffer + 36, "CQCQCQ", 6) != 0) && (i >= 0)) {
						if ((memcmp(readBuffer + 36, owner.c_str(), CALL_SIZE-1) != 0) &&
						        (readBuffer[43] == LINK_CODE) &&
						        (memcmp(readBuffer + 20, owner.c_str(), CALL_SIZE-1) == 0) &&
						        (readBuffer[27] == 'G') &&
						        ((readBuffer[17] == 0x00) ||
						         (readBuffer[17] == 0x08) ||
						         (readBuffer[17] == 0x20) ||
						         (readBuffer[17] == 0x28))) {
							if (only_link_unlink &&
							        (link_unlink_user.find(call) == link_unlink_user.end())) {
								traceit("link request denied, unauthorized rf user [%s]\n", call);
							} else {
								memset(temp_repeater, ' ', CALL_SIZE);
								memcpy(temp_repeater, readBuffer + 36, CALL_SIZE - 2);
								temp_repeater[CALL_SIZE] = '\0';

								if ((to_remote_g2[i].to_call[0] == '\0') ||   /* not linked */
								        ((to_remote_g2[i].to_call[0] != '\0') &&  /* waiting for a link reply that may never arrive */
								         !to_remote_g2[i].is_connected))

									g2link(readBuffer[35], temp_repeater, readBuffer[42]);
								else if (to_remote_g2[i].is_connected) {
									strcpy(linked_remote_system, to_remote_g2[i].to_call);
									space_p = strchr(linked_remote_system, ' ');
									if (space_p)
										*space_p = '\0';
									sprintf(notify_msg, "%c_already_linked.dat_LINKED_%s_%c",
									        to_remote_g2[i].from_mod,
									        linked_remote_system,
									        to_remote_g2[i].to_mod);
									audio_notify(notify_msg);
								}
							}
						} else if ((readBuffer[43] == UNLINK_CODE) &&
						           (readBuffer[36] == ' ')) {
							if (only_link_unlink &&
							        (link_unlink_user.find(call) == link_unlink_user.end())) {
								traceit("unlink request denied, unauthorized rf user [%s]\n", call);
							} else {
								if (to_remote_g2[i].to_call[0] != '\0') {
									if (to_remote_g2[i].toDst4.sin_port == htons(rmt_ref_port)) {
										/* Check to see if any other local bands are linked to that same IP */
										for (j = 0; j < 3; j++) {
											if (j != i) {
												if ((to_remote_g2[j].toDst4.sin_addr.s_addr == to_remote_g2[i].toDst4.sin_addr.s_addr) &&
												        (to_remote_g2[j].toDst4.sin_port == htons(rmt_ref_port))) {
													traceit("Info: Local %c is also linked to %s (different module) %c\n",
													        to_remote_g2[j].from_mod,
													        to_remote_g2[j].to_call, to_remote_g2[j].to_mod);
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

										for (j = 0; j < 5; j++)
											sendto(xrf_g2_sock, unlink_request, CALL_SIZE+3, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));
									} else {
										strcpy(cmd_2_dcs, owner.c_str());
										cmd_2_dcs[8] = to_remote_g2[i].from_mod;
										cmd_2_dcs[9] = ' ';
										cmd_2_dcs[10] = '\0';
										memcpy(cmd_2_dcs + 11, to_remote_g2[i].to_call, 8);

										for (j=0; j<5; j++)
											sendto(dcs_g2_sock, cmd_2_dcs, 19, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));
									}

									traceit("Unlinked from [%s] mod %c\n",
									        to_remote_g2[i].to_call, to_remote_g2[i].to_mod);
									sprintf(notify_msg, "%c_unlinked.dat_UNLINKED", to_remote_g2[i].from_mod);
									audio_notify(notify_msg);

									/* now zero out this entry */
									to_remote_g2[i].to_call[0] = '\0';
									memset(&(to_remote_g2[i].toDst4),0,sizeof(struct sockaddr_in));
									to_remote_g2[i].from_mod = ' ';
									to_remote_g2[i].to_mod = ' ';
									to_remote_g2[i].countdown = 0;
									to_remote_g2[i].is_connected = false;
									to_remote_g2[i].in_streamid[0] = 0x00;
									to_remote_g2[i].in_streamid[1] = 0x00;

									print_status_file();
								} else {
									sprintf(notify_msg, "%c_already_unlinked.dat_UNLINKED", readBuffer[35]);
									audio_notify(notify_msg);
								}
							}
						} else if ((readBuffer[43] == INFO_CODE) &&
						           (readBuffer[36] == ' ')) {
							if (to_remote_g2[i].is_connected) {
								strcpy(linked_remote_system, to_remote_g2[i].to_call);
								space_p = strchr(linked_remote_system, ' ');
								if (space_p)
									*space_p = '\0';
								sprintf(notify_msg, "%c_linked.dat_LINKED_%s_%c",
								        to_remote_g2[i].from_mod,
								        linked_remote_system,
								        to_remote_g2[i].to_mod);
								audio_notify(notify_msg);
							} else {
								sprintf(notify_msg, "%c_id.dat_%s_NOT_LINKED", readBuffer[35], owner.c_str());
								audio_notify(notify_msg);
							}
						} else if ((readBuffer[43] == EXEC_CODE) &&
						           (readBuffer[36] == ' ') &&
						           (admin.find(call) != admin.end())) { // only ADMIN can execute scripts
							if (readBuffer[42] != ' ') {
								memset(system_cmd, '\0', sizeof(system_cmd));
								snprintf(system_cmd, FILENAME_MAX, "%s/exec_%c.sh %s %c &",
								         announce_dir.c_str(),
								         readBuffer[42], call, readBuffer[35]);
								traceit("Executing %s\n", system_cmd);
								system(system_cmd);
							}
						} else if ((readBuffer[42] == DONGLE_CODE) &&
						           (readBuffer[36] == ' ') &&
						           (admin.find(call) != admin.end())) { // only ADMIN can block dongle users
							if (readBuffer[43] == '1') {
								max_dongles = saved_max_dongles;
								traceit("Dongle connections are now allowed\n");
							} else if (readBuffer[43] == '0') {
								inbound_list.clear();
								max_dongles = 0;
								traceit("Dongle connections are now disallowed\n");
							}
						} else if ((readBuffer[43] == FILE_REFRESH_GWYS_CODE) &&
						           (readBuffer[36] == ' ') &&
						           (admin.find(call) != admin.end())) { // only ADMIN can reload gwys.txt
							gwy_list.clear();
							load_gwys(gwys);
						}
					}

					/* send data to the donglers */
					if (inbound_list.size() > 0) {
						readBuffer2[0] = (unsigned char)(58 & 0xFF);
						readBuffer2[1] = (unsigned char)(58 >> 8 & 0x1F);
						readBuffer2[1] = (unsigned char)(readBuffer2[1] | 0xFFFFFF80);

						memcpy(readBuffer2 + 2, "DSVT", 4);
						readBuffer2[6] = 0x10;
						readBuffer2[7] = 0x00;
						readBuffer2[8] = 0x00;
						readBuffer2[9] = 0x00;
						readBuffer2[10] = readBuffer[10];
						readBuffer2[11] = readBuffer[11];
						readBuffer2[12] = readBuffer[12];
						readBuffer2[13] = readBuffer[13];
						memcpy(readBuffer2 + 14, readBuffer + 14, 44);
						memcpy(readBuffer2 + 20, owner.c_str(), CALL_SIZE);
						readBuffer2[27] = readBuffer[35];
						memcpy(readBuffer2 + 28, owner.c_str(), CALL_SIZE);
						readBuffer2[35] = 'G';
						memcpy(&readBuffer2[36], "CQCQCQ  ", 8);

						for (pos = inbound_list.begin(); pos != inbound_list.end(); pos++) {
							inbound_ptr = (inbound *)pos->second;
							for (j=0; j<5; j++)
								sendto(ref_g2_sock, readBuffer2, 58, 0, (struct sockaddr *)&(inbound_ptr->sin), sizeof(struct sockaddr_in));
						}
					}

					if (i >= 0) {
						/* do we have to broadcast ? */
						/* make sure the source is linked to xrf */
						if ((to_remote_g2[i].is_connected) &&
						        (memcmp(to_remote_g2[i].to_call, "XRF", 3) == 0) &&
						        /* only CQCQCQ */
						        (memcmp(readBuffer + 20, owner.c_str(), CALL_SIZE-1) == 0) &&
						        (memcmp(readBuffer + 36, "CQCQCQ", 6) == 0) &&
						        (readBuffer[27] == 'G')) {
							brd_from_rptr_idx = 0;
							streamid_raw = (readBuffer[14] * 256U) + readBuffer[15];

							for (j = 0; j < 3; j++) {
								if ((j != i) &&
								        (to_remote_g2[j].is_connected) &&
								        (memcmp(to_remote_g2[j].to_call, to_remote_g2[i].to_call, 8) == 0) &&
								        (to_remote_g2[j].to_mod == to_remote_g2[i].to_mod) &&
								        (to_remote_g2[j].to_mod != 'E')) {
									memcpy(fromrptr_torptr_brd, "DSVT", 4);
									fromrptr_torptr_brd[4] = 0x10;
									fromrptr_torptr_brd[5] = 0x00;
									fromrptr_torptr_brd[6] = 0x00;
									fromrptr_torptr_brd[7] = 0x00;
									fromrptr_torptr_brd[8] = readBuffer[10];
									fromrptr_torptr_brd[9] = readBuffer[11];
									fromrptr_torptr_brd[10] = readBuffer[12];
									fromrptr_torptr_brd[11] = readBuffer[13];
									memcpy(fromrptr_torptr_brd + 12, readBuffer + 14, 44);

									streamid_raw ++;
									if (streamid_raw == 0)
										streamid_raw ++;
									fromrptr_torptr_brd[12] = streamid_raw / 256U;
									fromrptr_torptr_brd[13] = streamid_raw % 256U;

									memcpy(fromrptr_torptr_brd + 18, owner.c_str(), CALL_SIZE);
									fromrptr_torptr_brd[25] = to_remote_g2[j].from_mod;
									memcpy(fromrptr_torptr_brd + 26, owner.c_str(), CALL_SIZE);
									fromrptr_torptr_brd[33] = 'G';

									memcpy(fromrptr_torptr_brd + 34, "CQCQCQ  ", 8);

									calcPFCS(fromrptr_torptr_brd, 56);

									sendto(xrf_g2_sock, fromrptr_torptr_brd, 56, 0, (struct sockaddr *)&toLocalg2, sizeof(struct sockaddr_in));

									brd_from_rptr.from_rptr_streamid[0] = readBuffer[14];
									brd_from_rptr.from_rptr_streamid[1] = readBuffer[15];
									brd_from_rptr.to_rptr_streamid[brd_from_rptr_idx][0] = fromrptr_torptr_brd[12];
									brd_from_rptr.to_rptr_streamid[brd_from_rptr_idx][1] = fromrptr_torptr_brd[13];
									brd_from_rptr_idx ++;
								}
							}
						}

						if (to_remote_g2[i].is_connected) {
							if ((memcmp(readBuffer + 20, owner.c_str(), 7) == 0) &&
							        (memcmp(readBuffer + 36, "CQCQCQ", 6) == 0) &&
							        (readBuffer[27] == 'G')) {
								to_remote_g2[i].out_streamid[0] = readBuffer[14];
								to_remote_g2[i].out_streamid[1] = readBuffer[15];

								if ((to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port)) ||
								        (to_remote_g2[i].toDst4.sin_port ==  htons(rmt_ref_port))) {
									readBuffer2[0] = (unsigned char)(58 & 0xFF);
									readBuffer2[1] = (unsigned char)(58 >> 8 & 0x1F);
									readBuffer2[1] = (unsigned char)(readBuffer2[1] | 0xFFFFFF80);

									memcpy(readBuffer2 + 2, "DSVT", 4);
									readBuffer2[6] = 0x10;
									readBuffer2[7] = 0x00;
									readBuffer2[8] = 0x00;
									readBuffer2[9] = 0x00;
									readBuffer2[10] =  readBuffer[10];
									readBuffer2[11] =  readBuffer[11];
									readBuffer2[12] = readBuffer[12];
									readBuffer2[13] = readBuffer[13];
									memcpy(readBuffer2 + 14, readBuffer + 14, 44);
									memset(readBuffer2 + 20, ' ', CALL_SIZE);
									memcpy(readBuffer2 + 20, to_remote_g2[i].to_call,
									       strlen(to_remote_g2[i].to_call));
									readBuffer2[27] = to_remote_g2[i].to_mod;
									memset(readBuffer2 + 28, ' ', CALL_SIZE);
									memcpy(readBuffer2 + 28, to_remote_g2[i].to_call,
									       strlen(to_remote_g2[i].to_call));
									readBuffer2[35] = 'G';
									memcpy(&readBuffer2[36], "CQCQCQ  ", 8);

									calcPFCS(readBuffer2 + 2,56);

									if (to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port)) {
										/* inform XRF about the source */
										readBuffer2[13] = to_remote_g2[i].from_mod;

										for (j=0; j<5; j++)
											sendto(xrf_g2_sock, readBuffer2+2, 56, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));
									} else {
										for (j=0; j<5; j++)
											sendto(ref_g2_sock, readBuffer2, 58, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));
									}
								} else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_dcs_port)) {
									memcpy(rptr_2_dcs[i].mycall, readBuffer + 44, 8);
									memcpy(rptr_2_dcs[i].sfx, readBuffer + 52, 4);
									rptr_2_dcs[i].dcs_rptr_seq = 0;
								}
							}
						}
					}
				} else {
					if (inbound_list.size() > 0) {
						readBuffer2[0] = (unsigned char)(29 & 0xFF);
						readBuffer2[1] = (unsigned char)(29 >> 8 & 0x1F);
						readBuffer2[1] = (unsigned char)(readBuffer2[1] | 0xFFFFFF80);

						memcpy(readBuffer2 + 2, "DSVT", 4);
						readBuffer2[6] = 0x20;
						readBuffer2[7] = 0x00;
						readBuffer2[8] = 0x00;
						readBuffer2[9] = 0x00;
						readBuffer2[10] = readBuffer[10];
						readBuffer2[11] = readBuffer[11];
						readBuffer2[12] = readBuffer[12];
						readBuffer2[13] = readBuffer[13];
						memcpy(readBuffer2 + 14, readBuffer + 14, 3);
						if (recvlen == 29)
							memcpy(readBuffer2 + 17, readBuffer + 17, 12);
						else
							memcpy(readBuffer2 + 17, readBuffer + 20, 12);

						for (pos = inbound_list.begin(); pos != inbound_list.end(); pos++) {
							inbound_ptr = (inbound *)pos->second;
							sendto(ref_g2_sock, readBuffer2, 29, 0, (struct sockaddr *)&(inbound_ptr->sin), sizeof(struct sockaddr_in));
						}
					}

					for (i=0; i<3; i++) {
						if ((to_remote_g2[i].is_connected) &&
						        (memcmp(to_remote_g2[i].out_streamid, readBuffer + 14, 2) == 0)) {
							/* check for broadcast */
							if (memcmp(brd_from_rptr.from_rptr_streamid, readBuffer + 14, 2) == 0) {
								memcpy(fromrptr_torptr_brd, "DSVT", 4);
								fromrptr_torptr_brd[4] = 0x10;
								fromrptr_torptr_brd[5] = 0x00;
								fromrptr_torptr_brd[6] = 0x00;
								fromrptr_torptr_brd[7] = 0x00;
								fromrptr_torptr_brd[8] = readBuffer[10];
								fromrptr_torptr_brd[9] = readBuffer[11];
								fromrptr_torptr_brd[10] = readBuffer[12];
								fromrptr_torptr_brd[11] = readBuffer[13];
								memcpy(fromrptr_torptr_brd + 12, readBuffer + 14, 3);

								if (recvlen == 29)
									memcpy(fromrptr_torptr_brd + 15, readBuffer + 17, 12);
								else
									memcpy(fromrptr_torptr_brd + 15, readBuffer + 20, 12);

								if ((brd_from_rptr.to_rptr_streamid[0][0] != 0x00) ||
								        (brd_from_rptr.to_rptr_streamid[0][1] != 0x00)) {
									fromrptr_torptr_brd[12] = brd_from_rptr.to_rptr_streamid[0][0];
									fromrptr_torptr_brd[13] = brd_from_rptr.to_rptr_streamid[0][1];
									sendto(xrf_g2_sock, fromrptr_torptr_brd, 27, 0, (struct sockaddr *)&toLocalg2,sizeof(struct sockaddr_in));
								}

								if ((brd_from_rptr.to_rptr_streamid[1][0] != 0x00) ||
								        (brd_from_rptr.to_rptr_streamid[1][1] != 0x00)) {
									fromrptr_torptr_brd[12] = brd_from_rptr.to_rptr_streamid[1][0];
									fromrptr_torptr_brd[13] = brd_from_rptr.to_rptr_streamid[1][1];
									sendto(xrf_g2_sock, fromrptr_torptr_brd, 27, 0, (struct sockaddr *)&toLocalg2,sizeof(struct sockaddr_in));
								}

								if ((readBuffer[16] & 0x40) != 0) {
									brd_from_rptr.from_rptr_streamid[0] = brd_from_rptr.from_rptr_streamid[1] = 0x00;
									brd_from_rptr.to_rptr_streamid[0][0] = brd_from_rptr.to_rptr_streamid[0][1] = 0x00;
									brd_from_rptr.to_rptr_streamid[1][0] = brd_from_rptr.to_rptr_streamid[1][1] = 0x00;
									brd_from_rptr_idx = 0;
								}
							}

							if ((to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port)) ||
							        (to_remote_g2[i].toDst4.sin_port ==  htons(rmt_ref_port))) {
								readBuffer2[0] = (unsigned char)(29 & 0xFF);
								readBuffer2[1] = (unsigned char)(29 >> 8 & 0x1F);
								readBuffer2[1] = (unsigned char)(readBuffer2[1] | 0xFFFFFF80);

								memcpy(readBuffer2 + 2, "DSVT", 4);
								readBuffer2[6] = 0x20;
								readBuffer2[7] = 0x00;
								readBuffer2[8] = 0x00;
								readBuffer2[9] = 0x00;
								readBuffer2[10] =  readBuffer[10];
								readBuffer2[11] =  readBuffer[11];
								readBuffer2[12] = readBuffer[12];
								readBuffer2[13] = readBuffer[13];
								memcpy(readBuffer2 + 14, readBuffer + 14, 3);
								if (recvlen == 29)
									memcpy(readBuffer2 + 17, readBuffer + 17, 12);
								else
									memcpy(readBuffer2 + 17, readBuffer + 20, 12);

								if (to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port)) {
									/* inform XRF about the source */
									readBuffer2[13] = to_remote_g2[i].from_mod;

									sendto(xrf_g2_sock, readBuffer2+2, 27, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));
								} else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_ref_port))
									sendto(ref_g2_sock, readBuffer2, 29, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));
							} else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_dcs_port)) {
								memset(dcs_buf, 0x00, 600);
								dcs_buf[0] = dcs_buf[1] = dcs_buf[2] = '0';
								dcs_buf[3] = '1';
								dcs_buf[4] = dcs_buf[5] = dcs_buf[6] = 0x00;
								memcpy(dcs_buf + 7, to_remote_g2[i].to_call, 8);
								dcs_buf[14] = to_remote_g2[i].to_mod;
								memcpy(dcs_buf + 15, owner.c_str(), CALL_SIZE);
								dcs_buf[22] = to_remote_g2[i].from_mod;
								memcpy(dcs_buf + 23, "CQCQCQ  ", 8);
								memcpy(dcs_buf + 31, rptr_2_dcs[i].mycall, 8);
								memcpy(dcs_buf + 39, rptr_2_dcs[i].sfx, 4);
								dcs_buf[43] = readBuffer[14];  /* streamid0 */
								dcs_buf[44] = readBuffer[15];  /* streamid1 */
								dcs_buf[45] = readBuffer[16];  /* cycle sequence */
								memcpy(dcs_buf + 46, readBuffer + 17, 12);

								dcs_buf[58] = (rptr_2_dcs[i].dcs_rptr_seq >> 0)  & 0xff;
								dcs_buf[59] = (rptr_2_dcs[i].dcs_rptr_seq >> 8)  & 0xff;
								dcs_buf[60] = (rptr_2_dcs[i].dcs_rptr_seq >> 16) & 0xff;

								rptr_2_dcs[i].dcs_rptr_seq ++;

								dcs_buf[61] = 0x01;
								dcs_buf[62] = 0x00;

								sendto(dcs_g2_sock, dcs_buf, 100, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));
							}

							if ((readBuffer[16] & 0x40) != 0) {
								to_remote_g2[i].out_streamid[0] = 0x00;
								to_remote_g2[i].out_streamid[1] = 0x00;
							}
							break;
						}
					}

					for (i = 0; i < 3; i++) {
						if (memcmp(tracing[i].streamid, readBuffer + 14, 2) == 0) {
							/* update the last time RF user talked */
							tracing[i].last_time = time(NULL);

							if ((readBuffer[16] & 0x40) != 0) {
								if (qso_details)
									traceit("END from local g2: cntr=%02x %02x, streamID=%d,%d, %d bytes\n",
									        readBuffer[4], readBuffer[5],
									        readBuffer[14],readBuffer[15],recvlen);

								if (bool_rptr_ack)
									rptr_ack(i);

								memset(dtmf_mycall[i], 0, sizeof(dtmf_mycall[i]));
								new_group[i] = true;
								GPS_seen[i] = false;

								tracing[i].streamid[0] = 0x00;
								tracing[i].streamid[1] = 0x00;
							} else {
								if (!GPS_seen[i]) {
									if (recvlen == 29)
										memcpy(tmp_txt, readBuffer + 26, 3);
									else
										memcpy(tmp_txt, readBuffer + 29, 3);

									if ((tmp_txt[0] != 0x55) || (tmp_txt[1] != 0x2d) || (tmp_txt[2] != 0x16)) {
										if (new_group[i]) {
											tmp_txt[0] = tmp_txt[0] ^ 0x70;
											header_type = tmp_txt[0] & 0xf0;

											if ((header_type == 0x50) ||  /* header  */
											        (header_type == 0xc0))    /* squelch */
												new_group[i] = false;
											else if (header_type == 0x30) { /* GPS or GPS id or APRS */
												GPS_seen[i] = true;
												new_group[i] = false;

												memcpy(tmp1, dtmf_mycall[i], 8);
												tmp1[8] = '\0';

												// delete the user if exists and it is a local RF entry
												p_tmp2 = NULL;
												for (dt_lh_pos = dt_lh_list.begin(); dt_lh_pos != dt_lh_list.end();  dt_lh_pos++) {
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
			FD_CLR (rptr_sock,&fdset);
		}
	}
}

void audio_notify(char *msg)
{
	if (!announce)
		return;

	short int i = 0;
	static char notify_msg[3][64];

	if (*msg == 'A')
		i = 0;
	else if (*msg == 'B')
		i = 1;
	else if (*msg == 'C')
		i = 2;

	strcpy(notify_msg[i], msg);
	try {
		std::async(std::launch::async, AudioNotifyThread, notify_msg[i]);
	} catch (const std::exception &e) {
		traceit ("Failed to start AudioNotifyThread(). Exception: %s\n", e.what());
	}
	return;
}

static void AudioNotifyThread(char *arg)
{
	char notify_msg[64];

	strcpy(notify_msg, (char *)arg);

	unsigned short rlen = 0;
	size_t nread = 0;
	unsigned char dstar_buf[56];
	bool useTEXT = false;
	short int TEXT_idx = 0;
	char RADIO_ID[21];
	char temp_file[FILENAME_MAX + 1];
	FILE *fp = NULL;
	char mod;
	char *p = NULL;
	u_int16_t streamid_raw = 0;
	struct timespec nanos;
	unsigned int aseed;
	time_t tnow = 0;
	struct sigaction act;

	/* example: A_linked.dat_LINKED_TO_XRF005_A */
	/* example: A_unlinked.dat */
	/* example: A_failed_linked.dat */

	act.sa_handler = sigCatch;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	if (sigaction(SIGTERM, &act, 0) != 0) {
		traceit("sigaction-TERM failed, error=%d\n", errno);
		return;
	}
	if (sigaction(SIGINT, &act, 0) != 0) {
		traceit("sigaction-INT failed, error=%d\n", errno);
		return;
	}

	memset(RADIO_ID, ' ', 20);
	RADIO_ID[20] = '\0';

	mod = notify_msg[0];

	if ((mod != 'A') && (mod != 'B') && (mod != 'C')) {
		traceit("Invalid module %c in %s\n", mod, notify_msg);
		return;
	}

	p = strstr(notify_msg, ".dat");
	if (!p) {
		traceit("Incorrect filename in %s\n", notify_msg);
		return;
	}

	if (p[4] == '_') {
		useTEXT = true;
		memcpy(RADIO_ID, p + 5, (strlen(p + 5) > 20)?20:strlen(p + 5));
		for (TEXT_idx = 0; TEXT_idx < 20; TEXT_idx++) {
			RADIO_ID[TEXT_idx] = toupper(RADIO_ID[TEXT_idx]);
			if (RADIO_ID[TEXT_idx] == '_')
				RADIO_ID[TEXT_idx] = ' ';
		}
		TEXT_idx = 0;
		p[4] = '\0';
	} else
		useTEXT = false;

	sleep(delay_before);

	memset(temp_file, '\0', sizeof(temp_file));
	snprintf(temp_file, FILENAME_MAX, "%s/%s", announce_dir.c_str(), notify_msg + 2);
	traceit("sending File:[%s], mod:[%c], RADIO_ID=[%s]\n", temp_file, mod, RADIO_ID);

	fp = fopen(temp_file, "rb");
	if (!fp) {
		traceit("Failed to open file %s for reading\n", temp_file);
		return;
	}

	/* stupid DVTOOL + 4 byte num_of_records */
	nread = fread(dstar_buf, 10, 1, fp);
	if (nread != 1) {
		traceit("Cant read first 10 bytes from %s\n", temp_file);
		fclose(fp);
		return;
	}
	if (memcmp(dstar_buf, "DVTOOL", 6) != 0) {
		traceit("DVTOOL keyword not found in %s\n", temp_file);
		fclose(fp);
		return;
	}

	time(&tnow);
	aseed = tnow + pthread_self();

	while (keep_running) {
		/* 2 byte length */
		nread = fread(&rlen, 2, 1, fp);
		if (nread != 1)
			break;

		if (rlen == 56)
			streamid_raw = (::rand_r(&aseed) % 65535U) + 1U;
		else if (rlen == 27)
			;
		else {
			traceit("Not 56-byte and not 27-byte in %s\n", temp_file);
			break;
		}

		nread = fread(dstar_buf, rlen, 1, fp);
		if (nread == 1) {
			if (memcmp(dstar_buf, "DSVT", 4) != 0) {
				traceit("DVST not found in %s\n", temp_file);
				break;
			}

			if (dstar_buf[8] != 0x20) {
				traceit("Not Voice type in %s\n", temp_file);
				break;
			}

			if (dstar_buf[4] == 0x10)
				;
			else if (dstar_buf[4] == 0x20)
				;
			else {
				traceit("Not a valid record type in %s\n", temp_file);
				break;
			}

			dstar_buf[12] = streamid_raw / 256U;
			dstar_buf[13] = streamid_raw % 256U;

			if (rlen == 56) {
				dstar_buf[15] = 0x01;

				memcpy(dstar_buf + 18, owner.c_str(), CALL_SIZE);
				dstar_buf[25] = mod;

				memcpy(dstar_buf + 26, owner.c_str(), CALL_SIZE);
				dstar_buf[33] = 'G';

				memcpy(dstar_buf + 34, "CQCQCQ  ", 8);

				memcpy(dstar_buf + 42, owner.c_str(), CALL_SIZE);
				dstar_buf[48] = ' ';
				dstar_buf[49] = ' ';

				memcpy(dstar_buf + 50, "RPTR", 4);
				calcPFCS(dstar_buf, 56);
			} else {
				if (useTEXT) {
					if ((dstar_buf[24] != 0x55) ||
					        (dstar_buf[25] != 0x2d) ||
					        (dstar_buf[26] != 0x16)) {
						if (TEXT_idx == 0) {
							dstar_buf[24] = '@' ^ 0x70;
							dstar_buf[25] = RADIO_ID[TEXT_idx++] ^ 0x4f;
							dstar_buf[26] = RADIO_ID[TEXT_idx++] ^ 0x93;
						} else if (TEXT_idx == 2) {
							dstar_buf[24] = RADIO_ID[TEXT_idx++] ^ 0x70;
							dstar_buf[25] = RADIO_ID[TEXT_idx++] ^ 0x4f;
							dstar_buf[26] = RADIO_ID[TEXT_idx++] ^ 0x93;
						} else if (TEXT_idx == 5) {
							dstar_buf[24] = 'A' ^ 0x70;
							dstar_buf[25] = RADIO_ID[TEXT_idx++] ^ 0x4f;
							dstar_buf[26] = RADIO_ID[TEXT_idx++] ^ 0x93;
						} else if (TEXT_idx == 7) {
							dstar_buf[24] = RADIO_ID[TEXT_idx++] ^ 0x70;
							dstar_buf[25] = RADIO_ID[TEXT_idx++] ^ 0x4f;
							dstar_buf[26] = RADIO_ID[TEXT_idx++] ^ 0x93;
						} else if (TEXT_idx == 10) {
							dstar_buf[24] = 'B' ^ 0x70;
							dstar_buf[25] = RADIO_ID[TEXT_idx++] ^ 0x4f;
							dstar_buf[26] = RADIO_ID[TEXT_idx++] ^ 0x93;
						} else if (TEXT_idx == 12) {
							dstar_buf[24] = RADIO_ID[TEXT_idx++] ^ 0x70;
							dstar_buf[25] = RADIO_ID[TEXT_idx++] ^ 0x4f;
							dstar_buf[26] = RADIO_ID[TEXT_idx++] ^ 0x93;
						} else if (TEXT_idx == 15) {
							dstar_buf[24] = 'C' ^ 0x70;
							dstar_buf[25] = RADIO_ID[TEXT_idx++] ^ 0x4f;
							dstar_buf[26] = RADIO_ID[TEXT_idx++] ^ 0x93;
						} else if (TEXT_idx == 17) {
							dstar_buf[24] = RADIO_ID[TEXT_idx++] ^ 0x70;
							dstar_buf[25] = RADIO_ID[TEXT_idx++] ^ 0x4f;
							dstar_buf[26] = RADIO_ID[TEXT_idx++] ^ 0x93;
						} else {
							dstar_buf[24] = 0x70;
							dstar_buf[25] = 0x4f;
							dstar_buf[26] = 0x93;
						}
					}
				}
			}
			sendto(rptr_sock,  dstar_buf, rlen, 0, (struct sockaddr *)&toLocalg2,sizeof(struct sockaddr_in));
		}
		nanos.tv_sec = 0;
		nanos.tv_nsec = delay_between * 1000000;
		nanosleep(&nanos,0);
	}
	fclose(fp);
	return;
}

int main(int argc, char **argv)
{
	short i, j;
	struct sigaction act;
	char unlink_request[CALL_SIZE + 3];
	inbound_type::iterator pos;
	inbound *inbound_ptr;

	char cmd_2_dcs[19];

	tzset();
	setvbuf(stdout, (char *)NULL, _IOLBF, 0);

	if (argc != 2) {
		traceit("Usage: ./g2_link g2_link.cfg\n");
		return 1;
	}

	int rc = regcomp(&preg,
	             "^(([1-9][A-Z])|([A-Z][0-9])|([A-Z][A-Z][0-9]))[0-9A-Z]*[A-Z][ ]*[ A-RT-Z]$",
	             REG_EXTENDED | REG_NOSUB);
	if (rc != 0) {
		traceit("The IRC regular expression is NOT valid\n");
		return 1;
	}

	act.sa_handler = sigCatch;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	if (sigaction(SIGTERM, &act, 0) != 0) {
		traceit("sigaction-TERM failed, error=%d\n", errno);
		return 1;
	}
	if (sigaction(SIGINT, &act, 0) != 0) {
		traceit("sigaction-INT failed, error=%d\n", errno);
		return 1;
	}

	for (i = 0; i < 3; i++) {
		to_remote_g2[i].to_call[0] = '\0';
		memset(&(to_remote_g2[i].toDst4),0,sizeof(struct sockaddr_in));
		to_remote_g2[i].to_mod = ' ';
		to_remote_g2[i].to_mod = ' ';
		to_remote_g2[i].countdown = 0;
		to_remote_g2[i].is_connected = false;
		to_remote_g2[i].in_streamid[0] = 0x00;
		to_remote_g2[i].in_streamid[1] = 0x00;
		to_remote_g2[i].out_streamid[0] = 0x00;
		to_remote_g2[i].out_streamid[1] = 0x00;
	}

	brd_from_xrf.xrf_streamid[0] = brd_from_xrf.xrf_streamid[1] = 0x00;
	brd_from_xrf.rptr_streamid[0][0] = brd_from_xrf.rptr_streamid[0][1] = 0x00;
	brd_from_xrf.rptr_streamid[1][0] = brd_from_xrf.rptr_streamid[1][1] = 0x00;
	brd_from_xrf_idx = 0;

	brd_from_rptr.from_rptr_streamid[0] = brd_from_rptr.from_rptr_streamid[1] = 0x00;
	brd_from_rptr.to_rptr_streamid[0][0] = brd_from_rptr.to_rptr_streamid[0][1] = 0x00;
	brd_from_rptr.to_rptr_streamid[1][0] = brd_from_rptr.to_rptr_streamid[1][1] = 0x00;
	brd_from_rptr_idx = 0;

	do {
		/* process configuration file */
		if (!read_config(argv[1])) {
			traceit("Failed to process config file %s\n", argv[1]);
			break;
		}
		print_status_file();

		/* Open DB */
		if (!load_gwys(gwys))
			break;

		/* create our server */
		if (!srv_open()) {
			traceit("srv_open() failed\n");
			break;
		}

		traceit("g2_link %s initialized...entering processing loop\n", VERSION);
		runit();
		traceit("Leaving processing loop...\n");

	} while (false);


	/* Clear connections */
	queryCommand[0] = 5;
	queryCommand[1] = 0;
	queryCommand[2] = 24;
	queryCommand[3] = 0;
	queryCommand[4] = 0;
	for (i = 0; i < 3; i++) {
		if (to_remote_g2[i].to_call[0] != '\0') {
			if (to_remote_g2[i].toDst4.sin_port == htons(rmt_ref_port))
				sendto(ref_g2_sock, queryCommand, 5, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));
			else if (to_remote_g2[i].toDst4.sin_port == htons(rmt_xrf_port)) {
				strcpy(unlink_request, owner.c_str());
				unlink_request[8] = to_remote_g2[i].from_mod;
				unlink_request[9] = ' ';
				unlink_request[10] = '\0';
				for (j=0; j<5; j++)
					sendto(xrf_g2_sock, unlink_request, CALL_SIZE+3, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));
			} else {
				strcpy(cmd_2_dcs, owner.c_str());
				cmd_2_dcs[8] = to_remote_g2[i].from_mod;
				cmd_2_dcs[9] = ' ';
				cmd_2_dcs[10] = '\0';
				memcpy(cmd_2_dcs + 11, to_remote_g2[i].to_call, 8);

				for (j=0; j<5; j++)
					sendto(dcs_g2_sock, cmd_2_dcs, 19, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(to_remote_g2[i].toDst4));
			}
		}
		to_remote_g2[i].to_call[0] = '\0';
		memset(&(to_remote_g2[i].toDst4),0,sizeof(struct sockaddr_in));
		to_remote_g2[i].from_mod = ' ';
		to_remote_g2[i].to_mod = ' ';
		to_remote_g2[i].countdown = 0;
		to_remote_g2[i].is_connected = false;
		to_remote_g2[i].in_streamid[0] = 0x00;
		to_remote_g2[i].in_streamid[1] = 0x00;
		to_remote_g2[i].out_streamid[0] = 0x00;
		to_remote_g2[i].out_streamid[1] = 0x00;
	}

	/* tell inbound dongles we are down */
	for (pos = inbound_list.begin(); pos != inbound_list.end(); pos++) {
		inbound_ptr = (inbound *)pos->second;
		sendto(ref_g2_sock, queryCommand, 5, 0, (struct sockaddr *)&(inbound_ptr->sin), sizeof(struct sockaddr_in));
	}
	inbound_list.clear();

	print_status_file();
	srv_close();
	traceit("g2_link exiting\n");

	return 0;
}
