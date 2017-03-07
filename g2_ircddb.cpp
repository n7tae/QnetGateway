/*
 *   Copyright (C) 2010 by Scott Lawson KI4LKF
 *
 *   Copyright 2017 by Thomas Early, AC2IE
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


/* by KI4LKF, AC2IE */
/*
   g2_ircddb is a dstar G2 gateway, using irc routing
       adapted from the OpenG2 G2 gateway
   Version 2.61 or higher will use ONLY the irc mechanism of routing
     and it will NOT use any local Postgres databases or any TRUST(s)
*/

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
#include <math.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <regex.h>

#include <atomic>
#include <future>
#include <exception>
#include <string>
#include <map>
#include <libconfig.h++>
using namespace libconfig;


#include "IRCDDB.h"
#include "IRCutils.h"
#include "versions.h"
#include "g2_typedefs.h"
#include "aprs.h"

#define IP_SIZE 15
#define MAXHOSTNAMELEN 64
#define CALL_SIZE 8
#define MAX_DTMF_BUF 32
#define ECHO_CODE 'E'
#define STORE_VM_CODE 'S'
#define RECALL_VM_CODE 'R'
#define CLEAR_VM_CODE 'C'
#define LINK_CODE 'L'

typedef struct echo_tag {
	time_t last_time;
	unsigned short streamid;
	int fd;
	char file[FILENAME_MAX + 1];
} SECHO;

typedef struct to_remote_g2_tag {
	unsigned short streamid;
	struct sockaddr_in toDst4;
	time_t last_time;
} STOREMOTEG2;

typedef struct torepeater_tag {
	// help with header re-generation
	unsigned char saved_hdr[58]; // repeater format
	uint32_t saved_adr;

	unsigned short streamid;
	uint32_t adr;
	struct sockaddr_in band_addr;
	time_t last_time;
	std::atomic<unsigned short> G2_COUNTER;
	unsigned char sequence;
} STOREPEATER;

typedef struct band_txt_tag {
	unsigned short streamID;
	unsigned char flags[3];
	char lh_mycall[CALL_SIZE + 1];
	char lh_sfx[5];
	char lh_yrcall[CALL_SIZE + 1];
	char lh_rpt1[CALL_SIZE + 1];
	char lh_rpt2[CALL_SIZE + 1];
	time_t last_time;
	char txt[64];   // Only 20 are used
	unsigned short txt_cnt;
	bool txt_stats_sent;

	char dest_rptr[CALL_SIZE + 1];

	// try to process GPS mode: GPRMC and ID
	char temp_line[256];
	unsigned short temp_line_cnt;
	char gprmc[256];
	char gpid[256];
	bool is_gps_sent;
	time_t gps_last_time;

	int num_dv_frames;
	int num_dv_silent_frames;
	int num_bit_errors;
} SBANDTXT;

SPORTIP g2_internal, g2_external, g2_link, ircddb;

static std::string OWNER, owner, local_irc_ip, status_file, dtmf_dir, dtmf_file,
					echotest_dir, irc_pass;

static bool bool_send_qrgs, bool_irc_debug, bool_dtmf_debug, bool_regen_header,
					bool_qso_details, bool_send_aprs;

static int play_wait, play_delay, echotest_rec_timeout, voicemail_rec_timeout,
					from_remote_g2_timeout, from_local_rptr_timeout, dtmf_digit;

// data needed for aprs login and aprs beacon
// RPTR defined in aprs.h
SRPTR rptr;

// local repeater modules being recorded
// This is for echotest and voicemail
static SECHO recd[3], vm[3];
SDSVT recbuf; // 56 or 27, max is 56

// the streamids going to remote Gateways from each local module
static STOREMOTEG2 to_remote_g2[3]; // 0=A, 1=B, 2=C

// input from remote G2 gateway
static int g2_sock = -1;
static struct sockaddr_in fromDst4;

//   Incoming data from remote systems
//   must be fed into our local repeater modules.
static STOREPEATER toRptr[3]; // 0=A, 1=B, 2=C

// input from our own local repeater modules
static int srv_sock = -1;
static SPKT rptrbuf; // 58 or 29 or 32, max is 58
static struct sockaddr_in fromRptr;

static SPKT end_of_audio;

static std::atomic<bool> keep_running(true);

// send packets to g2_link
static struct sockaddr_in plug;

// for talking with the irc server
static CIRCDDB *ii;
// for handling APRS stuff
static CAPRS *aprs;

// text coming from local repeater bands
static SBANDTXT band_txt[3]; // 0=A, 1=B, 2=C

/* Used to validate MYCALL input */
static regex_t preg;

// CACHE used to cache users, repeaters,
// gateways, IP numbers coming from the irc server

static std::map<std::string, std::string> user2rptr_map, rptr2gwy_map, gwy2ip_map;

static pthread_mutex_t irc_data_mutex = PTHREAD_MUTEX_INITIALIZER;

static int open_port(const SPORTIP &pip);
static void calcPFCS(unsigned char *packet, int len);
static void GetIRCDataThread();
static int get_yrcall_rptr_from_cache(char *call, char *arearp_cs, char *zonerp_cs, char *mod, char *ip, char RoU);
static bool get_yrcall_rptr(char *call, char *arearp_cs, char *zonerp_cs, char *mod, char *ip, char RoU);
static bool read_config(char *);
static void runit();
static void sigCatch(int signum);
static void PlayFileThread(char *file);
static void compute_aprs_hash();
static void APRSBeaconThread();

/* aprs functions, borrowed from my retired IRLP node 4201 */
static void gps_send(short int rptr_idx);
static bool verify_gps_csum(char *gps_text, char *csum_text);
static void build_aprs_from_gps_and_send(short int rptr_idx);

static void qrgs_and_maps();

static void set_dest_rptr(int mod_ndx, char *dest_rptr);

extern void dstar_dv_init();
extern int dstar_dv_decode(const unsigned char *d, int data[3]);

static void set_dest_rptr(int mod_ndx, char *dest_rptr)
{
	FILE *statusfp = fopen(status_file.c_str(), "r");
	if (statusfp) {
		setvbuf(statusfp, (char *)NULL, _IOLBF, 0);

		char statusbuf[1024];
		while (fgets(statusbuf, 1020, statusfp) != NULL) {
			char *p = strchr(statusbuf, '\r');
			if (p)
				*p = '\0';
			p = strchr(statusbuf, '\n');
			if (p)
				*p = '\0';

			const char *delim = ",";
			char *saveptr = NULL;
			char *status_local_mod = strtok_r(statusbuf, delim, &saveptr);
			char *status_remote_stm = strtok_r(NULL, delim, &saveptr);
			char *status_remote_mod = strtok_r(NULL, delim, &saveptr);

			if (!status_local_mod || !status_remote_stm || !status_remote_mod)
				continue;

			if ( ((*status_local_mod == 'A') && (mod_ndx == 0))  ||
			     ((*status_local_mod == 'B') && (mod_ndx == 1))  ||
			     ((*status_local_mod == 'C') && (mod_ndx == 2)) ) {
				strncpy(dest_rptr, status_remote_stm, CALL_SIZE);
				dest_rptr[7] = *status_remote_mod;
				dest_rptr[CALL_SIZE] = '\0';
				break;
			}
		}
		fclose(statusfp);
	}
	return;
}

/* compute checksum */
static void calcPFCS(unsigned char *packet, int len)
{
	const unsigned short crc_tabccitt[256] = {
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
	short int low, high;
	unsigned short tmp;

	switch (len) {
		case 56:
			low = 15;
			high = 54;
			break;
		case 58:
			low = 17;
			high = 56;
			break;
		default:
			return;
	}

	for (unsigned short int i = low; i < high ; i++) {
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
static bool read_config(char *cfgFile)
{
	Config cfg;

	traceit("Reading file %s\n", cfgFile);
	// Read the file. If there is an error, report it and exit.
	try {
		cfg.readFile(cfgFile);
	} catch(const FileIOException &fioex) {
		traceit("Can't read %s\n", cfgFile);
		return true;
	} catch(const ParseException &pex) {
		traceit("Parse error at %s:%d - %s\n", pex.getFile(), pex.getLine(), pex.getError());
		return true;
	}

	if (! get_value(cfg, "ircddb.login", owner, 3, CALL_SIZE-2, "UNDEFINED"))
		return true;
	OWNER = owner;
	ToLower(owner);
	ToUpper(OWNER);
	traceit("OWNER=[%s]\n", OWNER.c_str());
	OWNER.resize(CALL_SIZE, ' ');

	for (short int m=0; m<3; m++) {
		std::string path = "module.";
		path += m + 'a';
		std::string type;
		if (cfg.lookupValue(std::string(path+".type").c_str(), type)) {
			if (strcasecmp(type.c_str(), "dvap") && strcasecmp(type.c_str(), "dvrptr") && strcasecmp(type.c_str(), "mmdvm")) {
				traceit("%s.type '%s' is invalid\n", type.c_str());
				return true;
			}
			rptr.mod[m].defined = true;
			if (0 == strcasecmp(type.c_str(), "dvap"))
				rptr.mod[m].package_version = DVAP_VERSION;
			else if (0 == strcasecmp(type.c_str(), "dvrptr"))
				rptr.mod[m].package_version = DVRPTR_VERSION;
			else
				rptr.mod[m].package_version = MMDVM_VERSION;
			if (! get_value(cfg, std::string(path+".ip").c_str(), rptr.mod[m].portip.ip, 7, IP_SIZE, "127.0.0.1"))
				return true;
			get_value(cfg, std::string(path+".port").c_str(), rptr.mod[m].portip.port, 16000, 65535, 19998+m);
			get_value(cfg, std::string(path+".frequency").c_str(), rptr.mod[m].frequency, 0.0, 1.0e12, 0.0);
			get_value(cfg, std::string(path+".offset").c_str(), rptr.mod[m].offset,-1.0e12, 1.0e12, 0.0);
			get_value(cfg, std::string(path+".range").c_str(), rptr.mod[m].range, 0.0, 1609344.0, 0.0);
			get_value(cfg, std::string(path+".agl").c_str(), rptr.mod[m].agl, 0.0, 1000.0, 0.0);
			get_value(cfg, std::string(path+".latitude").c_str(), rptr.mod[m].latitude, -90.0, 90.0, 0.0);
			get_value(cfg, std::string(path+".longitude").c_str(), rptr.mod[m].longitude, -180.0, 180.0, 0.0);
			if (! cfg.lookupValue(path+".desc1", rptr.mod[m].desc1))
				rptr.mod[m].desc1 = "";
			if (! cfg.lookupValue(path+".desc2", rptr.mod[m].desc2))
				rptr.mod[m].desc2 = "";
			if (! get_value(cfg, std::string(path+".url").c_str(), rptr.mod[m].url, 0, 80, "github.com/ac2ie/g2_ircddb"))
				return true;
			// truncate strings
			if (rptr.mod[m].desc1.length() > 20)
				rptr.mod[m].desc1.resize(20);
			if (rptr.mod[m].desc2.length() > 20)
				rptr.mod[m].desc2.resize(20);
			// make the long description for the log
			if (rptr.mod[m].desc1.length())
				rptr.mod[m].desc = rptr.mod[m].desc1 + ' ';
			rptr.mod[m].desc += rptr.mod[m].desc2;
		} else
			rptr.mod[m].defined = false;
	}
	if (false==rptr.mod[0].defined && false==rptr.mod[1].defined && false==rptr.mod[2].defined) {
		traceit("No repeaters defined!\n");
		return true;
	}

	if (! get_value(cfg, "file.status", status_file, 1, FILENAME_MAX, "/usr/local/etc/RPTR_STATUS.txt"))
		return true;

	if (! get_value(cfg, "gateway.local_irc_ip", local_irc_ip, 7, IP_SIZE, "0.0.0.0"))
		return true;

	get_value(cfg, "gateway.send_qrgs_maps", bool_send_qrgs, true);

	if (! get_value(cfg, "aprs.host", rptr.aprs.ip, 7, MAXHOSTNAMELEN, "rotate.aprs.net"))
		return true;

	get_value(cfg, "aprs.port", rptr.aprs.port, 10000, 65535, 14580);

	get_value(cfg, "aprs.interval", rptr.aprs_interval, 40, 1000, 40);

	if (! get_value(cfg, "aprs.filter", rptr.aprs_filter, 0, 512, ""))
		return true;

	if (! get_value(cfg, "gateway.external.ip", g2_external.ip, 7, IP_SIZE, "0.0.0.0"))
		return true;

	get_value(cfg, "gateway.external.port", g2_external.port, 20001, 65535, 40000);

	if (! get_value(cfg, "gateway.internal.ip", g2_internal.ip, 7, IP_SIZE, "0.0.0.0"))
		return true;

	get_value(cfg, "gateway.internal.port", g2_internal.port, 16000, 65535, 19000);

	if (! get_value(cfg, "g2_link.outgoing_ip", g2_link.ip, 7, IP_SIZE, "127.0.0.1"))
		return true;

	get_value(cfg, "g2_link.port", g2_link.port, 16000, 65535, 18997);

	get_value(cfg, "log.qso", bool_qso_details, true);

	get_value(cfg, "log.irc", bool_irc_debug, false);

	get_value(cfg, "log.dtmf", bool_dtmf_debug, false);

	get_value(cfg, "gateway.regen_header", bool_regen_header, true);

	get_value(cfg, "gateway.aprs_send", bool_send_aprs, true);

	if (! get_value(cfg, "file.echotest", echotest_dir, 2, FILENAME_MAX, "/tmp"))
		return true;

	get_value(cfg, "timing.play.wait", play_wait, 1, 10, 2);

	get_value(cfg, "timing.play.delay", play_delay, 9, 25, 19);

	get_value(cfg, "timing.timeeout.echo", echotest_rec_timeout, 1, 10, 1);

	get_value(cfg, "timing.timeout.voicemail", voicemail_rec_timeout, 1, 10, 1);

	get_value(cfg, "timing.timeout.remote_g2", from_remote_g2_timeout, 1, 10, 2);

	get_value(cfg, "timing.timeout.local_rptr", from_local_rptr_timeout, 1, 10, 1);

	if (! get_value(cfg, "ircddb.host", ircddb.ip, 3, MAXHOSTNAMELEN, "rr.openquad.net"))
		return true;

	get_value(cfg, "ircddb.port", ircddb.port, 1000, 65535, 9007);

	if(! get_value(cfg, "ircddb.password", irc_pass, 0, 512, "1111111111111111"))
		return true;

	if (! get_value(cfg, "file.dtmf",  dtmf_dir, 2,FILENAME_MAX, "/tmp"))
		return true;

	return false;
}

// Create ports
static int open_port(const SPORTIP &pip)
{
	struct sockaddr_in sin;

	int sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (0 > sock) {
		traceit("Failed to create socket on %s:%d, errno=%d\n", pip.ip.c_str(), pip.port, errno);
		return -1;
	}
	fcntl(sock, F_SETFL, O_NONBLOCK);

	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(pip.port);
	sin.sin_addr.s_addr = inet_addr(pip.ip.c_str());

	if (bind(sock, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) != 0) {
		traceit("Failed to bind %s:%d, errno=%d\n", pip.ip.c_str(), pip.port, errno);
		close(sock);
		return -1;
	}
	
	return sock;
}

/* receive data from the irc server and save it */
static void GetIRCDataThread()
{
	struct timespec req;

	std::string user, rptr, gateway, ipaddr;
	DSTAR_PROTOCOL proto;
	IRCDDB_RESPONSE_TYPE type;
	struct sigaction act;
	short last_status = 0;

	act.sa_handler = sigCatch;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	if (sigaction(SIGTERM, &act, 0) != 0) {
		traceit("GetIRCDataThread: sigaction-TERM failed, error=%d\n", errno);
		keep_running = false;
		return;
	}
	if (sigaction(SIGINT, &act, 0) != 0) {
		traceit("GetIRCDataThread: sigaction-INT failed, error=%d\n", errno);
		keep_running = false;
		return;
	}
	if (sigaction(SIGPIPE, &act, 0) != 0) {
		traceit("GetIRCDataThread: sigaction-PIPE failed, error=%d\n", errno);
		keep_running = false;
		return;
	}

	short threshold = 0;
	while (keep_running) {
		threshold++;
		if (threshold >= 100) {
			int rc = ii->getConnectionState();
			if ((rc == 0) || (rc == 10)) {
				if (last_status != 0) {
					traceit("irc status=%d, probable disconnect...\n", rc);
					last_status = 0;
				}
			} else if (rc == 7) {
				if (last_status != 2) {
					traceit("irc status=%d, probable connect...\n", rc);
					last_status = 2;
				}
			} else {
				if (last_status != 1) {
					traceit("irc status=%d, probable connect...\n", rc);
					last_status = 1;
				}
			}
			threshold = 0;
		}

		while (((type = ii->getMessageType()) != IDRT_NONE) && keep_running) {
			if (type == IDRT_USER) {
				ii->receiveUser(user, rptr, gateway, ipaddr);
				if (!user.empty()) {
					if (!rptr.empty() && !gateway.empty() && !ipaddr.empty()) {
						if (bool_irc_debug)
							traceit("C-u:%s,%s,%s,%s\n", user.c_str(), rptr.c_str(), gateway.c_str(), ipaddr.c_str());

						pthread_mutex_lock(&irc_data_mutex);

						user2rptr_map[user] = rptr;
						rptr2gwy_map[rptr] = gateway;
						gwy2ip_map[gateway] = ipaddr;

						pthread_mutex_unlock(&irc_data_mutex);

						// traceit("%d users, %d repeaters, %d gateways\n",  user2rptr_map.size(), rptr2gwy_map.size(), gwy2ip_map.size());

					}
				}
			} else if (type == IDRT_REPEATER) {
				ii->receiveRepeater(rptr, gateway, ipaddr, proto);
				if (!rptr.empty()) {
					if (!gateway.empty() && !ipaddr.empty()) {
						if (bool_irc_debug)
							traceit("C-r:%s,%s,%s\n", rptr.c_str(), gateway.c_str(), ipaddr.c_str());

						pthread_mutex_lock(&irc_data_mutex);

						rptr2gwy_map[rptr] = gateway;
						gwy2ip_map[gateway] = ipaddr;

						pthread_mutex_unlock(&irc_data_mutex);

						// traceit("%d repeaters, %d gateways\n", rptr2gwy_map.size(), gwy2ip_map.size());

					}
				}
			} else if (type == IDRT_GATEWAY) {
				ii->receiveGateway(gateway, ipaddr, proto);
				if (!gateway.empty() && !ipaddr.empty()) {
					if (bool_irc_debug)
						traceit("C-g:%s,%s\n", gateway.c_str(),ipaddr.c_str());

					pthread_mutex_lock(&irc_data_mutex);

					gwy2ip_map[gateway] = ipaddr;

					pthread_mutex_unlock(&irc_data_mutex);

					// traceit("%d gateways\n", gwy2ip_map.size());

				}
			}
		}
		req.tv_sec = 0;
		req.tv_nsec = 500000000; // 500 milli
		nanosleep(&req, NULL);
	}
	traceit("GetIRCDataThread exiting...\n");
	return;
}

/* return codes: 0=OK(found it), 1=TRY AGAIN, 2=FAILED(bad data) */
static int get_yrcall_rptr_from_cache(char *call, char *arearp_cs, char *zonerp_cs, char *mod, char *ip, char RoU)
{
	std::map<std::string, std::string>::iterator user_pos = user2rptr_map.end();
	std::map<std::string, std::string>::iterator rptr_pos = rptr2gwy_map.end();
	std::map<std::string, std::string>::iterator gwy_pos = gwy2ip_map.end();
	char temp[CALL_SIZE + 1];

	memset(arearp_cs, ' ', CALL_SIZE);
	arearp_cs[CALL_SIZE] = '\0';
	memset(zonerp_cs, ' ', CALL_SIZE);
	zonerp_cs[CALL_SIZE] = '\0';
	*mod = ' ';

	/* find the user in the CACHE */
	if (RoU == 'U') {
		user_pos = user2rptr_map.find(call);
		if (user_pos != user2rptr_map.end()) {
			memcpy(arearp_cs, user_pos->second.c_str(), 7);
			*mod = user_pos->second.c_str()[7];
		} else
			return 1;
	} else if (RoU == 'R') {
		memcpy(arearp_cs, call, 7);
		*mod = call[7];
	} else {
		traceit("Invalid specification %c for RoU\n", RoU);
		return 2;
	}

	if ((*mod != 'A') && (*mod != 'B') && (*mod != 'C')) {
		traceit("Invalid module %c\n", *mod);
		return 2;
	}

	memcpy(temp, arearp_cs, 7);
	temp[7] = *mod;
	temp[CALL_SIZE] = '\0';

	rptr_pos = rptr2gwy_map.find(temp);
	if (rptr_pos != rptr2gwy_map.end()) {
		memcpy(zonerp_cs, rptr_pos->second.c_str(), CALL_SIZE);
		zonerp_cs[CALL_SIZE] = '\0';

		gwy_pos = gwy2ip_map.find(zonerp_cs);
		if (gwy_pos != gwy2ip_map.end()) {
			strncpy(ip, gwy_pos->second.c_str(),IP_SIZE);
			ip[IP_SIZE] = '\0';
			return 0;
		} else {
			/* traceit("Could not find IP for Gateway %s\n", zonerp_cs); */
			return 1;
		}
	} else {
		/* traceit("Could not find Gateway for repeater %s\n", temp); */
		return 1;
	}

	return 2;
}

static bool get_yrcall_rptr(char *call, char *arearp_cs, char *zonerp_cs, char *mod, char *ip, char RoU)
{
	pthread_mutex_lock(&irc_data_mutex);
	int rc = get_yrcall_rptr_from_cache(call, arearp_cs, zonerp_cs, mod, ip, RoU);
	pthread_mutex_unlock(&irc_data_mutex);
	if (rc == 0)
		return true;
	else if (rc == 2)
		return false;

	/* at this point, the data is not in cache */
	/* report the irc status */
	int status = ii->getConnectionState();
	// traceit("irc status=%d\n", status);
	if (status != 7) {
		traceit("Remote irc database not ready, irc status is not 7, try again\n");
		return false;
	}

	/* request data from irc server */
	if (RoU == 'U') {
		traceit("User [%s] not in local cache, try again\n", call);
		/*** YRCALL=KJ4NHFBL ***/
		if (((call[6] == 'A') || (call[6] == 'B') || (call[6] == 'C')) &&
		        (call[7] == LINK_CODE))
			traceit("If this was a gateway link request, that is ok\n");

		if (!ii->findUser(call)) {
			traceit("findUser(%s): Network error\n", call);
			return false;
		}
	} else if (RoU == 'R') {
		traceit("Repeater [%s] not in local cache, try again\n", call);
		if (!ii->findRepeater(call)) {
			traceit("findRepeater(%s): Network error\n", call);
			return false;
		}
	}

	return false;
}

/* signal catching function */
static void sigCatch(int signum)
{
	/* do NOT do any serious work here */
	if ((signum == SIGTERM) || (signum == SIGINT))
		keep_running = false;

	return;
}

/* run the main loop for g2_ircddb */
static void runit()
{
	SDSVT g2buf;
	fd_set fdset;
	struct timeval tv;

	socklen_t fromlen;
	int recvlen;
	int g2buflen;

	short i,j;

	bool result = false;
	int mycall_valid = REG_NOERROR;
	char temp_radio_user[CALL_SIZE + 1];
	char temp_mod;
	time_t t_now;

	char arearp_cs[CALL_SIZE + 1];
	char zonerp_cs[CALL_SIZE + 1];
	char ip[IP_SIZE + 1];

	char tempfile[FILENAME_MAX + 1];
	long num_recs = 0L;
	short int rec_len = 56;

	std::future<void> aprs_future, irc_data_future;

	/* START:  TEXT crap */
	bool new_group[3] = { true, true, true };
	int header_type = 0;
	short to_print[3] = { 0, 0, 0 };
	bool ABC_grp[3] = { false, false, false };
	bool C_seen[3] = { false, false, false };
	unsigned char tmp_txt[3];
	/* END:  TEXT crap */

	int ber_data[3];
	int ber_errs;

	int max_nfds = 0;

	dstar_dv_init();

	if (g2_sock > max_nfds)
		max_nfds = g2_sock;
	if (srv_sock > max_nfds)
		max_nfds = srv_sock;
	traceit("g2=%d, srv=%d, MAX+1=%d\n", g2_sock, srv_sock, max_nfds + 1);

	/* start the beacon thread */
	if (bool_send_aprs) {
		try {
			aprs_future = std::async(std::launch::async, APRSBeaconThread);
		} catch (const std::exception &e) {
			traceit("Failed to start the APRSBeaconThread. Exception: %s\n", e.what());
		}
		if (aprs_future.valid())
			traceit("APRS beacon thread started\n");
	}

	try {
		irc_data_future = std::async(std::launch::async, GetIRCDataThread);
	} catch (const std::exception &e) {
		traceit("Failed to start GetIRCDataThread. Exception: %s\n", e.what());
		keep_running = false;
	}
	if (keep_running)
		traceit("get_irc_data thread started\n");

	ii->kickWatchdog(IRCDDB_VERSION);

	while (keep_running) {
		for (i = 0; i < 3; i++) {
			/* echotest recording timed out? */
			if (recd[i].last_time != 0) {
				time(&t_now);
				if ((t_now - recd[i].last_time) > echotest_rec_timeout) {
					traceit("Inactivity on echotest recording mod %d, removing stream id=%04x\n",
						i, recd[i].streamid);

					recd[i].streamid = 0;
					recd[i].last_time = 0;
					close(recd[i].fd);
					recd[i].fd = -1;
					// traceit("Closed echotest audio file:[%s]\n", recd[i].file);

					/* START: echotest thread setup */
					try {
						std::async(std::launch::async, PlayFileThread, recd[i].file);
					} catch (const std::exception &e) {
						traceit("Failed to start echotest thread. Exception: %s\n", e.what());
						// when the echotest thread runs, it deletes the file,
						// Because the echotest thread did NOT start, we delete the file here
						unlink(recd[i].file);
					}
					/* END: echotest thread setup */
				}
			}

			/* voicemail recording timed out? */
			if (vm[i].last_time != 0) {
				time(&t_now);
				if ((t_now - vm[i].last_time) > voicemail_rec_timeout) {
					traceit("Inactivity on voicemail recording mod %d, removing stream id=%04x\n",
					        i, vm[i].streamid);

					vm[i].streamid = 0;
					vm[i].last_time = 0;
					close(vm[i].fd);
					vm[i].fd = -1;
					// traceit("Closed voicemail audio file:[%s]\n", vm[i].file);
				}
			}

			// any stream going to local repeater timed out?
			if (toRptr[i].last_time != 0) {
				time(&t_now);
				//   The stream can be from a cross-band, or from a remote system,
				//   so we could use either FROM_LOCAL_RPTR_TIMEOUT or FROM_REMOTE_G2_TIMEOUT
				//   but FROM_REMOTE_G2_TIMEOUT makes more sense, probably is a bigger number
				if ((t_now - toRptr[i].last_time) > from_remote_g2_timeout) {
					traceit("Inactivity to local rptr mod index %d, removing stream id %04x\n",
						i, toRptr[i].streamid);

					// Send end_of_audio to local repeater.
					// Let the repeater re-initialize
					end_of_audio.counter = toRptr[i].G2_COUNTER;
					if (i == 0)
						end_of_audio.vpkt.snd_term_id = 0x03;
					else if (i == 1)
						end_of_audio.vpkt.snd_term_id = 0x01;
					else
						end_of_audio.vpkt.snd_term_id = 0x02;
					end_of_audio.vpkt.streamid = toRptr[i].streamid;
					end_of_audio.vpkt.ctrl = toRptr[i].sequence | 0x40;

					for (j = 0; j < 2; j++)
						sendto(srv_sock, end_of_audio.pkt_id, 29, 0, (struct sockaddr *)&toRptr[i].band_addr, sizeof(struct sockaddr_in));

					toRptr[i].G2_COUNTER++;

					toRptr[i].streamid = 0;
					toRptr[i].adr = 0;
					toRptr[i].last_time = 0;
				}
			}

			/* any stream coming from local repeater timed out ? */
			if (band_txt[i].last_time != 0) {
				time(&t_now);
				if ((t_now - band_txt[i].last_time) > from_local_rptr_timeout) {
					/* This local stream never went to a remote system, so trace the timeout */
					if (to_remote_g2[i].toDst4.sin_addr.s_addr == 0)
						traceit("Inactivity from local rptr band %d, removing stream id %04x\n", i, band_txt[i].streamID);

					band_txt[i].streamID = 0;
					band_txt[i].flags[0] = band_txt[i].flags[1] = band_txt[i].flags[2] = 0x0;
					band_txt[i].lh_mycall[0] = '\0';
					band_txt[i].lh_sfx[0] = '\0';
					band_txt[i].lh_yrcall[0] = '\0';
					band_txt[i].lh_rpt1[0] = '\0';
					band_txt[i].lh_rpt2[0] = '\0';

					band_txt[i].last_time = 0;

					band_txt[i].txt[0] = '\0';
					band_txt[i].txt_cnt = 0;

					band_txt[i].dest_rptr[0] = '\0';

					band_txt[i].num_dv_frames = 0;
					band_txt[i].num_dv_silent_frames = 0;
					band_txt[i].num_bit_errors = 0;
				}
			}

			/* any stream from local repeater to a remote gateway timed out ? */
			if (to_remote_g2[i].toDst4.sin_addr.s_addr != 0) {
				time(&t_now);
				if ((t_now - to_remote_g2[i].last_time) > from_local_rptr_timeout) {
					traceit("Inactivity from local rptr mod %d, removing stream id %04x\n",
					        i, to_remote_g2[i].streamid);

					memset(&(to_remote_g2[i].toDst4),0,sizeof(struct sockaddr_in));
					to_remote_g2[i].streamid = 0;
					to_remote_g2[i].last_time = 0;
				}
			}
		}

		/* wait 20 ms max */
		FD_ZERO(&fdset);
		FD_SET(g2_sock, &fdset);
		FD_SET(srv_sock, &fdset);
		tv.tv_sec = 0;
		tv.tv_usec = 20000; /* 20 ms */
		(void)select(max_nfds + 1, &fdset, 0, 0, &tv);

		/* process packets coming from remote G2 */
		if (FD_ISSET(g2_sock, &fdset)) {
			fromlen = sizeof(struct sockaddr_in);
			g2buflen = recvfrom(g2_sock, g2buf.title, 56, 0, (struct sockaddr *)&fromDst4, &fromlen);

			if ( ((g2buflen == 56) || (g2buflen == 27)) &&
			      (0==memcmp(g2buf.title, "DSVT", 4)) &&
			      ((g2buf.config == 0x10) || (g2buf.config == 0x20)) &&  /* header or voiceframe */
			        (g2buf.id == 0x20)) {    /* voice type */
				if (g2buflen == 56) {

					// Find out the local repeater module IP/port
					// to send the data to
					i = g2buf.hdr.rpt1[7] - 'A';

					/* valid repeater module? */
					if (i>=0 && i<3) {
						// toRptr[i] is active if a remote system is talking to it or
						// toRptr[i] is receiving data from a cross-band
						if ((toRptr[i].last_time == 0) && (band_txt[i].last_time == 0) &&
						        ((g2buf.hdr.flag[0] == 0x00) ||
						         (g2buf.hdr.flag[0] == 0x01) || /* allow the announcements from g2_link */
						         (g2buf.hdr.flag[0] == 0x08) ||
						         (g2buf.hdr.flag[0] == 0x20) ||
						         (g2buf.hdr.flag[0] == 0x28) ||
						         (g2buf.hdr.flag[0] == 0x40))) {
							if (bool_qso_details)
								traceit("START from g2: streamID=%04x, flags=%02x:%02x:%02x, my=%.8s, sfx=%.4s, ur=%.8s, rpt1=%.8s, rpt2=%.8s, %d bytes fromIP=%s\n",
								        g2buf.streamid,
								        g2buf.hdr.flag[0], g2buf.hdr.flag[1], g2buf.hdr.flag[2],
								        g2buf.hdr.mycall,
								        g2buf.hdr.sfx, g2buf.hdr.urcall,
								        g2buf.hdr.rpt1, g2buf.hdr.rpt2,
								        g2buflen, inet_ntoa(fromDst4.sin_addr));

							memcpy(rptrbuf.pkt_id, "DSTR", 4);
							rptrbuf.counter = toRptr[i].G2_COUNTER;
							rptrbuf.flag[0] = 0x73;
							rptrbuf.flag[1] = 0x12;
							rptrbuf.nothing2[0] = 0x00;
							rptrbuf.nothing2[1] = 0x30;
							rptrbuf.vpkt.icm_id = 0x20;
							memcpy(&rptrbuf.vpkt.dst_rptr_id, g2buf.flagb, 47);
							sendto(srv_sock, rptrbuf.pkt_id, 58, 0, (struct sockaddr *)&toRptr[i].band_addr, sizeof(struct sockaddr_in));

							/* save the header */
							memcpy(toRptr[i].saved_hdr, rptrbuf.pkt_id, 58);
							toRptr[i].saved_adr = fromDst4.sin_addr.s_addr;

							/* This is the active streamid */
							toRptr[i].streamid = g2buf.streamid;
							toRptr[i].adr = fromDst4.sin_addr.s_addr;

							/* time it, in case stream times out */
							time(&toRptr[i].last_time);

							/* bump the G2 counter */
							toRptr[i].G2_COUNTER++;

							toRptr[i].sequence = rptrbuf.vpkt.ctrl;
						}
					}
				} else {
					if (g2buf.counter & 0x40) {
						if (bool_qso_details)
							traceit("END from g2: streamID=%04x, %d bytes from IP=%s\n",
								g2buf.streamid, g2buflen,inet_ntoa(fromDst4.sin_addr));
					}

					/* find out which repeater module to send the data to */
					for (i = 0; i < 3; i++) {
						/* streamid match ? */
						if ((toRptr[i].streamid==g2buf.streamid) &&
						        (toRptr[i].adr == fromDst4.sin_addr.s_addr)) {
							memcpy(rptrbuf.pkt_id, "DSTR", 4);
							rptrbuf.counter = toRptr[i].G2_COUNTER;
							rptrbuf.flag[0] = 0x73;
							rptrbuf.flag[1] = 0x12;
							rptrbuf.nothing2[0] = 0x00;
							rptrbuf.nothing2[1]= 0x13;
							rptrbuf.vpkt.icm_id = 0x20;
							memcpy(&rptrbuf.vpkt.dst_rptr_id, g2buf.flagb, 18);

							sendto(srv_sock, rptrbuf.pkt_id, 29, 0, (struct sockaddr *)&toRptr[i].band_addr, sizeof(struct sockaddr_in));

							/* timeit */
							time(&toRptr[i].last_time);

							/* bump G2 counter */
							toRptr[i].G2_COUNTER++;

							toRptr[i].sequence = rptrbuf.vpkt.ctrl;

							/* End of stream ? */
							if (g2buf.counter & 0x40) {
								/* clear the saved header */
								memset(toRptr[i].saved_hdr, 0, sizeof(toRptr[i].saved_hdr));
								toRptr[i].saved_adr = 0;

								toRptr[i].last_time = 0;
								toRptr[i].streamid = 0;
								toRptr[i].adr = 0;
							}
							break;
						}
					}

					/* no match ? */
					if ((i == 3) && bool_regen_header) {
						/* check if this a continuation of audio that timed out */

						if (g2buf.counter & 0x40)
							;  /* we do not care about end-of-QSO */
						else {
							/* for which repeater this stream has timed out ?  */
							for (i = 0; i < 3; i++) {
								/* match saved stream ? */
								if ((memcmp(toRptr[i].saved_hdr + 14, &g2buf.streamid, 2) == 0) &&
								        (toRptr[i].saved_adr == fromDst4.sin_addr.s_addr)) {
									/* repeater module is inactive ?  */
									if ((toRptr[i].last_time == 0) && (band_txt[i].last_time == 0)) {
										traceit("Re-generating header for streamID=%04x\n", g2buf.streamid);

										toRptr[i].saved_hdr[5] = (unsigned char)(toRptr[i].G2_COUNTER & 0xff);
										toRptr[i].saved_hdr[4] = (unsigned char)((toRptr[i].G2_COUNTER >> 8) & 0xff);

										/* re-generate/send the header */
										sendto(srv_sock, toRptr[i].saved_hdr, 58, 0, (struct sockaddr *)&toRptr[i].band_addr, sizeof(struct sockaddr_in));

										/* bump G2 counter */
										toRptr[i].G2_COUNTER++;

										/* send this audio packet to repeater */
										memcpy(rptrbuf.pkt_id, "DSTR", 4);
										rptrbuf.counter = toRptr[i].G2_COUNTER;
										rptrbuf.flag[0] = 0x73;
										rptrbuf.flag[1] = 0x12;
										rptrbuf.nothing2[0] = 0x00;
										rptrbuf.nothing2[1] = 0x13;
										rptrbuf.vpkt.icm_id = 0x20;
										memcpy(&rptrbuf.vpkt.dst_rptr_id, g2buf.flagb, 18);

										sendto(srv_sock, rptrbuf.pkt_id, 29, 0, (struct sockaddr *)&toRptr[i].band_addr, sizeof(struct sockaddr_in));

										/* make sure that any more audio arriving will be accepted */
										toRptr[i].streamid = g2buf.streamid;
										toRptr[i].adr = fromDst4.sin_addr.s_addr;

										/* time it, in case stream times out */
										time(&toRptr[i].last_time);

										/* bump the G2 counter */
										toRptr[i].G2_COUNTER++;

										toRptr[i].sequence = rptrbuf.vpkt.ctrl;

									}
									break;
								}
							}
						}
					}
				}
			}
			FD_CLR (g2_sock,&fdset);
		}

		/* process data coming from local repeater modules */
		if (FD_ISSET(srv_sock, &fdset)) {
			fromlen = sizeof(struct sockaddr_in);
			recvlen = recvfrom(srv_sock, rptrbuf.pkt_id, 58,  0, (struct sockaddr *)&fromRptr, &fromlen);

			/* DV */
			if ( ((recvlen == 58) || (recvlen == 29) || (recvlen == 32)) &&
			        (rptrbuf.flag[0] == 0x73) && (rptrbuf.flag[1] == 0x12) &&
			        (0 == memcmp(rptrbuf.pkt_id,"DSTR", 4)) &&
			        (rptrbuf.vpkt.icm_id == 0x20) && (rptrbuf.nothing2[0] == 0x00) &&
			        ((rptrbuf.nothing2[1] == 0x30) ||    /* 48 bytes follow */
			         (rptrbuf.nothing2[1] == 0x13) ||    /* 19 bytes follow */
			         (rptrbuf.nothing2[1] == 0x16)) ) {  /* 22 bytes follow */

				int dtmf_buf_count[3] = {0, 0, 0};
				char dtmf_buf[3][MAX_DTMF_BUF + 1] = { {""}, {""}, {""} };
				int dtmf_last_frame[3] = { 0, 0, 0 };
				unsigned int dtmf_counter[3] = { 0, 0, 0 };
				if (recvlen == 58) {
					
					if (bool_qso_details)
						traceit("START from rptr: cntr=%04x, streamID=%04x, flags=%02x:%02x:%02x, my=%.8s, sfx=%.4s, ur=%.8s, rpt1=%.8s, rpt2=%.8s, %d bytes fromIP=%s\n",
						        rptrbuf.counter,
						        rptrbuf.vpkt.streamid,
						        rptrbuf.vpkt.hdr.flag[0], rptrbuf.vpkt.hdr.flag[1], rptrbuf.vpkt.hdr.flag[2],
						        rptrbuf.vpkt.hdr.mycall, rptrbuf.vpkt.hdr.sfx, rptrbuf.vpkt.hdr.urcall,
						        rptrbuf.vpkt.hdr.rpt2, rptrbuf.vpkt.hdr.rpt1, recvlen, inet_ntoa(fromRptr.sin_addr));

					if ((memcmp(rptrbuf.vpkt.hdr.rpt2, OWNER.c_str(), 7) == 0) &&  /* rpt1 is this repeater */
					        /*** (memcmp(rptrbuf + 44, OWNER, 7) != 0) && ***/  /* MYCALL is NOT this repeater */
					        ((rptrbuf.vpkt.hdr.flag[0] == 0x00) ||                 /* normal */
					         (rptrbuf.vpkt.hdr.flag[0] == 0x08) ||                 /* EMR */
					         (rptrbuf.vpkt.hdr.flag[0] == 0x20) ||                 /* BREAK */
					         (rptrbuf.vpkt.hdr.flag[0] == 0x28))) {                /* EMR + BREAK */

						i = rptrbuf.vpkt.hdr.rpt2[7] - 'A';

						if (i>=0  && i<3) {
							dtmf_last_frame[i] = 0;
							dtmf_counter[i] = 0;
							memset(dtmf_buf[i], 0, sizeof(dtmf_buf[i]));
							dtmf_buf_count[i] = 0;

							/* Initialize the LAST HEARD data for the band */

							band_txt[i].streamID = rptrbuf.vpkt.streamid;

							memcpy(band_txt[i].flags, rptrbuf.vpkt.hdr.flag, 3);

							memcpy(band_txt[i].lh_mycall, rptrbuf.vpkt.hdr.mycall, 8);
							band_txt[i].lh_mycall[8] = '\0';

							memcpy(band_txt[i].lh_sfx, rptrbuf.vpkt.hdr.sfx, 4);
							band_txt[i].lh_sfx[4] = '\0';

							memcpy(band_txt[i].lh_yrcall, rptrbuf.vpkt.hdr.urcall, 8);
							band_txt[i].lh_yrcall[8] = '\0';

							memcpy(band_txt[i].lh_rpt1, rptrbuf.vpkt.hdr.rpt2, 8);
							band_txt[i].lh_rpt1[8] = '\0';

							memcpy(band_txt[i].lh_rpt2, rptrbuf.vpkt.hdr.rpt1, 8);
							band_txt[i].lh_rpt2[8] = '\0';

							time(&band_txt[i].last_time);

							band_txt[i].txt[0] = '\0';
							band_txt[i].txt_cnt = 0;
							band_txt[i].txt_stats_sent = false;

							band_txt[i].dest_rptr[0] = '\0';

							/* try to process GPS mode: GPRMC and ID */
							band_txt[i].temp_line[0] = '\0';
							band_txt[i].temp_line_cnt = 0;
							band_txt[i].gprmc[0] = '\0';
							band_txt[i].gpid[0] = '\0';
							band_txt[i].is_gps_sent = false;
							// band_txt[i].gps_last_time = 0; DO NOT reset it

							new_group[i] = true;
							to_print[i] = 0;
							ABC_grp[i] = false;

							band_txt[i].num_dv_frames = 0;
							band_txt[i].num_dv_silent_frames = 0;
							band_txt[i].num_bit_errors = 0;

							/* select the band for aprs processing, and lock on the stream ID */
							if (bool_send_aprs)
								aprs->SelectBand(i, rptrbuf.vpkt.streamid);
						}
					}

					/* Is MYCALL valid ? */
					memset(temp_radio_user, ' ', 8);
					memcpy(temp_radio_user, rptrbuf.vpkt.hdr.mycall, 8);
					temp_radio_user[8] = '\0';

					mycall_valid = regexec(&preg, temp_radio_user, 0, NULL, 0);

					if (mycall_valid == REG_NOERROR)
						; // traceit("MYCALL [%s] passed IRC expression validation\n", temp_radio_user);
					else {
						if (mycall_valid == REG_NOMATCH)
							traceit("MYCALL [%s] failed IRC expression validation\n", temp_radio_user);
						else
							traceit("Failed to validate MYCALL [%s], regexec error=%d\n", temp_radio_user, mycall_valid);
					}

					/* send data g2_link */
					if (mycall_valid == REG_NOERROR)
						sendto(srv_sock, rptrbuf.pkt_id, recvlen, 0, (struct sockaddr *)&plug, sizeof(struct sockaddr_in));

					if ((mycall_valid == REG_NOERROR) &&
					        (memcmp(rptrbuf.vpkt.hdr.urcall, "XRF", 3) != 0) &&             /* not a reflector */
					        (memcmp(rptrbuf.vpkt.hdr.urcall, "REF", 3) != 0) &&             /* not a reflector */
					        (memcmp(rptrbuf.vpkt.hdr.urcall, "DCS", 3) != 0) &&             /* not a reflector */
					        (rptrbuf.vpkt.hdr.urcall[0] != ' ') &&                          /* must have something */
					        (memcmp(rptrbuf.vpkt.hdr.urcall, "CQCQCQ", 6) != 0)) {          /* urcall is NOT CQCQCQ */
						if ((rptrbuf.vpkt.hdr.urcall[0] == '/') &&                          /* urcall starts with a slash */
						        (memcmp(rptrbuf.vpkt.hdr.rpt2, OWNER.c_str(), 7) == 0) &&   /* rpt1 is this repeater */
						        ((rptrbuf.vpkt.hdr.rpt2[7] == 'A') ||
						         (rptrbuf.vpkt.hdr.rpt2[7] == 'B') ||
						         (rptrbuf.vpkt.hdr.rpt2[7] == 'C')) &&                      /* mod is A,B,C */
						        (memcmp(rptrbuf.vpkt.hdr.rpt1, OWNER.c_str(), 7) == 0) &&   /* rpt2 is this repeater */
						        (rptrbuf.vpkt.hdr.rpt1[7] == 'G') &&                        /* local Gateway */
						        /*** (memcmp(rptrbuf + 44, OWNER, 7) != 0) && ***/          /* mycall is NOT this repeater */

						        ((rptrbuf.vpkt.hdr.flag[0] == 0x00) ||                         /* normal */
						         (rptrbuf.vpkt.hdr.flag[0] == 0x08) ||                         /* EMR */
						         (rptrbuf.vpkt.hdr.flag[0] == 0x20) ||                         /* BK */
						         (rptrbuf.vpkt.hdr.flag[0] == 0x28))                           /* EMR + BK */
						   ) {
							if (memcmp(rptrbuf.vpkt.hdr.urcall+1, OWNER.c_str(), 6) != 0) {   /* the value after the slash in urcall, is NOT this repeater */
								i = rptrbuf.vpkt.hdr.rpt2[7] - 'A';

								if (i>=0 && i<3) {
									/* one radio user on a repeater module at a time */
									if (to_remote_g2[i].toDst4.sin_addr.s_addr == 0) {
										/* YRCALL=/repeater + mod */
										/* YRCALL=/KJ4NHFB */

										memset(temp_radio_user, ' ', 8);
										memcpy(temp_radio_user, rptrbuf.vpkt.hdr.urcall+1, 6);
										temp_radio_user[6] = ' ';
										temp_radio_user[7] = rptrbuf.vpkt.hdr.urcall[7];
										if (temp_radio_user[7] == ' ')
											temp_radio_user[7] = 'A';
										temp_radio_user[CALL_SIZE] = '\0';

										result = get_yrcall_rptr(temp_radio_user, arearp_cs, zonerp_cs, &temp_mod, ip, 'R');
										if (result) { /* it is a repeater */
											/* set the destination */
											to_remote_g2[i].streamid = rptrbuf.vpkt.streamid;
											memset(&to_remote_g2[i].toDst4, 0, sizeof(struct sockaddr_in));
											to_remote_g2[i].toDst4.sin_family = AF_INET;
											to_remote_g2[i].toDst4.sin_port = htons(g2_external.port);
											to_remote_g2[i].toDst4.sin_addr.s_addr = inet_addr(ip);

											memcpy(g2buf.title, "DSVT", 4);
											g2buf.config = 0x10;
											g2buf.flaga[0] = g2buf.flaga[1] = g2buf.flaga[2] = 0x00;
											g2buf.id =  rptrbuf.vpkt.icm_id;
											g2buf.flagb[0] = rptrbuf.vpkt.dst_rptr_id;
											g2buf.flagb[1] = rptrbuf.vpkt.snd_rptr_id;
											g2buf.flagb[2] = rptrbuf.vpkt.snd_term_id;
											memcpy(&g2buf.streamid, &rptrbuf.vpkt.streamid, 44);
											/* set rpt1 */
											memset(g2buf.hdr.rpt1, ' ', 8);
											memcpy(g2buf.hdr.rpt1, arearp_cs, strlen(arearp_cs));
											g2buf.hdr.rpt1[7] = temp_mod;
											/* set rpt2 */
											memset(g2buf.hdr.rpt2, ' ', 8);
											memcpy(g2buf.hdr.rpt2, zonerp_cs, strlen(zonerp_cs));
											g2buf.hdr.rpt2[7] = 'G';
											/* set yrcall, can NOT let it be slash and repeater + module */
											memcpy(g2buf.hdr.urcall, "CQCQCQ  ", 8);

											/* set PFCS */
											calcPFCS(g2buf.title, 56);

											/*
											   The remote repeater has been set, lets fill in the dest_rptr
											   so that later we can send that to the LIVE web site
											*/
											memcpy(band_txt[i].dest_rptr, g2buf.hdr.rpt1, 8);
											band_txt[i].dest_rptr[CALL_SIZE] = '\0';

											/* send to remote gateway */
											for (j = 0; j < 5; j++)
												sendto(g2_sock, g2buf.title, 56, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));

											traceit("Routing to IP=%s, streamID=%04x, my=%.8s, sfx=%.4s, ur=%.8s, rpt1=%.8s, rpt2=%.8s, %d bytes\n",
											        inet_ntoa(to_remote_g2[i].toDst4.sin_addr),
											        g2buf.streamid, g2buf.hdr.mycall,
											        g2buf.hdr.sfx, g2buf.hdr.urcall,
											        g2buf.hdr.rpt1, &g2buf.hdr.rpt2,
											        56);

											time(&(to_remote_g2[i].last_time));
										}
									}
								}
							}
						} else if ((memcmp(rptrbuf.vpkt.hdr.urcall, OWNER.c_str(), 7) != 0) &&	/* urcall is not this repeater */
						           (memcmp(rptrbuf.vpkt.hdr.rpt2, OWNER.c_str(), 7) == 0) &&	/* rpt1 is this repeater */
						           ((rptrbuf.vpkt.hdr.rpt2[7] == 'A') ||
						            (rptrbuf.vpkt.hdr.rpt2[7] == 'B') ||
						            (rptrbuf.vpkt.hdr.rpt2[7] == 'C')) &&						/* mod is A,B,C */
						           (memcmp(rptrbuf.vpkt.hdr.rpt1, OWNER.c_str(), 7) == 0) &&	/* rpt2 is this repeater */
						           (rptrbuf.vpkt.hdr.rpt1[7] == 'G') &&							/* local Gateway */
						           /*** (memcmp(rptrbuf + 44, OWNER, 7) != 0) && ***/			/* mycall is NOT this repeater */

						           ((rptrbuf.vpkt.hdr.flag[0] == 0x00) ||						/* normal */
						            (rptrbuf.vpkt.hdr.flag[0] == 0x08) ||						/* EMR */
						            (rptrbuf.vpkt.hdr.flag[0] == 0x20) ||						/* BK */
						            (rptrbuf.vpkt.hdr.flag[0] == 0x28))							/* EMR + BK */
						          ) {

							memset(temp_radio_user, ' ', 8);
							memcpy(temp_radio_user, rptrbuf.vpkt.hdr.urcall, 8);
							temp_radio_user[8] = '\0';
							result = get_yrcall_rptr(temp_radio_user, arearp_cs, zonerp_cs, &temp_mod, ip, 'U');
							if (result) {
								/* destination is a remote system */
								if (memcmp(zonerp_cs, OWNER.c_str(), 7) != 0) {
									i = rptrbuf.vpkt.hdr.rpt2[7] - 'A';

									if (i>=0 && i<3) {
										/* one radio user on a repeater module at a time */
										if (to_remote_g2[i].toDst4.sin_addr.s_addr == 0) {
											/* set the destination */
											to_remote_g2[i].streamid = rptrbuf.vpkt.streamid;
											memset(&to_remote_g2[i].toDst4, 0, sizeof(struct sockaddr_in));
											to_remote_g2[i].toDst4.sin_family = AF_INET;
											to_remote_g2[i].toDst4.sin_port = htons(g2_external.port);
											to_remote_g2[i].toDst4.sin_addr.s_addr = inet_addr(ip);

											memcpy(g2buf.title, "DSVT", 4);
											g2buf.config = 0x10;
											g2buf.flaga[0] = g2buf.flaga[1] = g2buf.flaga[2] = 0x00;
											g2buf.id = rptrbuf.vpkt.icm_id;
											g2buf.flagb[0] = rptrbuf.vpkt.dst_rptr_id;
											g2buf.flagb[1] = rptrbuf.vpkt.snd_rptr_id;
											g2buf.flagb[2] = rptrbuf.vpkt.snd_term_id;
											memcpy(&g2buf.streamid, &rptrbuf.vpkt.streamid, 44);
											/* set rpt1 */
											memset(g2buf.hdr.rpt1, ' ', 8);
											memcpy(g2buf.hdr.rpt1, arearp_cs, strlen(arearp_cs));
											g2buf.hdr.rpt1[7] = temp_mod;
											/* set rpt2 */
											memset(g2buf.hdr.rpt2, ' ', 8);
											memcpy(g2buf.hdr.rpt2, zonerp_cs, strlen(zonerp_cs));
											g2buf.hdr.rpt2[7] = 'G';
											/* set PFCS */
											calcPFCS(g2buf.title, 56);

											// The remote repeater has been set, lets fill in the dest_rptr
											// so that later we can send that to the LIVE web site
											memcpy(band_txt[i].dest_rptr, g2buf.hdr.rpt1, 8);
											band_txt[i].dest_rptr[CALL_SIZE] = '\0';

											/* send to remote gateway */
											for (j = 0; j < 5; j++)
												sendto(g2_sock, g2buf.title, 56, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));

											traceit("Routing to IP=%s, streamID=%04x, my=%.8s, sfx=%.4s, ur=%.8s, rpt1=%.8s, rpt2=%.8s, %d bytes\n",
											        inet_ntoa(to_remote_g2[i].toDst4.sin_addr),
											        g2buf.streamid, g2buf.hdr.mycall,
											        g2buf.hdr.sfx, g2buf.hdr.urcall,
											        g2buf.hdr.rpt1, g2buf.hdr.rpt2,
											        56);

											time(&(to_remote_g2[i].last_time));
										}
									}
								} else {
									i = rptrbuf.vpkt.hdr.rpt2[7] - 'A';

									if (i>=0 && i<3) {
										/* the user we are trying to contact is on our gateway */
										/* make sure they are on a different module */
										if (temp_mod != rptrbuf.vpkt.hdr.rpt2[7]) {
											/*
											   The remote repeater has been set, lets fill in the dest_rptr
											   so that later we can send that to the LIVE web site
											*/
											memcpy(band_txt[i].dest_rptr, rptrbuf.vpkt.hdr.rpt1, 8);
											band_txt[i].dest_rptr[7] = temp_mod;
											band_txt[i].dest_rptr[8] = '\0';

											i = temp_mod - 'A';

											/* valid destination repeater module? */
											if (i>=0 && i<3) {
												/*
												   toRptr[i] :    receiving from a remote system or cross-band
												   band_txt[i] :  local RF is talking.
												*/
												if ((toRptr[i].last_time == 0) && (band_txt[i].last_time == 0)) {
													traceit("CALLmode cross-banding from mod %c to %c\n",  rptrbuf.vpkt.hdr.rpt2[7], temp_mod);

													rptrbuf.vpkt.hdr.rpt1[7] = temp_mod;
													rptrbuf.vpkt.hdr.rpt2[7] = 'G';
													calcPFCS(rptrbuf.pkt_id, 58);

													sendto(srv_sock, rptrbuf.pkt_id, 58, 0, (struct sockaddr *)&toRptr[i].band_addr, sizeof(struct sockaddr_in));

													/* This is the active streamid */
													toRptr[i].streamid = rptrbuf.vpkt.streamid;
													toRptr[i].adr = fromRptr.sin_addr.s_addr;

													/* time it, in case stream times out */
													time(&toRptr[i].last_time);

													/* bump the G2 counter */
													toRptr[i].G2_COUNTER++;

													toRptr[i].sequence = rptrbuf.vpkt.ctrl;
												}
											}
										} else
											traceit("icom rule: no routing from %.8s to %s%c\n", rptrbuf.vpkt.hdr.rpt2, arearp_cs, temp_mod);
									}
								}
							}
						}
					} else if ((rptrbuf.vpkt.hdr.urcall[7] == '0') &&
					           (rptrbuf.vpkt.hdr.urcall[6] == CLEAR_VM_CODE) &&
					           (rptrbuf.vpkt.hdr.urcall[0] == ' ')) {
						i = rptrbuf.vpkt.hdr.rpt2[7] - 'A';

						if (i>=0 && i<3) {
							/* voicemail file is closed */
							if ((vm[i].fd == -1) && (vm[i].file[0] != '\0')) {
								unlink(vm[i].file);
								traceit("removed voicemail file: %s\n", vm[i].file);
								vm[i].file[0] = '\0';
							} else
								traceit("No voicemail to clear or still recording\n");
						}
					} else if ((rptrbuf.vpkt.hdr.urcall[7] == '0') &&
					           (rptrbuf.vpkt.hdr.urcall[6] == RECALL_VM_CODE) &&
					           (rptrbuf.vpkt.hdr.urcall[0] == ' ')) {
						i = -1;
						switch (rptrbuf.vpkt.hdr.rpt2[7]) {
							case 'A':
								i = 0;
								break;
							case 'B':
								i = 1;
								break;
							case 'C':
								i = 2;
								break;
						}

						if (i >= 0) {
							/* voicemail file is closed */
							if ((vm[i].fd == -1) && (vm[i].file[0] != '\0')) {
								try {
									std::async(std::launch::async, PlayFileThread, vm[i].file);
								} catch (const std::exception &e) {
									traceit("Filed to start voicemail playback. Exception: %s\n", e.what());
								}
							} else
								traceit("No voicemail to recall or still recording\n");
						}
					} else if ((rptrbuf.vpkt.hdr.urcall[7] == '0') &&
					           (rptrbuf.vpkt.hdr.urcall[6] == STORE_VM_CODE) &&
					           (rptrbuf.vpkt.hdr.urcall[0] == ' ')) {
						i = rptrbuf.vpkt.hdr.rpt2[7] - 'A';

						if (i>=0 && i<3) {
							if (vm[i].fd >= 0)
								traceit("Already recording for voicemail on mod %d\n", i);
							else {
								memset(tempfile, '\0', sizeof(tempfile));
								snprintf(tempfile, FILENAME_MAX, "%s/%c_%s",
								         echotest_dir.c_str(),
								         rptrbuf.vpkt.hdr.rpt2[7],
								         "voicemail.dat");

								vm[i].fd = open(tempfile,
								                O_CREAT | O_WRONLY | O_TRUNC | O_APPEND,
								                S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
								if (vm[i].fd < 0)
									traceit("Failed to create file %s for voicemail\n", tempfile);
								else {
									strcpy(vm[i].file, tempfile);
									traceit("Recording mod %c for voicemail into file:[%s]\n",
									        rptrbuf.vpkt.hdr.rpt2[7],
									        vm[i].file);

									time(&vm[i].last_time);
									vm[i].streamid = rptrbuf.vpkt.streamid;

									memcpy(recbuf.title, "DSVT", 4);
									recbuf.config = 0x10;
									recbuf.flaga[0] = recbuf.flaga[1] = recbuf.flaga[2] = 0;
									recbuf.id =  rptrbuf.vpkt.icm_id;
									recbuf.flagb[0] = rptrbuf.vpkt.dst_rptr_id;
									recbuf.flagb[1] = rptrbuf.vpkt.snd_rptr_id;
									recbuf.flagb[2] = rptrbuf.vpkt.snd_term_id;
									memcpy(&recbuf.streamid, &rptrbuf.vpkt.streamid, 44);
									memset(recbuf.hdr.rpt1, ' ', 8);
									memcpy(recbuf.hdr.rpt1, OWNER.c_str(), OWNER.length());
									recbuf.hdr.rpt1[7] = rptrbuf.vpkt.hdr.rpt2[7];
									memset(recbuf.hdr.rpt2, ' ', 8);
									memcpy(recbuf.hdr.rpt2,  OWNER.c_str(), OWNER.length());
									recbuf.hdr.rpt2[7] = 'G';
									memcpy(recbuf.hdr.urcall, "CQCQCQ  ", 8);

									calcPFCS(recbuf.title, 56);

									rec_len = 56;
									(void)write(vm[i].fd, "DVTOOL", 6);
									(void)write(vm[i].fd, &num_recs, 4);
									(void)write(vm[i].fd, &rec_len, 2);
									(void)write(vm[i].fd, &recbuf, rec_len);
								}
							}
						}
					} else if ((rptrbuf.vpkt.hdr.urcall[7] == ECHO_CODE) && (rptrbuf.vpkt.hdr.urcall[0] == ' ')) {
						i = rptrbuf.vpkt.hdr.rpt2[7] - 'A';

						if (i>=0 && i<3) {
							if (recd[i].fd >= 0)
								traceit("Already recording for echotest on mod %d\n", i);
							else {
								memset(tempfile, '\0', sizeof(tempfile));
								snprintf(tempfile, FILENAME_MAX, "%s/%c_%s", echotest_dir.c_str(),
														rptrbuf.vpkt.hdr.rpt2[7], "echotest.dat");

								recd[i].fd = open(tempfile,
								                  O_CREAT | O_WRONLY | O_EXCL | O_TRUNC | O_APPEND,
								                  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
								if (recd[i].fd < 0)
									traceit("Failed to create file %s for echotest\n", tempfile);
								else {
									strcpy(recd[i].file, tempfile);
									traceit("Recording mod %c for echotest into file:[%s]\n",
														rptrbuf.vpkt.hdr.rpt2[7], recd[i].file);

									time(&recd[i].last_time);
									recd[i].streamid = rptrbuf.vpkt.streamid;

									memcpy(recbuf.title, "DSVT", 4);
									recbuf.config = 0x10;
									recbuf.id =  rptrbuf.vpkt.icm_id;
									recbuf.flaga[0] = recbuf.flaga[1] = recbuf.flaga[2] = 0;
									recbuf.flagb[0] = rptrbuf.vpkt.dst_rptr_id;
									recbuf.flagb[1] = rptrbuf.vpkt.snd_rptr_id;
									recbuf.flagb[2] = rptrbuf.vpkt.snd_term_id;
									memcpy(&recbuf.streamid, &rptrbuf.vpkt.streamid, 44);
									memset(recbuf.hdr.rpt1, ' ', 8);
									memcpy(recbuf.hdr.rpt1, OWNER.c_str(), OWNER.length());
									recbuf.hdr.rpt1[7] = rptrbuf.vpkt.hdr.rpt2[7];
									memset(recbuf.hdr.rpt2, ' ', 8);
									memcpy(recbuf.hdr.rpt2,  OWNER.c_str(), OWNER.length());
									recbuf.hdr.rpt2[7] = 'G';
									memcpy(recbuf.hdr.urcall, "CQCQCQ  ", 8);

									calcPFCS(recbuf.title, 56);

									rec_len = 56;
									(void)write(recd[i].fd, "DVTOOL", 6);
									(void)write(recd[i].fd, &num_recs, 4);
									(void)write(recd[i].fd, &rec_len, 2);
									(void)write(recd[i].fd, &recbuf, rec_len);
								}
							}
						}
					/* check for cross-banding */
					} else if (0 == (memcmp(rptrbuf.vpkt.hdr.urcall, "CQCQCQ", 6)) &&			/* yrcall is CQCQCQ */
							(0 == memcmp(rptrbuf.vpkt.hdr.rpt1, OWNER.c_str(), 7)) && 	/* rpt1 is this repeater */
							(0 == memcmp(rptrbuf.vpkt.hdr.rpt2, OWNER.c_str(), 7)) &&	/* rpt2 is this repeater */
							((rptrbuf.vpkt.hdr.rpt2[7] == 'A') ||
							 (rptrbuf.vpkt.hdr.rpt2[7] == 'B') ||
							 (rptrbuf.vpkt.hdr.rpt2[7] == 'C')) &&                   /* mod of rpt1 is A,B,C */
							((rptrbuf.vpkt.hdr.rpt1[7] == 'A') ||
							 (rptrbuf.vpkt.hdr.rpt1[7] == 'B') ||
							 (rptrbuf.vpkt.hdr.rpt1[7] == 'C')) &&           /* !!! usually a G of rpt2, but we see A,B,C */
							(rptrbuf.vpkt.hdr.rpt1[7] != rptrbuf.vpkt.hdr.rpt2[7])) {  /* cross-banding? make sure NOT the same */
						i = rptrbuf.vpkt.hdr.rpt2[7] - 'A';

						if (i>=0 && i<3) {
							// The remote repeater has been set, lets fill in the dest_rptr
							// so that later we can send that to the LIVE web site
							memcpy(band_txt[i].dest_rptr, rptrbuf.vpkt.hdr.rpt1, 8);
							band_txt[i].dest_rptr[8] = '\0';
						}

						i = rptrbuf.vpkt.hdr.rpt1[7] - 'A';

						/* valid destination repeater module? */
						if (i>=0 && i<3) {
							// toRptr[i] :    receiving from a remote system or cross-band
							// band_txt[i] :  local RF is talking.
							if ((toRptr[i].last_time == 0) && (band_txt[i].last_time == 0)) {
								traceit("ZONEmode cross-banding from mod %c to %c\n",  rptrbuf.vpkt.hdr.rpt2[7], rptrbuf.vpkt.hdr.rpt1[7]);

								rptrbuf.vpkt.hdr.rpt2[7] = 'G';
								calcPFCS(rptrbuf.pkt_id, 58);

								sendto(srv_sock, rptrbuf.pkt_id, 58, 0, (struct sockaddr *)&toRptr[i].band_addr, sizeof(struct sockaddr_in));

								/* This is the active streamid */
								toRptr[i].streamid = rptrbuf.vpkt.streamid;
								toRptr[i].adr = fromRptr.sin_addr.s_addr;

								/* time it, in case stream times out */
								time(&toRptr[i].last_time);

								/* bump the G2 counter */
								toRptr[i].G2_COUNTER ++;

								toRptr[i].sequence = rptrbuf.vpkt.ctrl;
							}
						}
					}
				} else {
					for (i = 0; i < 3; i++) {
						if (band_txt[i].streamID == rptrbuf.vpkt.streamid) {
							time(&band_txt[i].last_time);

							if ((rptrbuf.vpkt.ctrl & 0x40) != 0) {
								if (dtmf_buf_count[i] > 0) {
									dtmf_file = dtmf_dir;
									dtmf_file.push_back('/');
									dtmf_file.push_back('A'+i);
									dtmf_file += "_mod_DTMF_NOTIFY";
									if (bool_dtmf_debug)
										traceit("Saving dtmfs=[%s] into file: [%s]\n", dtmf_buf[i], dtmf_file.c_str());
									FILE *dtmf_fp = fopen(dtmf_file.c_str(), "w");
									if (dtmf_fp) {
										fprintf(dtmf_fp, "%s\n%s", dtmf_buf[i], band_txt[i].lh_mycall);
										fclose(dtmf_fp);
									} else
										traceit("Failed to create dtmf file %s\n", dtmf_file.c_str());


									memset(dtmf_buf[i], 0, sizeof(dtmf_buf[i]));
									dtmf_buf_count[i] = 0;
									dtmf_counter[i] = 0;
									dtmf_last_frame[i] = 0;
								}

								ii->sendHeardWithTXStats(band_txt[i].lh_mycall,
								                         band_txt[i].lh_sfx,
								                         (strstr(band_txt[i].lh_yrcall,"REF") == NULL)?band_txt[i].lh_yrcall:"CQCQCQ  ",
								                         band_txt[i].lh_rpt1,
								                         band_txt[i].lh_rpt2,
								                         band_txt[i].flags[0],
								                         band_txt[i].flags[1],
								                         band_txt[i].flags[2],
								                         band_txt[i].num_dv_frames,
								                         band_txt[i].num_dv_silent_frames,
								                         band_txt[i].num_bit_errors);

								band_txt[i].streamID = 0;
								band_txt[i].flags[0] = band_txt[i].flags[1] = band_txt[i].flags[2] = 0;
								band_txt[i].lh_mycall[0] = '\0';
								band_txt[i].lh_sfx[0] = '\0';
								band_txt[i].lh_yrcall[0] = '\0';
								band_txt[i].lh_rpt1[0] = '\0';
								band_txt[i].lh_rpt2[0] = '\0';

								band_txt[i].last_time = 0;

								band_txt[i].txt[0] = '\0';
								band_txt[i].txt_cnt = 0;

								band_txt[i].dest_rptr[0] = '\0';

								band_txt[i].num_dv_frames = 0;
								band_txt[i].num_dv_silent_frames = 0;
								band_txt[i].num_bit_errors = 0;

							} else {
								ber_errs = dstar_dv_decode(rptrbuf.vpkt.vasd.voice, ber_data);
								if (ber_data[0] == 0xf85)
									band_txt[i].num_dv_silent_frames++;
								band_txt[i].num_bit_errors += ber_errs;
								band_txt[i].num_dv_frames++;

								if ((ber_data[0] & 0x0ffc) == 0xfc0) {
									dtmf_digit = (ber_data[0] & 0x03) | ((ber_data[2] & 0x60) >> 3);
									if (dtmf_counter[i] > 0) {
										if (dtmf_last_frame[i] != dtmf_digit)
											dtmf_counter[i] = 0;
									}
									dtmf_last_frame[i] = dtmf_digit;
									dtmf_counter[i] ++;

									if ((dtmf_counter[i] == 5) && (dtmf_digit >= 0) && (dtmf_digit <= 15)) {
										if (dtmf_buf_count[i] < MAX_DTMF_BUF) {
											const char *dtmf_chars = "147*2580369#ABCD";
											dtmf_buf[i][ dtmf_buf_count[i] ] = dtmf_chars[dtmf_digit];
											dtmf_buf_count[i] ++;
										}
									}
									const unsigned char silence[9] = { 0x4e,0x8d,0x32,0x88,0x26,0x1a,0x3f,0x61,0xe8 };
									memcpy(rptrbuf.vpkt.vasd.voice, silence, 9);
								} else
									dtmf_counter[i] = 0;
							}
							break;
						}
					}

					if (recvlen == 29)
						memcpy(tmp_txt, rptrbuf.vpkt.vasd.text, 3);
					else
						memcpy(tmp_txt, rptrbuf.vpkt.vasd1.text, 3);

					// traceit("%x%x%x\n", tmp_txt[0], tmp_txt[1], tmp_txt[2]);
					// traceit("%c%c%c\n", tmp_txt[0] ^ 0x70, tmp_txt[1] ^ 0x4f, tmp_txt[2] ^ 0x93);

					/* extract 20-byte RADIO ID */
					if ((tmp_txt[0] != 0x55) || (tmp_txt[1] != 0x2d) || (tmp_txt[2] != 0x16)) {
						// traceit("%x%x%x\n", tmp_txt[0], tmp_txt[1], tmp_txt[2]);
						// traceit("%c%c%c\n", tmp_txt[0] ^ 0x70, tmp_txt[1] ^ 0x4f, tmp_txt[2] ^ 0x93);

						for (i = 0; i < 3; i++) {
							if (band_txt[i].streamID == rptrbuf.vpkt.streamid) {
								if (new_group[i]) {
									tmp_txt[0] = tmp_txt[0] ^ 0x70;
									header_type = tmp_txt[0] & 0xf0;

									if ((header_type == 0x50) ||  /* header  */
									        (header_type == 0xc0)) {  /* squelch */
										new_group[i] = false;
										to_print[i] = 0;
										ABC_grp[i] = false;
									} else if (header_type == 0x30) { /* GPS or GPS id or APRS */
										new_group[i] = false;
										to_print[i] = tmp_txt[0] & 0x0f;
										ABC_grp[i] = false;
										if (to_print[i] > 5)
											to_print[i] = 5;
										else if (to_print[i] < 1)
											to_print[i] = 1;

										if ((to_print[i] > 1) && (to_print[i] <= 5)) {
											/* something went wrong? all bets are off */
											if (band_txt[i].temp_line_cnt > 200) {
												traceit("Reached the limit in the OLD gps mode\n");
												band_txt[i].temp_line[0] = '\0';
												band_txt[i].temp_line_cnt = 0;
											}

											/* fresh GPS string, re-initialize */
											if ((to_print[i] == 5) && ((tmp_txt[1] ^ 0x4f) == '$')) {
												band_txt[i].temp_line[0] = '\0';
												band_txt[i].temp_line_cnt = 0;
											}

											/* do not copy CR, NL */
											if (((tmp_txt[1] ^ 0x4f) != '\r') && ((tmp_txt[1] ^ 0x4f) != '\n')) {
												band_txt[i].temp_line[band_txt[i].temp_line_cnt] = tmp_txt[1] ^ 0x4f;
												band_txt[i].temp_line_cnt++;
											}
											if (((tmp_txt[2] ^ 0x93) != '\r') && ((tmp_txt[2] ^ 0x93) != '\n')) {
												band_txt[i].temp_line[band_txt[i].temp_line_cnt] = tmp_txt[2] ^ 0x93;
												band_txt[i].temp_line_cnt++;
											}

											if (((tmp_txt[1] ^ 0x4f) == '\r') || ((tmp_txt[2] ^ 0x93) == '\r')) {
												if (memcmp(band_txt[i].temp_line, "$GPRMC", 6) == 0) {
													memcpy(band_txt[i].gprmc, band_txt[i].temp_line, band_txt[i].temp_line_cnt);
													band_txt[i].gprmc[band_txt[i].temp_line_cnt] = '\0';
												} else if (band_txt[i].temp_line[0] != '$') {
													memcpy(band_txt[i].gpid, band_txt[i].temp_line, band_txt[i].temp_line_cnt);
													band_txt[i].gpid[band_txt[i].temp_line_cnt] = '\0';
													if (bool_send_aprs && !band_txt[i].is_gps_sent)
														gps_send(i);
												}
												band_txt[i].temp_line[0] = '\0';
												band_txt[i].temp_line_cnt = 0;
											} else if (((tmp_txt[1] ^ 0x4f) == '\n') || ((tmp_txt[2] ^ 0x93) == '\n')) {
												band_txt[i].temp_line[0] = '\0';
												band_txt[i].temp_line_cnt = 0;
											}
											to_print[i] -= 2;
										} else {
											/* something went wrong? all bets are off */
											if (band_txt[i].temp_line_cnt > 200) {
												traceit("Reached the limit in the OLD gps mode\n");
												band_txt[i].temp_line[0] = '\0';
												band_txt[i].temp_line_cnt = 0;
											}

											/* do not copy CR, NL */
											if (((tmp_txt[1] ^ 0x4f) != '\r') && ((tmp_txt[1] ^ 0x4f) != '\n')) {
												band_txt[i].temp_line[band_txt[i].temp_line_cnt] = tmp_txt[1] ^ 0x4f;
												band_txt[i].temp_line_cnt++;
											}

											if ((tmp_txt[1] ^ 0x4f) == '\r') {
												if (memcmp(band_txt[i].temp_line, "$GPRMC", 6) == 0) {
													memcpy(band_txt[i].gprmc, band_txt[i].temp_line, band_txt[i].temp_line_cnt);
													band_txt[i].gprmc[band_txt[i].temp_line_cnt] = '\0';
												} else if (band_txt[i].temp_line[0] != '$') {
													memcpy(band_txt[i].gpid, band_txt[i].temp_line, band_txt[i].temp_line_cnt);
													band_txt[i].gpid[band_txt[i].temp_line_cnt] = '\0';
													if (bool_send_aprs && !band_txt[i].is_gps_sent)
														gps_send(i);
												}
												band_txt[i].temp_line[0] = '\0';
												band_txt[i].temp_line_cnt = 0;
											} else if ((tmp_txt[1] ^ 0x4f) == '\n') {
												band_txt[i].temp_line[0] = '\0';
												band_txt[i].temp_line_cnt = 0;
											}
											to_print[i] --;
										}
									} else if (header_type == 0x40) { /* ABC text */
										new_group[i] = false;
										to_print[i] = 3;
										ABC_grp[i] = true;
										C_seen[i] = ((tmp_txt[0] & 0x0f) == 0x03)?true:false;

										band_txt[i].txt[band_txt[i].txt_cnt] = tmp_txt[1] ^ 0x4f;
										band_txt[i].txt_cnt++;

										band_txt[i].txt[band_txt[i].txt_cnt] = tmp_txt[2] ^ 0x93;
										band_txt[i].txt_cnt++;

										/*
										   We should NOT see any more text,
										   if we already processed text,
										   so blank out the codes.
										*/
										if (band_txt[i].txt_stats_sent) {
											if (recvlen == 29) {
												rptrbuf.vpkt.vasd.text[0] = 0x70;
												rptrbuf.vpkt.vasd.text[1] = 0x4f;
												rptrbuf.vpkt.vasd.text[2] = 0x93;
											} else {
												rptrbuf.vpkt.vasd1.text[0] = 0x70;
												rptrbuf.vpkt.vasd1.text[1] = 0x4f;
												rptrbuf.vpkt.vasd1.text[2] = 0x93;
											}
										}

										if (band_txt[i].txt_cnt >= 20) {
											band_txt[i].txt[band_txt[i].txt_cnt] = '\0';
											/***
											ii->sendHeardWithTXMsg(band_txt[i].lh_mycall,
											                       band_txt[i].lh_sfx,
											                       (strstr(band_txt[i].lh_yrcall,"REF") == NULL)?band_txt[i].lh_yrcall:"CQCQCQ  ",
											                       band_txt[i].lh_rpt1,
											                       band_txt[i].lh_rpt2,
											                       band_txt[i].flags[0],
											                       band_txt[i].flags[1],
											                       band_txt[i].flags[2],
											                       band_txt[i].dest_rptr,
											                       band_txt[i].txt);
											***/
											// traceit("TEXT1=[%s]\n", band_txt[i].txt);
											band_txt[i].txt_cnt = 0;
										}
									} else {
										new_group[i] = false;
										to_print[i] = 0;
										ABC_grp[i] = false;
									}
								} else {
									if (to_print[i] == 3) {
										if (ABC_grp[i]) {
											band_txt[i].txt[band_txt[i].txt_cnt] = tmp_txt[0] ^ 0x70;
											band_txt[i].txt_cnt ++;

											band_txt[i].txt[band_txt[i].txt_cnt] = tmp_txt[1] ^ 0x4f;
											band_txt[i].txt_cnt ++;

											band_txt[i].txt[band_txt[i].txt_cnt] = tmp_txt[2] ^ 0x93;
											band_txt[i].txt_cnt ++;

											/*
											   We should NOT see any more text,
											   if we already processed text,
											   so blank out the codes.
											*/
											if (band_txt[i].txt_stats_sent) {
												if (recvlen == 29) {
													rptrbuf.vpkt.vasd.text[0] = 0x70;
													rptrbuf.vpkt.vasd.text[1] = 0x4f;
													rptrbuf.vpkt.vasd.text[2] = 0x93;
												} else {
													rptrbuf.vpkt.vasd1.text[0] = 0x70;
													rptrbuf.vpkt.vasd1.text[1] = 0x4f;
													rptrbuf.vpkt.vasd1.text[2] = 0x93;
												}
											}

											if ((band_txt[i].txt_cnt >= 20) || C_seen[i]) {
												band_txt[i].txt[band_txt[i].txt_cnt] = '\0';
												if (!band_txt[i].txt_stats_sent) {
													/*** if YRCALL is CQCQCQ, set dest_rptr ***/
													if (memcmp(band_txt[i].lh_yrcall, "CQCQCQ", 6) == 0) {
														set_dest_rptr(i, band_txt[i].dest_rptr);
														if (memcmp(band_txt[i].dest_rptr, "REF", 3) == 0)
															band_txt[i].dest_rptr[0] = '\0';
													}

													ii->sendHeardWithTXMsg(band_txt[i].lh_mycall,
													                       band_txt[i].lh_sfx,
													                       (strstr(band_txt[i].lh_yrcall,"REF") == NULL)?band_txt[i].lh_yrcall:"CQCQCQ  ",
													                       band_txt[i].lh_rpt1,
													                       band_txt[i].lh_rpt2,
													                       band_txt[i].flags[0],
													                       band_txt[i].flags[1],
													                       band_txt[i].flags[2],
													                       band_txt[i].dest_rptr,
													                       band_txt[i].txt);
													// traceit("TEXT2=[%s], destination repeater=[%s]\n", band_txt[i].txt, band_txt[i].dest_rptr);
													band_txt[i].txt_stats_sent = true;
												}
												band_txt[i].txt_cnt = 0;
											}
											if (C_seen[i])
												C_seen[i] = false;
										} else {
											/* something went wrong? all bets are off */
											if (band_txt[i].temp_line_cnt > 200) {
												traceit("Reached the limit in the OLD gps mode\n");
												band_txt[i].temp_line[0] = '\0';
												band_txt[i].temp_line_cnt = 0;
											}

											/* do not copy CR, NL */
											if (((tmp_txt[0] ^ 0x70) != '\r') && ((tmp_txt[0] ^ 0x70) != '\n')) {
												band_txt[i].temp_line[band_txt[i].temp_line_cnt] = tmp_txt[0] ^ 0x70;
												band_txt[i].temp_line_cnt++;
											}
											if (((tmp_txt[1] ^ 0x4f) != '\r') && ((tmp_txt[1] ^ 0x4f) != '\n')) {
												band_txt[i].temp_line[band_txt[i].temp_line_cnt] = tmp_txt[1] ^ 0x4f;
												band_txt[i].temp_line_cnt++;
											}
											if (((tmp_txt[2] ^ 0x93) != '\r') && ((tmp_txt[2] ^ 0x93) != '\n')) {
												band_txt[i].temp_line[band_txt[i].temp_line_cnt] = tmp_txt[2] ^ 0x93;
												band_txt[i].temp_line_cnt++;
											}

											if (
											    ((tmp_txt[0] ^ 0x70) == '\r') ||
											    ((tmp_txt[1] ^ 0x4f) == '\r') ||
											    ((tmp_txt[2] ^ 0x93) == '\r')
											) {
												if (memcmp(band_txt[i].temp_line, "$GPRMC", 6) == 0) {
													memcpy(band_txt[i].gprmc, band_txt[i].temp_line, band_txt[i].temp_line_cnt);
													band_txt[i].gprmc[band_txt[i].temp_line_cnt] = '\0';
												} else if (band_txt[i].temp_line[0] != '$') {
													memcpy(band_txt[i].gpid, band_txt[i].temp_line, band_txt[i].temp_line_cnt);
													band_txt[i].gpid[band_txt[i].temp_line_cnt] = '\0';
													if (bool_send_aprs && !band_txt[i].is_gps_sent)
														gps_send(i);
												}
												band_txt[i].temp_line[0] = '\0';
												band_txt[i].temp_line_cnt = 0;
											} else if (((tmp_txt[0] ^ 0x70) == '\n') ||
											           ((tmp_txt[1] ^ 0x4f) == '\n') ||
											           ((tmp_txt[2] ^ 0x93) == '\n')) {
												band_txt[i].temp_line[0] = '\0';
												band_txt[i].temp_line_cnt = 0;
											}
										}
									} else if (to_print[i] == 2) {
										/* something went wrong? all bets are off */
										if (band_txt[i].temp_line_cnt > 200) {
											traceit("Reached the limit in the OLD gps mode\n");
											band_txt[i].temp_line[0] = '\0';
											band_txt[i].temp_line_cnt = 0;
										}

										/* do not copy CR, NL */
										if (((tmp_txt[0] ^ 0x70) != '\r') && ((tmp_txt[0] ^ 0x70) != '\n')) {
											band_txt[i].temp_line[band_txt[i].temp_line_cnt] = tmp_txt[0] ^ 0x70;
											band_txt[i].temp_line_cnt++;
										}
										if (((tmp_txt[1] ^ 0x4f) != '\r') && ((tmp_txt[1] ^ 0x4f) != '\n')) {
											band_txt[i].temp_line[band_txt[i].temp_line_cnt] = tmp_txt[1] ^ 0x4f;
											band_txt[i].temp_line_cnt++;
										}

										if (((tmp_txt[0] ^ 0x70) == '\r') || ((tmp_txt[1] ^ 0x4f) == '\r')) {
											if (memcmp(band_txt[i].temp_line, "$GPRMC", 6) == 0) {
												memcpy(band_txt[i].gprmc, band_txt[i].temp_line, band_txt[i].temp_line_cnt);
												band_txt[i].gprmc[band_txt[i].temp_line_cnt] = '\0';
											} else if (band_txt[i].temp_line[0] != '$') {
												memcpy(band_txt[i].gpid, band_txt[i].temp_line, band_txt[i].temp_line_cnt);
												band_txt[i].gpid[band_txt[i].temp_line_cnt] = '\0';
												if (bool_send_aprs && !band_txt[i].is_gps_sent)
													gps_send(i);
											}
											band_txt[i].temp_line[0] = '\0';
											band_txt[i].temp_line_cnt = 0;
										} else if (((tmp_txt[0] ^ 0x70) == '\n') || ((tmp_txt[1] ^ 0x4f)  == '\n')) {
											band_txt[i].temp_line[0] = '\0';
											band_txt[i].temp_line_cnt = 0;
										}
									} else if (to_print[i] == 1) {
										/* something went wrong? all bets are off */
										if (band_txt[i].temp_line_cnt > 200) {
											traceit("Reached the limit in the OLD gps mode\n");
											band_txt[i].temp_line[0] = '\0';
											band_txt[i].temp_line_cnt = 0;
										}

										/* do not copy CR, NL */
										if (((tmp_txt[0] ^ 0x70) != '\r') && ((tmp_txt[0] ^ 0x70) != '\n')) {
											band_txt[i].temp_line[band_txt[i].temp_line_cnt] = tmp_txt[0] ^ 0x70;
											band_txt[i].temp_line_cnt++;
										}

										if ((tmp_txt[0] ^ 0x70) == '\r') {
											if (memcmp(band_txt[i].temp_line, "$GPRMC", 6) == 0) {
												memcpy(band_txt[i].gprmc, band_txt[i].temp_line, band_txt[i].temp_line_cnt);
												band_txt[i].gprmc[band_txt[i].temp_line_cnt] = '\0';
											} else if (band_txt[i].temp_line[0] != '$') {
												memcpy(band_txt[i].gpid, band_txt[i].temp_line, band_txt[i].temp_line_cnt);
												band_txt[i].gpid[band_txt[i].temp_line_cnt] = '\0';
												if (bool_send_aprs && !band_txt[i].is_gps_sent)
													gps_send(i);
											}
											band_txt[i].temp_line[0] = '\0';
											band_txt[i].temp_line_cnt = 0;
										} else if ((tmp_txt[0] ^ 0x70) == '\n') {
											band_txt[i].temp_line[0] = '\0';
											band_txt[i].temp_line_cnt = 0;
										}
									}
									new_group[i] = true;
									to_print[i] = 0;
									ABC_grp[i] = false;
								}
								break;
							}
						}
					}

					/* send data to g2_link */
					sendto(srv_sock, rptrbuf.pkt_id, recvlen, 0, (struct sockaddr *)&plug, sizeof(struct sockaddr_in));

					/* aprs processing */
					if (bool_send_aprs)
						//                             streamID               seq                     audio+text             size
						aprs->ProcessText(rptrbuf.vpkt.streamid, rptrbuf.vpkt.ctrl, rptrbuf.vpkt.vasd.voice, (recvlen == 29)?12:15);

					for (i = 0; i < 3; i++) {
						/* find out if data must go to the remote G2 */
						if (to_remote_g2[i].streamid == rptrbuf.vpkt.streamid) {
							memcpy(g2buf.title, "DSVT", 4);
							g2buf.config = 0x20;
							g2buf.flaga[0] = g2buf.flaga[1] = g2buf.flaga[2] = 0x00;
							memcpy(&g2buf.id, &rptrbuf.vpkt.icm_id, 7);
							if (recvlen == 29)
								memcpy(g2buf.vasd.voice, rptrbuf.vpkt.vasd.voice, 12);
							else
								memcpy(g2buf.vasd.voice, rptrbuf.vpkt.vasd1.voice, 12);

							sendto(g2_sock, g2buf.title, 27, 0, (struct sockaddr *)&(to_remote_g2[i].toDst4), sizeof(struct sockaddr_in));

							time(&(to_remote_g2[i].last_time));

							/* Is this the end-of-stream */
							if (rptrbuf.vpkt.ctrl & 0x40) {
								memset(&to_remote_g2[i].toDst4,0,sizeof(struct sockaddr_in));
								to_remote_g2[i].streamid = 0;
								to_remote_g2[i].last_time = 0;
							}
							break;
						} else
							/* Is the data to be recorded for echotest */
							if (recd[i].fd>=0 && recd[i].streamid==rptrbuf.vpkt.streamid) {
								time(&recd[i].last_time);

								memcpy(recbuf.title, "DSVT", 4);
								recbuf.config = 0x20;
								recbuf.id = rptrbuf.vpkt.icm_id;
								recbuf.flaga[0] = recbuf.flaga[1] = recbuf.flaga[20] = 0;
								recbuf.flagb[0] = rptrbuf.vpkt.dst_rptr_id;
								recbuf.flagb[1] = rptrbuf.vpkt.snd_rptr_id;
								recbuf.flagb[2] = rptrbuf.vpkt.snd_term_id;
								memcpy(&recbuf.streamid, &rptrbuf.vpkt.streamid, 3);
								if (recvlen == 29)
									memcpy(recbuf.vasd.voice, rptrbuf.vpkt.vasd.voice, 12);
								else
									memcpy(recbuf.vasd.voice, rptrbuf.vpkt.vasd1.voice, 12);

								rec_len = 27;
								(void)write(recd[i].fd, &rec_len, 2);
								(void)write(recd[i].fd, &recbuf, rec_len);

								if ((rptrbuf.vpkt.ctrl & 0x40) != 0) {
									recd[i].streamid = 0;
									recd[i].last_time = 0;
									close(recd[i].fd);
									recd[i].fd = -1;
									// traceit("Closed echotest audio file:[%s]\n", recd[i].file);

									/* we are in echotest mode, so play it back */
									try {
										std::async(std::launch::async, PlayFileThread, recd[i].file);
									} catch (const std::exception &e) {
										traceit("failed to start PlayFileThread. Exception: %s\n", e.what());
										//   When the echotest thread runs, it deletes the file,
										//   Because the echotest thread did NOT start, we delete the file here
										unlink(recd[i].file);
									}
								}
								break;
							} else
								/* Is the data to be recorded for voicemail */
								if ((vm[i].fd >= 0) && (vm[i].streamid==rptrbuf.vpkt.streamid)) {
									time(&vm[i].last_time);

									memcpy(recbuf.title, "DSVT", 4);
									recbuf.config = 0x20;
									recbuf.flaga[0] = recbuf.flaga[1] = recbuf.flaga[2] = 0;
									recbuf.id = rptrbuf.vpkt.icm_id;
									recbuf.flagb[0] = rptrbuf.vpkt.dst_rptr_id;
									recbuf.flagb[1] = rptrbuf.vpkt.snd_rptr_id;
									recbuf.flagb[2] = rptrbuf.vpkt.snd_term_id;
									memcpy(&recbuf.streamid, &rptrbuf.vpkt.streamid, 3);
									if (recvlen == 29)
										memcpy(recbuf.vasd.voice, rptrbuf.vpkt.vasd.voice, 12);
									else
										memcpy(recbuf.vasd.voice, rptrbuf.vpkt.vasd1.voice, 12);

									rec_len = 27;
									(void)write(vm[i].fd, &rec_len, 2);
									(void)write(vm[i].fd, &recbuf, rec_len);

									if ((rptrbuf.vpkt.ctrl & 0x40) != 0) {
										vm[i].streamid = 0;
										vm[i].last_time = 0;
										close(vm[i].fd);
										vm[i].fd = -1;
										// traceit("Closed voicemail audio file:[%s]\n", vm[i].file);
									}
									break;
								} else
									/* or maybe this is cross-banding data */
									if ((toRptr[i].streamid==rptrbuf.vpkt.streamid) && (toRptr[i].adr == fromRptr.sin_addr.s_addr)) {
										sendto(srv_sock, rptrbuf.pkt_id, 29, 0, (struct sockaddr *)&toRptr[i].band_addr, sizeof(struct sockaddr_in));

										/* timeit */
										time(&toRptr[i].last_time);

										/* bump G2 counter */
										toRptr[i].G2_COUNTER ++;

										toRptr[i].sequence = rptrbuf.vpkt.ctrl;

										/* End of stream ? */
										if (rptrbuf.vpkt.ctrl & 0x40) {
											toRptr[i].last_time = 0;
											toRptr[i].streamid = 0;
											toRptr[i].adr = 0;
										}
										break;
									}
					}

					if (rptrbuf.vpkt.ctrl & 0x40) {
						if (bool_qso_details)
							traceit("END from rptr: cntr=%04x, streamID=%04x, %d bytes\n", rptrbuf.counter, rptrbuf.vpkt.streamid, recvlen);
					}
				}
			}
			FD_CLR (srv_sock,&fdset);
		}
	}

	// thread clean-up
	if (bool_send_aprs) {
		if (aprs_future.valid())
			aprs_future.get();
	}
	irc_data_future.get();
	return;
}

static void compute_aprs_hash()
{
	short hash = 0x73e2;
	char rptr_sign[CALL_SIZE + 1];

	strcpy(rptr_sign, OWNER.c_str());
	char *p = strchr(rptr_sign, ' ');
	if (!p) {
		traceit("Failed to build repeater callsign for aprs hash\n");
		return;
	}
	*p = '\0';
	p = rptr_sign;
	short int len = strlen(rptr_sign);

	for (short int i=0; i < len; i+=2) {
		hash ^= (*p++) << 8;
		hash ^= (*p++);
	}
	traceit("aprs hash code=[%d] for %s\n", hash, OWNER.c_str());
	rptr.aprs_hash = hash;

	return;
}

void APRSBeaconThread()
{
	struct timespec req;

	char snd_buf[512];
	char rcv_buf[512];
	time_t tnow = 0;

	struct sigaction act;

	/*
	   Every 20 seconds, the remote APRS host sends a KEEPALIVE packet-comment
	   on the TCP/APRS port.
	   If we have not received any KEEPALIVE packet-comment after 5 minutes
	   we must assume that the remote APRS host is down or disappeared
	   or has dropped the connection. In these cases, we must re-connect.
	   There are 3 keepalive packets in one minute, or every 20 seconds.
	   In 5 minutes, we should have received a total of 15 keepalive packets.
	*/
	short THRESHOLD_COUNTDOWN = 15;

	act.sa_handler = sigCatch;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	if (sigaction(SIGTERM, &act, 0) != 0) {
		traceit("APRSBeaconThread: sigaction-TERM failed, error=%d\n", errno);
		return;
	}
	if (sigaction(SIGINT, &act, 0) != 0) {
		traceit("APRSBeaconThread: sigaction-INT failed, error=%d\n", errno);
		return;
	}
	if (sigaction(SIGPIPE, &act, 0) != 0) {
		traceit("APRSBeaconThread: sigaction-PIPE failed, error=%d\n", errno);
		return;
	}

	time_t last_keepalive_time;
	time(&last_keepalive_time);

	/* This thread is also saying to the APRS_HOST that we are ALIVE */
	while (keep_running) {
		if (aprs->GetSock() == -1) {
			aprs->Open(OWNER);
			if (aprs->GetSock() == -1)
				sleep(1);
			else
				THRESHOLD_COUNTDOWN = 15;
		}

		time(&tnow);
		time_t last_beacon_time = 0;
		if ((tnow - last_beacon_time) > (rptr.aprs_interval * 60)) {
			for (short int i=0; i<3; i++) {
				if (rptr.mod[i].desc[0] != '\0') {
					float tmp_lat = fabs(rptr.mod[i].latitude);
					float tmp_lon = fabs(rptr.mod[i].longitude);
					float lat = floor(tmp_lat);
					float lon = floor(tmp_lon);
					lat = (tmp_lat - lat) * 60.0F + lat  * 100.0F;
					lon = (tmp_lon - lon) * 60.0F + lon  * 100.0F;

					char lat_s[15], lon_s[15];
					if (lat >= 1000.0F)
						sprintf(lat_s, "%.2f", lat);
					else if (lat >= 100.0F)
						sprintf(lat_s, "0%.2f", lat);
					else if (lat >= 10.0F)
						sprintf(lat_s, "00%.2f", lat);
					else
						sprintf(lat_s, "000%.2f", lat);

					if (lon >= 10000.0F)
						sprintf(lon_s, "%.2f", lon);
					else if (lon >= 1000.0F)
						sprintf(lon_s, "0%.2f", lon);
					else if (lon >= 100.0F)
						sprintf(lon_s, "00%.2f", lon);
					else if (lon >= 10.0F)
						sprintf(lon_s, "000%.2f", lon);
					else
						sprintf(lon_s, "0000%.2f", lon);

					/* send to aprs */
					sprintf(snd_buf, "%s>APJI23,TCPIP*,qAC,%sS:!%s%cD%s%c&RNG%04u %s %s",
					        rptr.mod[i].call.c_str(),  rptr.mod[i].call.c_str(),
					        lat_s,  (rptr.mod[i].latitude < 0.0)  ? 'S' : 'N',
					        lon_s,  (rptr.mod[i].longitude < 0.0) ? 'W' : 'E',
					        (unsigned int)rptr.mod[i].range, rptr.mod[i].band.c_str(), rptr.mod[i].desc.c_str());

					// traceit("APRS Beacon =[%s]\n", snd_buf);
					strcat(snd_buf, "\r\n");

					while (keep_running) {
						if (aprs->GetSock() == -1) {
							aprs->Open(OWNER);
							if (aprs->GetSock() == -1)
								sleep(1);
							else
								THRESHOLD_COUNTDOWN = 15;
						} else {
							int rc = aprs->WriteSock(snd_buf, strlen(snd_buf));
							if (rc < 0) {
								if ((errno == EPIPE) ||
								        (errno == ECONNRESET) ||
								        (errno == ETIMEDOUT) ||
								        (errno == ECONNABORTED) ||
								        (errno == ESHUTDOWN) ||
								        (errno == EHOSTUNREACH) ||
								        (errno == ENETRESET) ||
								        (errno == ENETDOWN) ||
								        (errno == ENETUNREACH) ||
								        (errno == EHOSTDOWN) ||
								        (errno == ENOTCONN)) {
									traceit("send_aprs_beacon: APRS_HOST closed connection,error=%d\n",errno);
									close(aprs->GetSock());
									aprs->SetSock( -1 );
								} else if (errno == EWOULDBLOCK) {
									req.tv_sec = 0;
									req.tv_nsec = 100000000; // 100 milli
									nanosleep(&req, NULL);
								} else {
									/* Cant do nothing about it */
									traceit("send_aprs_beacon failed, error=%d\n", errno);
									break;
								}
							} else {
								// traceit("APRS beacon sent\n");
								break;
							}
						}
						int rc = recv(aprs->GetSock(), rcv_buf, sizeof(rcv_buf), 0);
						if (rc > 0)
							THRESHOLD_COUNTDOWN = 15;
					}
				}
				int rc = recv(aprs->GetSock(), rcv_buf, sizeof(rcv_buf), 0);
				if (rc > 0)
					THRESHOLD_COUNTDOWN = 15;
			}
			time(&last_beacon_time);
		}
		/*
		   Are we still receiving from APRS host ?
		*/
		int rc = recv(aprs->GetSock(), rcv_buf, sizeof(rcv_buf), 0);
		if (rc < 0) {
			if ((errno == EPIPE) ||
			        (errno == ECONNRESET) ||
			        (errno == ETIMEDOUT) ||
			        (errno == ECONNABORTED) ||
			        (errno == ESHUTDOWN) ||
			        (errno == EHOSTUNREACH) ||
			        (errno == ENETRESET) ||
			        (errno == ENETDOWN) ||
			        (errno == ENETUNREACH) ||
			        (errno == EHOSTDOWN) ||
			        (errno == ENOTCONN)) {
				traceit("send_aprs_beacon: recv error: APRS_HOST closed connection,error=%d\n",errno);
				close(aprs->GetSock());
				aprs->SetSock( -1 );
			}
		} else if (rc == 0) {
			traceit("send_aprs_beacon: recv: APRS shutdown\n");
			close(aprs->GetSock());
			aprs->SetSock( -1 );
		} else
			THRESHOLD_COUNTDOWN = 15;

		req.tv_sec = 0;
		req.tv_nsec = 100000000; // 100 milli
		nanosleep(&req, NULL);

		/* 20 seconds passed already ? */
		time(&tnow);
		if ((tnow - last_keepalive_time) > 20) {
			/* we should be receving keepalive packets ONLY if the connection is alive */
			if (aprs->GetSock() >= 0) {
				if (THRESHOLD_COUNTDOWN > 0)
					THRESHOLD_COUNTDOWN--;

				if (THRESHOLD_COUNTDOWN == 0) {
					traceit("APRS host keepalive timeout\n");
					close(aprs->GetSock());
					aprs->SetSock( -1 );
				}
			}
			/* reset timer */
			time(&last_keepalive_time);
		}
	}
	traceit("APRS beacon thread exiting...\n");
	return;
}

static void PlayFileThread(char *file)
{
	struct timespec req;

	unsigned short rlen = 0;
	unsigned char dstar_buf[56];
	unsigned char rptr_buf[58];
	short int i = 0;
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
	if (sigaction(SIGPIPE, &act, 0) != 0) {
		traceit("sigaction-PIPE failed, error=%d\n", errno);
		return;
	}

	traceit("File to playback:[%s]\n", file);

	FILE *fp = fopen(file, "rb");
	if (!fp) {
		traceit("Failed to open file %s\n", file);
		return;
	}

	size_t nread = fread(dstar_buf, 10, 1, fp);
	if (nread != 1) {
		traceit("Cant read first 10 bytes in %s\n", file);
		fclose(fp);
		return;
	}

	if (memcmp(dstar_buf, "DVTOOL", 6) != 0) {
		traceit("DVTOOL keyword not found in %s\n", file);
		fclose(fp);
		return;
	}

	sleep(play_wait);
	while (keep_running) {
		nread = fread(&rlen, 2, 1, fp);
		if (nread != 1)
			break;

		if ((rlen != 56) && (rlen != 27)) {
			traceit("Expected 56 bytes or 27 bytes, found %d\n", rlen);
			break;
		}
		nread = fread(dstar_buf, rlen, 1, fp);
		if (nread == 1) {
			if (memcmp(dstar_buf, "DSVT", 4) != 0) {
				traceit("DVST keyword not found in %s\n", file);
				break;
			}

			if (dstar_buf[8] != 0x20) {
				traceit("Not Voice type in %s\n", file);
				break;
			}

			if ((dstar_buf[4] != 0x10) && (dstar_buf[4] != 0x20)) {
				traceit("Not a valid record type in %s\n",file);
				break;
			}

			if (rlen == 56) {
				/* which module is this recording for? */
				if (dstar_buf[25] == 'A')
					i = 0;
				else if (dstar_buf[25] == 'B')
					i = 1;
				else if (dstar_buf[25] == 'C')
					i = 2;

				memcpy(rptr_buf, "DSTR", 4);
				rptr_buf[5] = (unsigned char)(toRptr[i].G2_COUNTER & 0xff);
				rptr_buf[4] = (unsigned char)((toRptr[i].G2_COUNTER >> 8) & 0xff);
				rptr_buf[6] = 0x73;
				rptr_buf[7] = 0x12;
				rptr_buf[8] = 0x00;
				rptr_buf[9] = 0x30;
				rptr_buf[10] = 0x20;
				memcpy(rptr_buf + 11, dstar_buf + 9, 47);

				/* We did not change anything */
				// calcPFCS(rptr_buf, 58);
			} else {
				rptr_buf[5] = (unsigned char)(toRptr[i].G2_COUNTER & 0xff);
				rptr_buf[4] = (unsigned char)((toRptr[i].G2_COUNTER >> 8) & 0xff);
				rptr_buf[9] = 0x13;
				memcpy(rptr_buf + 11, dstar_buf + 9, 18);
			}

			sendto(srv_sock, rptr_buf, rlen + 2, 0, (struct sockaddr *)&toRptr[i].band_addr, sizeof(struct sockaddr_in));

			toRptr[i].G2_COUNTER ++;

			req.tv_sec = 0;
			req.tv_nsec = play_delay * 1000000;
			nanosleep(&req, NULL);
		}
	}
	fclose(fp);
	if (!strstr(file, "voicemail.dat"))
		unlink(file);
	traceit("Finished playing\n");
	return;
}

static void qrgs_and_maps()
{
	for(int i=0; i<3; i++) {
		std::string rptrcall = OWNER;
		rptrcall.resize(CALL_SIZE-1);
		rptrcall += i + 'A';
		if (rptr.mod[i].latitude || rptr.mod[i].longitude || rptr.mod[i].desc1.length() || rptr.mod[i].url.length())
			ii->rptrQTH(rptrcall, rptr.mod[i].latitude, rptr.mod[i].longitude, rptr.mod[i].desc1, rptr.mod[i].desc2, rptr.mod[i].url, rptr.mod[i].package_version);
		if (rptr.mod[i].frequency)
			ii->rptrQRG(rptrcall, rptr.mod[i].frequency, rptr.mod[i].offset, rptr.mod[i].range, rptr.mod[i].agl);
	}

	return;
}

int main(int argc, char **argv)
{
	short int i;
	struct sigaction act;

	setvbuf(stdout, (char *)NULL, _IOLBF, 0);

	traceit("VERSION %s\n", IRCDDB_VERSION);
	if (argc != 2) {
		traceit("Example: g2_ircddb g2_ircddb.cfg\n");
		return 1;
	}

	/* Used to validate MYCALL input */
	int rc = regcomp(&preg,
	             "^(([1-9][A-Z])|([A-Z][0-9])|([A-Z][A-Z][0-9]))[0-9A-Z]*[A-Z][ ]*[ A-RT-Z]$",
	             REG_EXTENDED | REG_NOSUB);
	if (rc != REG_NOERROR) {
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
	if (sigaction(SIGPIPE, &act, 0) != 0) {
		traceit("sigaction-PIPE failed, error=%d\n", errno);
		return 1;
	}

	rptr.mod[0].band = "23cm";
	rptr.mod[1].band = "70cm";
	rptr.mod[2].band = "2m";

	for (i = 0; i < 3; i++) {
		memset(&band_txt[0], 0, sizeof(SBANDTXT));
	}

	/* process configuration file */
	if ( read_config(argv[1]) ) {
		traceit("Failed to process config file %s\n", argv[1]);
		return 1;
	}

	/* build the repeater callsigns for aprs */
	rptr.mod[0].call = OWNER;
	for (i=OWNER.length(); i; i--)
		if (! isspace(OWNER[i-1]))
			break;
	rptr.mod[0].call.resize(i);

	rptr.mod[1].call = rptr.mod[0].call;
	rptr.mod[2].call = rptr.mod[0].call;
	rptr.mod[0].call += "-A";
	rptr.mod[1].call += "-B";
	rptr.mod[2].call += "-C";
	traceit("Repeater callsigns: [%s] [%s] [%s]\n", rptr.mod[0].call.c_str(), rptr.mod[1].call.c_str(), rptr.mod[2].call.c_str());

	if (bool_send_aprs) {
		aprs = new CAPRS();
		if (aprs)
			aprs->Init();
		else {
			traceit("aprs class init failed!\nAPRS will be turned off");
			bool_send_aprs = false;
		}
	}
	compute_aprs_hash();

	ii = new CIRCDDB(ircddb.ip, ircddb.port, owner, irc_pass, IRCDDB_VERSION, local_irc_ip);
	bool ok = ii->open();
	if (!ok) {
		traceit("irc open failed\n");
		return 1;
	}

	rc = ii->getConnectionState();
	traceit("Waiting for irc connection status of 2\n");
	i = 0;
	while (rc < 2) {
		traceit("irc status=%d\n", rc);
		if (rc < 2) {
			i++;
			sleep(5);
		} else
			break;

		if (!keep_running)
			break;

		if (i > 5) {
			traceit("We can not wait any longer...\n");
			break;
		}
		rc = ii->getConnectionState();
	}

	do {
		/* udp port 40000 must open first */
		g2_sock = open_port(g2_external);
		if (0 > g2_sock) {
			traceit("Can't open %s:%d\n", g2_external.ip.c_str(), g2_external.port);
			break;
		}

		/* Open udp INTERNAL port */
		srv_sock = open_port(g2_internal);
		if (0 > srv_sock) {
			traceit("Can't open %s:%d\n", g2_internal.ip.c_str(), g2_internal.port);
			break;
		}

		for (i = 0; i < 3; i++) {
			// recording for echotest on local repeater modules
			recd[i].last_time = 0;
			recd[i].streamid = 0;
			recd[i].fd = -1;
			memset(recd[i].file, 0, sizeof(recd[i].file));

			// recording for voicemail on local repeater modules 
			vm[i].last_time = 0;
			vm[i].streamid = 0;
			vm[i].fd = -1;
			memset(vm[i].file, 0, sizeof(vm[i].file));

			snprintf(vm[i].file, FILENAME_MAX, "%s/%c_%s", echotest_dir.c_str(), 'A'+i, "voicemail.dat");

			if (access(vm[i].file, F_OK) != 0)
				memset(vm[i].file, 0, sizeof(vm[i].file));
			else
				traceit("Loaded voicemail file: %s for mod %d\n", vm[i].file, i);

			// the repeater modules run on these ports
			memset(&toRptr[i],0,sizeof(toRptr[i]));

			memset(toRptr[i].saved_hdr, 0, sizeof(toRptr[i].saved_hdr));
			toRptr[i].saved_adr = 0;

			toRptr[i].streamid = 0;
			toRptr[i].adr = 0;

			toRptr[i].band_addr.sin_family = AF_INET;
			toRptr[i].band_addr.sin_addr.s_addr = inet_addr(rptr.mod[i].portip.ip.c_str());
			toRptr[i].band_addr.sin_port = htons(rptr.mod[i].portip.port);

			toRptr[i].last_time = 0;
			toRptr[i].G2_COUNTER = 0;

			toRptr[i].sequence = 0x0;
		}

		/*
		   Initialize the end_of_audio that will be sent to the local repeater
		   when audio from remote G2 has timed out
		*/
		memcpy(end_of_audio.pkt_id, "DSTR", 4);
		end_of_audio.flag[0] = 0x73;
		end_of_audio.flag[1] = 0x12;
		end_of_audio.nothing2[0] = 0x00;
		end_of_audio.nothing2[1] = 0x13;
		end_of_audio.vpkt.icm_id = 0x20;
		end_of_audio.vpkt.dst_rptr_id = 0x00;
		end_of_audio.vpkt.snd_rptr_id = 0x01;
		memset(end_of_audio.vpkt.vasd.voice, '\0', 9);
		end_of_audio.vpkt.vasd.text[0] = 0x70;
		end_of_audio.vpkt.vasd.text[1] = 0x4f;
		end_of_audio.vpkt.vasd.text[2] = 0x93;

		/* to remote systems */
		for (i = 0; i < 3; i++) {
			memset(&to_remote_g2[i].toDst4, 0, sizeof(struct sockaddr_in));
			to_remote_g2[i].streamid = 0;
			to_remote_g2[i].last_time = 0;
		}

		/* where to send packets to g2_link */
		memset(&plug, 0, sizeof(struct sockaddr_in));
		plug.sin_family = AF_INET;
		plug.sin_port = htons(g2_link.port);
		plug.sin_addr.s_addr = inet_addr(g2_link.ip.c_str());

		traceit("g2_ircddb...entering processing loop\n");

		if (bool_send_qrgs)
			qrgs_and_maps();

		runit();
		traceit("Leaving processing loop...\n");

	} while (false);

	if (srv_sock != -1) {
		close(srv_sock);
		traceit("Closed G2_INTERNAL_PORT\n");
	}

	if (g2_sock != -1) {
		close(g2_sock);
		traceit("Closed G2_EXTERNAL_PORT\n");
	}

	if (bool_send_aprs) {
		if (aprs->GetSock() != -1) {
			close(aprs->GetSock());
			traceit("Closed APRS\n");
		}
		delete aprs;
	}

	for (i = 0; i < 3; i++) {
		recd[i].last_time = 0;
		recd[i].streamid = 0;
		if (recd[i].fd >= 0) {
			close(recd[i].fd);
			unlink(recd[i].file);
		}
	}

	ii->close();
	delete ii;

	traceit("g2_ircddb exiting\n");
	return rc;
}

static bool validate_csum(SBANDTXT &bt, bool is_gps)
{
	const char *name = is_gps ? "GPS" : "GPRMC";
	char *s = is_gps ? bt.gpid : bt.gprmc;
	char *p = strrchr(s, '*');
	if (!p) {
		// BAD news, something went wrong
		traceit("Missing asterisk before checksum in %s\n", name);
		bt.gprmc[0] = bt.gpid[0] = '\0';
		return true;
	} else {
		*p = '\0';
		// verify csum in GPRMC
		bool ok = verify_gps_csum(s + 1, p + 1);
		if (!ok) {
			traceit("csum in %s not good\n", name);
			bt.gprmc[0] = bt.gpid[0] = '\0';
			return true;
		}
	}
	return false;
}

static void gps_send(short int rptr_idx)
{
	time_t tnow = 0;
	static char old_mycall[CALL_SIZE + 1] = { "        " };

	if ((rptr_idx < 0) || (rptr_idx > 2)) {
		traceit("ERROR in gps_send: rptr_idx %d is invalid\n", rptr_idx);
		return;
	}

	if (band_txt[rptr_idx].gprmc[0] == '\0') {
		band_txt[rptr_idx].gpid[0] = '\0';
		traceit("missing GPS ID\n");
		return;
	}
	if (band_txt[rptr_idx].gpid[0] == '\0') {
		band_txt[rptr_idx].gprmc[0] = '\0';
		traceit("Missing GPSRMC\n");
		return;
	}
	if (memcmp(band_txt[rptr_idx].gpid, band_txt[rptr_idx].lh_mycall, CALL_SIZE) != 0) {
		traceit("MYCALL [%s] does not match first 8 characters of GPS ID [%.8s]\n",
		        band_txt[rptr_idx].lh_mycall, band_txt[rptr_idx].gpid);
		band_txt[rptr_idx].gprmc[0] = '\0';
		band_txt[rptr_idx].gpid[0] = '\0';
		return;
	}

	/* if new station, reset last time */
	if (strcmp(old_mycall, band_txt[rptr_idx].lh_mycall) != 0) {
		strcpy(old_mycall, band_txt[rptr_idx].lh_mycall);
		band_txt[rptr_idx].gps_last_time = 0;
	}

	/* do NOT process often */
	time(&tnow);
	if ((tnow - band_txt[rptr_idx].gps_last_time) < 31)
		return;

	traceit("GPRMC=[%s]\n", band_txt[rptr_idx].gprmc);
	traceit("GPS id=[%s]\n",band_txt[rptr_idx].gpid);

	if (validate_csum(band_txt[rptr_idx], false) || validate_csum(band_txt[rptr_idx], true))
		return;

	/* now convert GPS into APRS and send it */
	build_aprs_from_gps_and_send(rptr_idx);

	band_txt[rptr_idx].is_gps_sent = true;
	time(&(band_txt[rptr_idx].gps_last_time));
	return;
}

static void build_aprs_from_gps_and_send(short int rptr_idx)
{
	char buf[512];
	const char *delim = ",";

	char *saveptr = NULL;

	/*** dont care about the rest */

	strcpy(buf, band_txt[rptr_idx].lh_mycall);
	char *p = strchr(buf, ' ');
	if (p) {
		if (band_txt[rptr_idx].lh_mycall[7] != ' ') {
			*p = '-';
			*(p + 1) = band_txt[rptr_idx].lh_mycall[7];
			*(p + 2) = '>';
			*(p + 3) = '\0';
		} else {
			*p = '>';
			*(p + 1) = '\0';
		}
	} else
		strcat(buf, ">");

	strcat(buf, "APDPRS,DSTAR*,qAR,");
	strcat(buf, rptr.mod[rptr_idx].call.c_str());
	strcat(buf, ":!");

	//GPRMC =
	strtok_r(band_txt[rptr_idx].gprmc, delim, &saveptr);
	//time_utc =
	strtok_r(NULL, delim, &saveptr);
	//nav =
	strtok_r(NULL, delim, &saveptr);
	char *lat_str = strtok_r(NULL, delim, &saveptr);
	char *lat_NS = strtok_r(NULL, delim, &saveptr);
	char *lon_str = strtok_r(NULL, delim, &saveptr);
	char *lon_EW = strtok_r(NULL, delim, &saveptr);

	if (lat_str && lat_NS) {
		if ((*lat_NS != 'N') && (*lat_NS != 'S')) {
			traceit("Invalid North or South indicator in latitude\n");
			return;
		}
		if (strlen(lat_str) != 9) {
			traceit("Invalid latitude\n");
			return;
		}
		if (lat_str[4] != '.') {
			traceit("Invalid latitude\n");
			return;
		}
		lat_str[7] = '\0';
		strcat(buf, lat_str);
		strcat(buf, lat_NS);
	} else {
		traceit("Invalid latitude\n");
		return;
	}
	/* secondary table */
	strcat(buf, "\\");

	if (lon_str && lon_EW) {
		if ((*lon_EW != 'E') && (*lon_EW != 'W')) {
			traceit("Invalid East or West indicator in longitude\n");
			return;
		}
		if (strlen(lon_str) != 10) {
			traceit("Invalid longitude\n");
			return;
		}
		if (lon_str[5] != '.') {
			traceit("Invalid longitude\n");
			return;
		}
		lon_str[8] = '\0';
		strcat(buf, lon_str);
		strcat(buf, lon_EW);
	} else {
		traceit("Invalid longitude\n");
		return;
	}

	/* Just this symbolcode only */
	strcat(buf, "k");
	strncat(buf, band_txt[rptr_idx].gpid + 13, 32);

	// traceit("Built APRS from old GPS mode=[%s]\n", buf);
	strcat(buf, "\r\n");

	if (-1 == aprs->WriteSock(buf, strlen(buf))) {
		if ((errno == EPIPE) || (errno == ECONNRESET) || (errno == ETIMEDOUT) || (errno == ECONNABORTED) ||
		    (errno == ESHUTDOWN) || (errno == EHOSTUNREACH) || (errno == ENETRESET) || (errno == ENETDOWN) ||
		    (errno == ENETUNREACH) || (errno == EHOSTDOWN) || (errno == ENOTCONN)) {
			traceit("build_aprs_from_gps_and_send: APRS_HOST closed connection, error=%d\n", errno);
			close(aprs->GetSock());
			aprs->SetSock( -1 );
		} else
			traceit("build_aprs_from_gps_and_send: send error=%d\n", errno);
	}
	return;
}

static bool verify_gps_csum(char *gps_text, char *csum_text)
{
	short computed_csum = 0;
	char computed_csum_text[16];

	short int len = strlen(gps_text);
	for (short int i=0; i<len; i++) {
		char c = gps_text[i];
		if (computed_csum == 0)
			computed_csum = (char)c;
		else
			computed_csum = computed_csum ^ ((char)c);
	}
	sprintf(computed_csum_text, "%02X", computed_csum);
	// traceit("computed_csum_text=[%s]\n", computed_csum_text);

	char *p = strchr(csum_text, ' ');
	if (p)
		*p = '\0';

	if (strcmp(computed_csum_text, csum_text) == 0)
		return true;
	else
		return false;
}
