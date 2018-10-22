/*
 *   Copyright (C) 2018 by Thomas Early N7TAE
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

#include <libconfig.h++>
#include "QnetTypeDefs.h"
#include "SEcho.h"

#include "aprs.h"

using namespace libconfig;

#define IP_SIZE 15
#define MAXHOSTNAMELEN 64
#define CALL_SIZE 8
#define MAX_DTMF_BUF 32

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
	bool sent_key_on_msg;

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

class CQnetGateway {
public:
	CQnetGateway();
	~CQnetGateway();
	void Process();
	int Init(char *cfgfile);

private:
	// text stuff
	bool new_group[3] = { true, true, true };
	unsigned char header_type = 0;
	short to_print[3] = { 0, 0, 0 };
	bool ABC_grp[3] = { false, false, false };
	bool C_seen[3] = { false, false, false };

	SPORTIP g2_internal, g2_external, g2_link, ircddb;

	std::string OWNER, owner, local_irc_ip, status_file, dtmf_dir, dtmf_file, echotest_dir, irc_pass, qnvoicefile;

	bool bool_send_qrgs, bool_irc_debug, bool_dtmf_debug, bool_regen_header, bool_qso_details, bool_send_aprs, playNotInCache;
	bool is_icom, is_not_icom;

	int play_wait, play_delay, echotest_rec_timeout, voicemail_rec_timeout, from_remote_g2_timeout, from_local_rptr_timeout, dtmf_digit;

	unsigned int vPacketCount;

	std::map <uint32_t, uint16_t> portmap;

	// data needed for aprs login and aprs beacon
	// RPTR defined in aprs.h
	SRPTR rptr;

	// local repeater modules being recorded
	// This is for echotest and voicemail
	SECHO recd[3], vm[3];
	SDSVT recbuf; // 56 or 27, max is 56

	// the streamids going to remote Gateways from each local module
	STOREMOTEG2 to_remote_g2[3]; // 0=A, 1=B, 2=C

	// input from remote G2 gateway
	int g2_sock = -1;
	struct sockaddr_in fromDst4;

	// Incoming data from remote systems
	// must be fed into our local repeater modules.
	STOREPEATER toRptr[3]; // 0=A, 1=B, 2=C

	// input from our own local repeater modules
	int srv_sock = -1;
	SDSTR rptrbuf; // 58 or 29 or 32, max is 58
	struct sockaddr_in fromRptr;

	SDSTR end_of_audio;

	// send packets to g2_link
	struct sockaddr_in plug;

	// for talking with the irc server
	CIRCDDB *ii;
	// for handling APRS stuff
	CAPRS *aprs;

	// text coming from local repeater bands
	SBANDTXT band_txt[3]; // 0=A, 1=B, 2=C

	/* Used to validate MYCALL input */
	regex_t preg;

	// CACHE used to cache users, repeaters,
	// gateways, IP numbers coming from the irc server

	std::map<std::string, std::string> user2rptr_map, rptr2gwy_map, gwy2ip_map;

	pthread_mutex_t irc_data_mutex = PTHREAD_MUTEX_INITIALIZER;

	int open_port(const SPORTIP &pip);
	void calcPFCS(unsigned char *packet, int len);
	void GetIRCDataThread();
	int get_yrcall_rptr_from_cache(char *call, char *arearp_cs, char *zonerp_cs, char *mod, char *ip, char RoU);
	bool get_yrcall_rptr(char *call, char *arearp_cs, char *zonerp_cs, char *mod, char *ip, char RoU);
	void PlayFileThread(SECHO &edata);
	void compute_aprs_hash();
	void APRSBeaconThread();
	void ProcessTimeouts();
	void ProcessSlowData(unsigned char *data, unsigned short sid);
	bool Flag_is_ok(unsigned char flag);

	// read configuration file
	bool read_config(char *);
	bool get_value(const Config &cfg, const std::string path, int &value, int min, int max, int default_value);
	bool get_value(const Config &cfg, const std::string path, double &value, double min, double max, double default_value);
	bool get_value(const Config &cfg, const std::string path, bool &value, bool default_value);
	bool get_value(const Config &cfg, const std::string path, std::string &value, int min, int max, const char *default_value);

/* aprs functions, borrowed from my retired IRLP node 4201 */
	void gps_send(short int rptr_idx);
	bool verify_gps_csum(char *gps_text, char *csum_text);
	void build_aprs_from_gps_and_send(short int rptr_idx);

	void qrgs_and_maps();

	void set_dest_rptr(int mod_ndx, char *dest_rptr);
	bool validate_csum(SBANDTXT &bt, bool is_gps);
};
