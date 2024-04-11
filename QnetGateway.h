/*
 *   Copyright (C) 2018-2020 by Thomas Early N7TAE
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

#include <set>
#include <regex>
#include <future>
#include <queue>

#include "IRCDDB.h"
#include "QnetTypeDefs.h"
#include "SEcho.h"
#include "UnixDgramSocket.h"
#include "UnixPacketSock.h"
#include "aprs.h"
#include "SockAddress.h"
#include "QnetDB.h"
#include "DStarDecode.h"
#include "KRBase.h"
#include "Location.h"

#define MAXHOSTNAMELEN 64
#define CALL_SIZE 8
#define MAX_DTMF_BUF 32

using STOREMOTEG2 = struct to_remote_g2_tag
{
	unsigned short streamid;
	CSockAddress toDstar;
	time_t last_time;
};

using STOREPEATER = struct torepeater_tag
{
	// help with header re-generation
	SDSVT saved_hdr; // repeater format
	time_t last_time;
	unsigned char sequence;
};

using SBANDTXT = struct band_txt_tag
{
	unsigned short streamID;
	unsigned char flags[3];
	std::string mycall, sfx, urcall, rpt1, rpt2, txt, dest_rptr;
	time_t last_time, gps_last_time;
	bool sent_key_on_msg, is_gps_sent;

	int num_dv_frames;
	int num_dv_silent_frames;
	int num_bit_errors;

	void Initialize()
	{
		streamID = 0x0U;
		last_time = gps_last_time = 0;
		is_gps_sent = sent_key_on_msg = false;
		num_dv_frames = num_dv_silent_frames = num_bit_errors = 0;
		flags[0] = flags[1] = flags[2] = 0x0U;
		mycall.clear();
		sfx.clear();
		urcall.clear();
		rpt1.clear();
		rpt2.clear();
		txt.clear();
		dest_rptr.clear();
	}
};

using SSD = struct sd_tag
{
	unsigned char header[41];
	unsigned char message[21];
	unsigned char gps[256];
	unsigned int ih, im, ig;
	unsigned char type;
	bool first;
	unsigned int size;
	void Init() { ih = im = ig = 0; first = true; }
};

class CQnetGateway : public CKRBase
{
public:
	CQnetGateway();
	~CQnetGateway();
	void Process();
	bool Init(char *cfgfile);

private:
	std::queue<std::future<void>> m_fqueue;
	// link type
	int link_family[3] = { AF_UNSPEC, AF_UNSPEC, AF_UNSPEC };
	// network type
	int af_family[2] = { AF_UNSPEC, AF_UNSPEC };

	int Index[3] = { -1, -1, -1 };

	SPORTIP g2_external, g2_ipv6_external, ircddb[2];

	CUnixDgramReader FromRemote;
	CUnixPacketServer ToLink, ToModem[3];

	std::string tolink, fromremote, tomodem[3];

	std::string OWNER, owner, FILE_DTMF, FILE_ECHOTEST, IRCDDB_PASSWORD[2], FILE_QNVOICE_FILE, DASH_SHOW_ORDER;

	bool GATEWAY_SEND_QRGS_MAP, GATEWAY_HEADER_REGEN, APRS_ENABLE, playNotInCache, showLastHeard;
	bool LOG_DEBUG, LOG_IRC, LOG_DTMF, LOG_QSO, IS_HF[3];

	int DASH_REFRESH, TIMING_PLAY_WAIT, TIMING_PLAY_DELAY, TIMING_TIMEOUT_ECHO, TIMING_TIMEOUT_VOICEMAIL, TIMING_TIMEOUT_REMOTE_G2, TIMING_TIMEOUT_LOCAL_RPTR, dtmf_digit;

	unsigned int vPacketCount[3] = { 0, 0, 0 };

	std::set<std::string> findRoute;

	// data needed for aprs login and aprs beacon
	// RPTR defined in aprs.h
	SRPTR Rptr;

	// local repeater modules being recorded
	// This is for echotest and voicemail
	SECHO recd[3], vm[3];
	SDSVT recbuf; // 56 or 27, max is 56

	// the streamids going to remote Gateways from each local module
	STOREMOTEG2 to_remote_g2[3]; // 0=A, 1=B, 2=C

	// input from remote G2 gateway
	int g2_sock[2] = { -1, -1 };
	CSockAddress fromDstar;

	// Incoming data from remote systems
	// must be fed into our local repeater modules.
	STOREPEATER toRptr[3]; // 0=A, 1=B, 2=C

	SDSVT end_of_audio, sdheader;

	// send packets to g2_link
	struct sockaddr_in plug;

	// for talking with the irc server
	CIRCDDB *ii[2];
	// for handling APRS stuff
	CAPRS *aprs;
	// for parsign GPS slow data
	CLocation gps;

	// text coming from local repeater bands
	SBANDTXT band_txt[3]; // 0=A, 1=B, 2=C

	/* Used to validate MYCALL input */
	std::regex preg;

	// database for the dashboard last heard section
	CQnetDB qnDB;

	// for bit error rate calcs
	CDStarDecode decode;

	// g2 data
	std::string lhcallsign[3], lhsfx[3];
	unsigned char nextctrl[3] = { 0U, 0U, 0U };
	std::string superframe[3];

	// dtmf stuff
	int dtmf_buf_count[3];
	char dtmf_buf[3][MAX_DTMF_BUF + 1];
	int dtmf_last_frame[3];
	unsigned int dtmf_counter[3];

	bool VoicePacketIsSync(const unsigned char *text) const;
	int open_port(const SPORTIP *pip, int family);
	void calcPFCS(unsigned char *packet, int len);
	void GetIRCDataThread(const int i);
	int get_yrcall_rptr_from_cache(const int i, const std::string &call, std::string &rptr, std::string &gate, std::string &addr, char RoU);
	int get_yrcall_rptr(const std::string &call, std::string &rptr, std::string &gate, std::string &addr, char RoU);
	void PlayFileThread(SECHO &edata);
	void compute_aprs_hash();
	void APRSBeaconThread();
	bool Printable(unsigned char *string);
	void ProcessTimeouts();
	void ProcessSlowData(unsigned char *data, const unsigned short sid);
	void ProcessIncomingSD(const SDSVT &dsvt, const int source_sock);
	void ProcessOutGoingSD(const SDSVT &dsvt, const int mod);
	bool ProcessG2Msg(const unsigned char *data, const int mod, std::string &smrtgrp);
	void ProcessG2(const ssize_t g2buflen, SDSVT &g2buf, const int sock_source);
	void ProcessG2Header(const SDSVT &g2buf, const int source_sock);
	void ProcessModem(const ssize_t len, SDSVT &dsvt);
	bool Flag_is_ok(unsigned char flag);
	void UnpackCallsigns(const std::string &str, std::set<std::string> &set, const std::string &delimiters = ",");
	void PrintCallsigns(const std::string &key, const std::set<std::string> &set);
	int FindIndex(const int i) const;

	// read configuration file
	bool ReadConfig(char *);

	void qrgs_and_maps();

	void set_dest_rptr(const char mod, std::string &call);

	// for incoming slow header stuff;
	SSD sdin[4], sdout[3];
};
