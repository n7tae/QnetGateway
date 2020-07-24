#pragma once

/*
 *   Copyright (C) 2018-2019 by Thomas A. Early N7TAE
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

#include <regex.h>
#include <string>
#include <map>
#include <vector>
#include <set>
#include <netinet/in.h>

#include "QnetTypeDefs.h"
#include "SEcho.h"
#include "Random.h"
#include "UnixPacketSock.h"
#include "UDPSocket.h"
#include "UDPSocket.h"
#include "Timer.h"
#include "QnetDB.h"
#include "KRBase.h"

/*** version number must be x.xx ***/
#define CALL_SIZE 8
#define IP_SIZE 15
#define QUERY_SIZE 56
#define MAXHOSTNAMELEN 64
#define TIMEOUT 50
#define LH_MAX_SIZE 39

using SREFDSVT = struct refdsvt_tag
{
	unsigned char head[2];
	SDSVT dsvt;
};

using STOREMOTE = struct to_remote_g2_tag
{
	char cs[CALL_SIZE + 1];
	CSockAddress addr;
	char from_mod, to_mod;
	short countdown;
	bool auto_link, is_connected;
	unsigned short in_streamid;  // incoming from remote systems
	unsigned short out_streamid; // outgoing to remote systems
};

// This is the data payload in the map: inbound_list
// This is for inbound dongles
using SINBOUND = struct inbound_tag
{
	char call[CALL_SIZE + 1];	// the callsign of the remote
	CSockAddress addr;			// IP and port of remote
	short countdown;			// if countdown expires, the connection is terminated
	char mod;					// A B C This user talked on this module
	char client;				// dvap, dvdongle
};

using STRACING = struct tracing_tag
{
	unsigned short streamid;
	time_t last_time;	// last time RF user talked
};


class CQnetLink : CKRBase
{
public:
	// functions
	CQnetLink();
	~CQnetLink();
	bool Init(const char *cfgfile);
	void Process();
	void Shutdown();
private:
	// functions
	void ToUpper(std::string &s);
	void UnpackCallsigns(const std::string &str, std::set<std::string> &set, const std::string &delimiters = ",");
	void PrintCallsigns(const std::string &key, const std::set<std::string> &set);
	void LoadGateways(const std::string &filename);
	void calcPFCS(unsigned char *packet, int len);
	bool ReadConfig(const char *);
	bool srv_open();
	void srv_close();
	void g2link(const char from_mod, const char *call, const char to_mod);
	void send_heartbeat();
	bool resolve_rmt(const char *name, const unsigned short port, CSockAddress &addr);
	void rptr_ack(int i);
	void PlayAudioNotifyThread(char *msg);
	void AudioNotifyThread(SECHO &edata);
	void RptrAckThread(char *arg);
	void ProcessXRF(unsigned char *buf, const int length);
	void ProcessDCS(unsigned char *buf, const int length);
	void ProcessREF(unsigned char *buf, const int length);
	void REFWrite(const void *buf, const size_t size, const CSockAddress &addr);
	void DCSWrite(const void *buf, const size_t size, const CSockAddress &addr);
	void XRFWrite(const void *buf, const size_t size, const CSockAddress &addr);

	/* configuration data */
	std::string login_call, owner, to_g2_external_ip, gwys, qnvoice_file, announce_dir;
	bool only_admin_login, only_link_unlink, qso_details, log_debug, bool_rptr_ack, announce;
	bool dplus_authorize, dplus_reflectors, dplus_repeaters, dplus_priority, uses_ipv6;
	unsigned short rmt_xrf_port, rmt_ref_port, rmt_dcs_port, my_g2_link_port, to_g2_external_port;
	int delay_between, delay_before;
	std::string link_at_startup[3];
	unsigned int max_dongles, saved_max_dongles;
	int rf_inactivity_timer[3];
	const unsigned char REF_ACK[3] = { 3, 96, 0 };

	// the Key in this inbound_list map is the unique IP address of the remote
	std::map<std::string, SINBOUND *> inbound_list;

	std::set<std::string> admin, link_unlink_user, link_blacklist;

	std::map<std::string, std::string> dt_lh_list;

	char notify_msg[3][64];

	STOREMOTE to_remote_g2[3];

	// broadcast for data arriving from xrf to local rptr
	struct brd_from_xrf_tag
	{
		unsigned short xrf_streamid;		// streamid from xrf
		unsigned short rptr_streamid[2];	// generated streamid to rptr(s)
	} brd_from_xrf;
	SDSVT from_xrf_torptr_brd;
	short brd_from_xrf_idx;

	// broadcast for data arriving from local rptr to xrf
	struct brd_from_rptr_tag
	{
		unsigned short from_rptr_streamid;
		unsigned short to_rptr_streamid[2];
	} brd_from_rptr;
	SDSVT fromrptr_torptr_brd;
	short brd_from_rptr_idx;

	STRACING tracing[3];

	// input from remote
	//int xrf_g2_sock, ref_g2_sock, dcs_g2_sock;
	CUDPSocket XRFSock4, XRFSock6, DCSSock4, DCSSock6, REFSock4, REFSock6;
	CSockAddress fromDst4;

	// unix sockets to gateway
	std::string togate;
	CUnixPacketClient ToGate;

	struct timeval tv;

	// Used to validate incoming donglers
	regex_t preg;

	unsigned char queryCommand[QUERY_SIZE];

	// START:  TEXT crap
	char dtmf_mycall[3][CALL_SIZE + 1];
	bool new_group[3];
	int header_type;
	bool GPS_seen[3];
	unsigned char tmp_txt[3];
	char *p_tmp2;
	// END:  TEXT crap

	// this is used for the "dashboard and qso_details" to avoid processing multiple headers
	struct old_sid_tag
	{
		unsigned short sid;
	} old_sid[3];

	CRandom Random;
	CQnetDB qnDB;
	std::vector<unsigned long> speak;

	// used for processing loop
	const unsigned char endbytes[6] = { 0x55U, 0x55U, 0x55U, 0x55U, 0xC8U, 0x7AU };
	time_t tnow;
	unsigned char dcs_seq[3] = { 0x00, 0x00, 0x00 };
	struct
	{
		char mycall[9];
		char sfx[5];
		unsigned int dcs_rptr_seq;
	} rptr_2_dcs[3] =
	{
		{"        ", "    ", 0},
		{"        ", "    ", 0},
		{"        ", "    ", 0}
	};
	struct
	{
		char mycall[9];
		char sfx[5];
		unsigned int dcs_rptr_seq;
	} ref_2_dcs[3] =
	{
		{"        ", "    ", 0},
		{"        ", "    ", 0},
		{"        ", "    ", 0}
	};
	struct
	{
		char mycall[9];
		char sfx[5];
		unsigned int dcs_rptr_seq;
	} xrf_2_dcs[3] =
	{
		{"        ", "    ", 0},
		{"        ", "    ", 0},
		{"        ", "    ", 0}
	};
};
