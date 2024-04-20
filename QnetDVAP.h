#pragma once

/*
 *   Copyright (C) 2018,2020 by Thomas A. Early N7TAE
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

#include <future>

#include "UnixDgramSocket.h"
#include "Base.h"

using SDVAP_ACK_ARG = struct davp_ack_arg_tag
{
	char mycall[8];
	float ber;
};

class CQnetDVAP : public CModem
{
public:
	CQnetDVAP(int index) : CModem(index) {}
	~CQnetDVAP() {}
	bool Initialize(const std::string &path);
	void Run();
	void Close();

private:
	bool ReadConfig(const std::string &path);
	void ReadFromGateway();
	void calcPFCS(unsigned char *packet, unsigned char *pfcs);
	void ReadDVAPThread();
	void RptrAckThread(SDVAP_ACK_ARG *parg);


	// classes
	CDStarDecode decode;
	CDVAPDongle dongle;
	CRandom Random;

	// data
	std::future<void> m_readThread;

	// unix sockets
	CUnixDgramWriter ToGate;
	CUnixDgramReader FromGate;
	/* Default configuration data */
	std::string RPTR;
	std::string OWNER;
	char RPTR_MOD;
	std::string MODULE_SERIAL_NUMBER;	/* AP123456 */
	std::string MODULE_DEVICE;			/* /dev/ttyUSBx */
	int MODULE_FREQUENCY;				/* between 144000000 and 148000000 */
	int MODULE_POWER;					/* between  -12 and 10 */
	int MODULE_SQUELCH; 				/* between  -128 and -45 */
	int MODULE_OFFSET;					/* between -2000 and 2000 */
	int MODULE_PACKET_WAIT;				/* wait 25 ms in reading from local G2 */
	int TIMING_TIMEOUT_REMOTE_G2;		/* 1 second */
	int TIMING_PLAY_DELAY;
	int TIMING_PLAY_WAIT;
	bool MODULE_ACKNOWLEDGE;
	double TIMING_TIMEOUT_LOCAL_RPTR;
	bool LOG_DEBUG;
	bool LOG_QSO;
	int inactiveMax = 25;

	/* helper data */
	unsigned char SND_TERM_ID;
	char RPTR_and_G[9];
	char RPTR_and_MOD[9];
	int serfd = -1;
	bool busy20000 = false;

	unsigned int space = 0;
};
