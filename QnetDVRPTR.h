#pragma once
/*
 *   Copyright (C) 2020 by Thomas Early N7TAE
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

#include <cstdint>
#include <string>

#include "UnixDgramSocket.h"
#include "DStarDecode.h"
#include "QnetTypeDefs.h"
#include "Base.h"

using tambevoicefec = unsigned char[9];
using tambevoice = unsigned char[6];

#define interleaveambe12(bp) { bp+=12; if (bp>71) bp -= 71; }
#define CALL_SIZE 8
#define GORLAY_X22	0x00400000	// vector representation of X^{22}
#define GORLAY_X11	0x00000800	// vector representation of X^{11}
#define GORLAY_MASK12	0xfffff800	// auxiliary vector for testing
#define GORLAY_GENPOL	0x00000c75	// generator polinomial, g(x)

class CQnetDVRPTR : public CModem
{
public:
	CQnetDVRPTR(int index) : CModem(index) {}
	~CQnetDVRPTR() {}
	bool Initialize(const std::string &file);
	void Run();
	void Close();

private:
	CDStarDecode decode;
	bool ReadConfig(const std::string &cfgFile);
	void readFrom20000();
	bool check_serial();
	void CleanCall(std::string &callsign);
	void ambefec_deinterleave(tambevoicefec result, const tambevoicefec voice);
	void ambefec_interleave(tambevoicefec result, const tambevoicefec raw_voice);
	void ambefec_regenerate(tambevoicefec voice);
	uint32_t get_syndrome_23127(uint32_t pattern);
	unsigned int gorlay_decode23127(unsigned int code);
	unsigned int gorlay_encode24128(unsigned int data);
	unsigned int gorlay_decode24128(unsigned int code);
	void calcPFCS(unsigned char *packet);
	char *cleanstr(char *Text);
	int open_port(char *dvrptr_device);
	int read_port(int *fd_ser, unsigned char *buffera);
	void send_ack(char *a_call, float ber);
	/*** BER stuff ***/
	int ber_data[3];
	int ber_errs;
	int num_dv_frames;
	int num_bit_errors;

	short block = 0;
	short old_seq_no = 0;

	short seq_no1 = 1;
	short seq_no2 = 1;
	short seq_no3 = 0;
	int fd_ser = -1;
	bool busy20000 = false;

	int rqst_count = 6;
	unsigned short streamid = 0x0;
	unsigned char start_Header[8]= {0xD0,0x03,0x00,0x16,0x01,0x00,0x00,0x00};
	unsigned char ptt_off[8]= {0xD0,0x03,0x00,0x1A,0x01,0xff,0x00,0x00};


	SDSVT Send_Network_Header;
	SDSVT Send_Network_Audio;

	int inactiveMax = 3200;

	unsigned char Send_Modem_Header[52];

	unsigned char writevoice[24];
	unsigned char writevoice1[24];

	// Modem INIT
	unsigned char Modem_Init0[6]= {0xD0,0x01,0x00,0x11,0x00,0x00};
	unsigned char Modem_Init1[7]= {0xD0,0x02,0x00,0x10,0x03,0x00,0x00}; // RX TX Enable
	unsigned char Modem_Init2[12]= {0xD0,0x07,0x00,0x14,0xC0,0x04,0x00,0x57,0x53,0x00,0x00,0x00}; // Modem Init
	unsigned char Modem_STATUS[6]= {0xD0,0x01,0x00,0x10,0x00,0x00}; // Status Abfragr
	unsigned char Modem_SERIAL[6]= {0xD0,0x01,0x00,0x12,0x00,0x00};

	CUnixDgramWriter ToGate;
	CUnixDgramReader FromGate;

	std::string DVRPTR_SERIAL;
	char DVCALL[CALL_SIZE + 1];
	char RPTR[CALL_SIZE + 1];
	char DVRPTR_MOD = 'B';
	int RF_AUDIO_Level = 10;
	bool DUPLEX = true;
	int ACK_DELAY = 200000;
	int DELAY_BETWEEN = 20000;
	bool RPTR_ACK = false;
	char ENABLE_RF[CALL_SIZE + 1];
	char DISABLE_RF[CALL_SIZE + 1];
	bool IS_ENABLED = true;
	bool RX_Inverse = true;
	bool TX_Inverse = true;
	int TX_DELAY;  /* in milliseconds */
	unsigned char SND_TERM_ID = 0x00;
	char DVCALL_and_G[9];
	char DVCALL_and_MOD[9];
	int REMOTE_TIMEOUT = 1;  /* 1 second */
	int RQST_COUNT = 6;
	u_int16_t streamid_raw = 0;
	char myRPT2[10]; //RX from HF RPT2
	char myRPT1[10]; //RX from HF RPT1
	char myUR[10];
	char myCall[10];
	char myCall2[10];

	char cbuf[250];

	SDSVT recv_buf;
	int InitCount;
};
