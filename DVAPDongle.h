#pragma once
/*
 *   Copyright 2017 by Thomas Early, N7TAE
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

 #include <stdint.h>

enum REPLY_TYPE {
	RT_TIMEOUT,
	RT_ERR,
	RT_UNKNOWN,
	RT_NAME,
	RT_SER,
	RT_FW,
	RT_START,
	RT_STOP,
	RT_MODU,
	RT_MODE,
	RT_SQL,
	RT_PWR,
	RT_OFF,
	RT_FREQ,
	RT_FREQ_LIMIT,
	RT_STS,
	RT_PTT,
	RT_ACK,
	RT_HDR,
	RT_HDR_ACK,
	RT_DAT
};

#pragma pack(push,1)
typedef struct dvp_register_tag {
	uint16_t header;
	union {
		uint8_t nul;
		struct {
			uint16_t control;
			union {
				int8_t byte;
				int16_t word;
				int32_t dword;
				int32_t twod[2];
				char sstr[12];
				uint8_t ustr[12];
			};
		} param;
		struct {
			uint16_t streamid;
			uint8_t framepos;
			uint8_t seq;
			union {
				struct {
					unsigned char flag[3];
					unsigned char rpt2[8];
					unsigned char rpt1[8];
					unsigned char urcall[8];
					unsigned char mycall[8];
					unsigned char sfx[4];
					unsigned char pfcs[2];
				} hdr;
				struct {
					unsigned char voice;
					unsigned char sdata;
				} vad;
			};
		} frame;
	};
} SDVAP_REGISTER;
#pragma pack(pop)

class CDVAPDongle
{
	public:
		CDVAPDongle();
		~CDVAPDongle();
		bool Initialize(const char *serialno, const int frequency, const int offset, const int power, const int squelch);
		REPLY_TYPE GetReply(SDVAP_REGISTER &dr);
		void Stop();
		int KeepAlive();
		void SendRegister(SDVAP_REGISTER &dr);

	private:
		// data
		int serfd;
		const unsigned int MAX_REPL_CNT;
		uint32_t frequency;
		int32_t offset;
		SDVAP_REGISTER dvapreg;

		// functions
		bool OpenSerial(char *device);
		int read_from_dvp(void* buf, unsigned int len);
		int write_to_dvp(const void* buf, const unsigned int len);
		bool syncit();
		bool get_ser(const char *dvp, const char *dvap_serial_number);
		bool get_name();
		bool get_fw();
		bool set_modu();
		bool set_mode();
		bool set_sql(int squelch);
		bool set_pwr(int power);
		bool set_off(int offset);
		bool set_freq(int frequency);
		bool start_dvap();
};
