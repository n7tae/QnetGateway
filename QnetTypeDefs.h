#pragma once
/*
 *   Copyright 2017-2021 by Thomas Early, N7TAE
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

// for communicating with the g2 gateway on the internal port
#pragma pack(push, 1)	// used internally by Icom stacks
using SDSTR = struct dstr_tag
{
	uint8_t pkt_id[4];	//  0	"DSTR"
	uint16_t counter;		//  4
	uint8_t flag[3];		//  6	{ 0x73, 0x12, 0x00 }
	uint8_t remaining;	//  9	the number of bytes left in the packet
	union
	{
		struct
		{
			uint8_t mycall[8];	// 10
			uint8_t rpt[8];		// 18
		} spkt;							// total 26
		struct
		{
			uint8_t icm_id;		// 10
			uint8_t dst_rptr_id;	// 11
			uint8_t snd_rptr_id;	// 12
			uint8_t snd_term_id;	// 13
			uint16_t streamid;	// 14
			uint8_t ctrl;			// 16	sequence number hdr=0, voice%21, end|=0x40
			union
			{
				struct
				{
					uint8_t flag[3];	// 17
					uint8_t r2[8];	// 20
					uint8_t r1[8];	// 28
					uint8_t ur[8];	// 36
					uint8_t my[8];	// 44
					uint8_t nm[4];	// 52
					uint8_t pfcs[2];	// 56
				} hdr;						// total 58
				union
				{
					struct
					{
						uint8_t voice[9];	// 17
						uint8_t text[3];	// 26
					} vasd;						// total 29
					struct
					{
						uint8_t UNKNOWN[3];	// 17 not sure what this is, but g2_ doesn't seem to need it
						uint8_t voice[9];		// 20
						uint8_t text[3];		// 29
					} vasd1;						// total 32
				};
			};
		} vpkt;
	};
};
#pragma pack(pop)

// for the g2 external port and between QnetGateway programs
#pragma pack(push, 1)
using SDSVT = struct dsvt_tag
{
	uint8_t title[4];	//  0   "DSVT"
	uint8_t config;	//  4   0x10 is hdr 0x20 is vasd
	uint8_t flaga[3];	//  5   zeros
	uint8_t id;		//  8   0x20
	uint8_t flagb[3];	//  9   0x0 0x1 (A:0x3 B:0x1 C:0x2)
	uint16_t streamid;// 12
	uint8_t ctrl;		// 14   hdr: 0x80 vsad: framecounter (mod 21)
	union
	{
		struct                      // index
		{
			uint8_t flag[3];  // 15
			uint8_t rpt1[8];	// 18
			uint8_t rpt2[8];  // 26
			uint8_t urcall[8];// 34
			uint8_t mycall[8];// 42
			uint8_t sfx[4];   // 50
			uint8_t pfcs[2];  // 54
		} hdr;						// total 56
		struct
		{
			uint8_t voice[9]; // 15
			uint8_t text[3];  // 24
		} vasd;	// voice and slow data total 27
		struct
		{
			uint8_t voice[9];	  // 15
			uint8_t textend[6]; // 24
		} vend;	// voice and end seq total 32 (for DPlus)
	};
};
#pragma pack(pop)

// for mmdvm
#pragma pack(push, 1)
using SDSRP = struct dsrp_tag  	//									offset	  size
{
	uint8_t title[4];	// "DSRP"								 0
	uint8_t tag;		// Poll   : 0xA							 4
							// Header : busy ? 0x22 : 0x20
							// Voice  : busy ? 0x23 : 0x21
	union
	{
		uint8_t poll_msg[59];	// space for text				 5		variable, max is 64, including trailing null
		struct
		{
			uint16_t id;		// random id number				 5
			uint8_t seq;		// 0x0							 7
			uint8_t flag[3];	// 0x80 Dstar Data				 8
									// 0x40 Dstar Repeater
									// 0x01 Dstar Relay Unavailable
			uint8_t r2[8];	// Repeater 2					11
			uint8_t r1[8];	// Repeater 1					19
			uint8_t ur[8];	// Your Call					27
			uint8_t my[8];	// My Call						35
			uint8_t nm[4];	// Name							43
			uint8_t pfcs[2];	// checksum						47		49
		} header;
		struct
		{
			uint16_t id;		// random id number				 5
			uint8_t seq;		// sequence from 0 to 0x14		 7
			// if end then sequence |= 0x40
			uint8_t err;		// # of errors?					 8
			uint8_t ambe[12];	// voice + slow data			 9		21
		} voice;
		struct
		{
			uint16_t id;		// random id number				 5
			uint8_t seq;		// sequence from 0 to 0x14		 7
			// if end then sequence |= 0x40
			uint8_t err;		// # of errors?					 8
			uint8_t ambe[15];	// voice + slow data			 9		24
		} endvoice;
	};
};
#pragma pack(pop)

#pragma pack(push, 1)
using SLINKFAMILY = struct link_family_tag
{
	char title[4];
	int family[3];
};
#pragma pack(pop)
