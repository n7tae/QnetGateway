#pragma once
/*
 *   Copyright 2017-2019 by Thomas Early, N7TAE
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
typedef struct dstr_tag {
	unsigned char pkt_id[4];	//  0	"DSTR"
	unsigned short counter;		//  4
	unsigned char flag[3];		//  6	{ 0x73, 0x12, 0x00 }
	unsigned char remaining;	//  9	the number of bytes left in the packet
	union {
		struct {
			unsigned char mycall[8];	// 10
			unsigned char rpt[8];		// 18
		} spkt;							// total 26
		struct {
			unsigned char icm_id;		// 10
			unsigned char dst_rptr_id;	// 11
			unsigned char snd_rptr_id;	// 12
			unsigned char snd_term_id;	// 13
			unsigned short streamid;	// 14
			unsigned char ctrl;			// 16	sequence number hdr=0, voice%21, end|=0x40
			union {
				struct {
					unsigned char flag[3];	// 17
					unsigned char r2[8];	// 20
					unsigned char r1[8];	// 28
					unsigned char ur[8];	// 36
					unsigned char my[8];	// 44
					unsigned char nm[4];	// 52
					unsigned char pfcs[2];	// 56
				} hdr;						// total 58
				union {
					struct {
						unsigned char voice[9];	// 17
						unsigned char text[3];	// 26
					} vasd;						// total 29
					struct {
						unsigned char UNKNOWN[3];	// 17 not sure what this is, but g2_ doesn't seem to need it
						unsigned char voice[9];		// 20
						unsigned char text[3];		// 29
					} vasd1;						// total 32
				};
			};
		} vpkt;
	};
} SDSTR;
#pragma pack(pop)

// for the g2 external port and between QnetGateway programs
#pragma pack(push, 1)
typedef struct dsvt_tag {
	unsigned char title[4];	//  0   "DSVT"
	unsigned char config;	//  4   0x10 is hdr 0x20 is vasd
	unsigned char flaga[3];	//  5   zeros
	unsigned char id;		//  8   0x20
	unsigned char flagb[3];	//  9   0x0 0x1 (A:0x3 B:0x1 C:0x2)
	unsigned short streamid;// 12
	unsigned char ctrl;		// 14   hdr: 0x80 vsad: framecounter (mod 21)
	union {
		struct {                    // index
			unsigned char flag[3];  // 15
			unsigned char rpt1[8];	// 18
			unsigned char rpt2[8];  // 26
			unsigned char urcall[8];// 34
			unsigned char mycall[8];// 42
			unsigned char sfx[4];   // 50
			unsigned char pfcs[2];  // 54
		} hdr;						// total 56
		struct {
			unsigned char voice[9]; // 15
			unsigned char text[3];  // 24
		} vasd;	// voice and slow data total 27
	};
} SDSVT;
#pragma pack(pop)

// for mmdvm
#pragma pack(push, 1)
typedef struct dsrp_tag {	//									offset	  size
	unsigned char title[4];	// "DSRP"								 0
	unsigned char tag;		// Poll   : 0xA							 4
							// Header : busy ? 0x22 : 0x20
							// Voice  : busy ? 0x23 : 0x21
	union {
		unsigned char poll_msg[59];	// space for text				 5		variable, max is 64, including trailing null
		struct {
			unsigned short id;		// random id number				 5
			unsigned char seq;		// 0x0							 7
			unsigned char flag[3];	// 0x80 Dstar Data				 8
									// 0x40 Dstar Repeater
									// 0x01 Dstar Relay Unavailable
			unsigned char r2[8];	// Repeater 2					11
			unsigned char r1[8];	// Repeater 1					19
			unsigned char ur[8];	// Your Call					27
			unsigned char my[8];	// My Call						35
			unsigned char nm[4];	// Name							43
			unsigned char pfcs[2];	// checksum						47		49
		} header;
		struct {
			unsigned short id;		// random id number				 5
			unsigned char seq;		// sequence from 0 to 0x14		 7
									// if end then sequence |= 0x40
			unsigned char err;		// # of errors?					 8
			unsigned char ambe[12];	// voice + slow data			 9		21
		} voice;
	};
} SDSRP;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct link_family_tag {
    char title[4];
    int family[3];
} SLINKFAMILY;
#pragma pack(pop)
