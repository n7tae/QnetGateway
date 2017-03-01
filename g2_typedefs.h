#pragma once
/*
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

// for communicating with the g2 gateway

#pragma pack(push, 1)	// we need to be sure these structures don't have any dead space
typedef struct pkt_tag {
	unsigned char pkt_id[4];		//  0
	unsigned short counter;			//  4
	unsigned char flag[2];			//  6
	unsigned char nothing2[2];		//  8
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
			uint16_t streamid;			// 14
			unsigned char ctrl;			// 16
			union {
				struct {
					unsigned char flag[3];	// 17
					unsigned char rpt1[8];	// 20
					unsigned char rpt2[8];	// 28
					unsigned char urcall[8];// 36
					unsigned char mycall[8];// 44
					unsigned char sfx[4];	// 52
					unsigned char pfcs[2];	// 56
				} hdr;						// total 58
				struct {
					unsigned char voice[9];	// 17
					unsigned char text[3];	// 26
				} vasd;						// total 29
			};
		} vpkt;
	};
} SPKT;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct dsvt_tag {
	unsigned char title[4];	//  0   "DSVT"
	unsigned char config;	//  4   0x10 is hdr 0x20 is vasd
	unsigned char flaga[3];	//  5   zeros
	unsigned char id;		//  8   0x20 
	unsigned char flagb[3];	//  9   0x0 0x1 0x1
	unsigned short streamid;// 12
	unsigned char counter;	// 14   hdr: 0x80 vsad: framecounter (mod 21)
	union {
		struct {                    // index
			unsigned char flag[3];  // 15
			unsigned char rpt1[8];  // 18
			unsigned char rpt2[8];  // 26
			unsigned char urcall[8];// 34
			unsigned char mycall[8];// 42
			unsigned char sfx[4];   // 50
			unsigned char pfcs[2];  // 54
		} hdr;
		struct {
			unsigned char voice[9]; // 15
			unsigned char text[3];  // 24
		} vasd;
	};
} SDSVT;
#pragma pack(pop)
