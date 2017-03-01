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
	unsigned char pkt_id[4];
	unsigned short counter;
	unsigned char flag[2];
	unsigned char nothing2[2];
	union {
		struct {
			unsigned char mycall[8];
			unsigned char rpt[8];
		} spkt;
		struct {
			struct {
				unsigned char icm_id;
				unsigned char dst_rptr_id;
				unsigned char snd_rptr_id;
				unsigned char snd_term_id;
				uint16_t streamid;
				unsigned char ctrl;
			} icm;
			union {
				struct {
					unsigned char flag[3];
					unsigned char rpt1[8];
					unsigned char rpt2[8];
					unsigned char urcall[8];
					unsigned char mycall[8];
					unsigned char sfx[4];
					unsigned char pfcs[2];
				} hdr;	// 41 byte header
				struct {
					unsigned char voice[9];
					unsigned char text[3];
				} vasd;	// 12 byte voice and slow data
			};
		} vpkt;
	};
} SPKT;
#pragma pack(pop)

