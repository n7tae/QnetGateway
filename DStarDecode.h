#pragma once
/*
 *   Copyright (c) 1994 by Robert Morelos-Zaragoza. All rights reserved.
 *   See http://www.eccpage.com/golay23.c
 *   Copyright (C) 2010 by Michael Dirska, DL1BFF (dl1bff@mdx.de)
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

class CDStarDecode {
public:
	CDStarDecode();
	~CDStarDecode() {}
	int Decode(const unsigned char *d, int data[3]);

private:
	// functions
	long get_syndrome(long pattern);
	long arr2int(int a[], int r);
	void nextcomb(int n, int r, int a[]);
	int golay2412(int data, int *decoded);

	// data
	long decoding_table[2048];
	int prng[4096];
};
