/*

ircDDB-mheard

Copyright (C) 2010   Michael Dirska, DL1BFF (dl1bff@mdx.de)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include "dstar_dv.h"
#include "golay23.h"

int bit_pos1[] = {
	0, 0,  1, 1,  2, 2,
	0, 0,  1, 1,  2, 2,
	0, 0,  1, 1,  2, 2,
	0, 0,  1, 1,  2, 2,
	0, 0,  1, 1,  2, 2,
	0, 0,  1, 1,  2, 2,

	0, 0,  1, 1,  2, 2,
	0, 0,  1, 1,  2, 2,
	0, 0,  1, 1,  2, 2,
	0, 0,  1, 1,  2, 2,
	0, 0,  1, 1,  2, 2,
	0, 0,  1, 1,  2, 2
};

int bit_pos2[] = {
	23, 11,
	23, 11,
	23, 11,

	22, 10,
	22, 10,
	22, 10,

	21, 9,
	21, 9,
	21, 9,

	20, 8,
	20, 8,
	20, 8,

	19, 7,
	19, 7,
	19, 7,

	18, 6,
	18, 6,
	18, 6,

	17, 5,
	17, 5,
	17, 5,

	16, 4,
	16, 4,
	16, 4,

	15, 3,
	15, 3,
	15, 3,

	14, 2,
	14, 2,
	14, 2,

	13, 1,
	13, 1,
	13, 1,

	12, 0,
	12, 0,
	12, 0

};



static long decoding_table[2048];
static int prng[4096];

static void init_prng(void)
{
	int i;

	for (i=0; i < 4096; i++) {
		int mask = 0x800000;
		int j;
		int pr;

		prng[i] = 0;
		pr = i << 4;

		for (j=0; j < 24; j++) {
			pr = ((173 * pr) + 13849) & 0xFFFF;

			if ((pr & 0x8000) != 0) {
				prng[i] |= mask;
			}

			mask = mask >> 1;
		}
	}

}

void dstar_dv_init(void)
{
	long temp;
	int i;
	int a[4];

	decoding_table[0] = 0;
	decoding_table[1] = 1;
	temp = 1;
	for (i=2; i<= 23; i++) {
		temp = temp << 1;
		decoding_table[get_syndrome(temp)] = temp;
	}

	a[1] = 1;
	a[2] = 2;
	temp = arr2int(a,2);
	decoding_table[get_syndrome(temp)] = temp;
	for (i=1; i<253; i++) {
		nextcomb(23,2,a);
		temp = arr2int(a,2);
		decoding_table[get_syndrome(temp)] = temp;
	}

	a[1] = 1;
	a[2] = 2;
	a[3] = 3;
	temp = arr2int(a,3);
	decoding_table[get_syndrome(temp)] = temp;
	for (i=1; i<1771; i++) {
		nextcomb(23,3,a);
		temp = arr2int(a,3);
		decoding_table[get_syndrome(temp)] = temp;
	}

	init_prng();
}


static int golay2412 (int data, int *decoded)
{
	int block = (data >> 1) & 0x07fffff;
	int corrected_block = block ^ decoding_table[get_syndrome(block)];

	int errs = 0;
	int parity_corr = 0;
	int i;

	for (i = 0; i < 23; i++) {
		int mask = 1 << i;

		int bit_rcvd = block & mask;
		int bit_corr = corrected_block & mask;

		if (bit_corr != 0) {
			parity_corr ++;
		}

		if (bit_rcvd != bit_corr) {
			errs ++;
		}
	}

	if ((parity_corr & 0x01) != (data & 0x01)) {
		errs ++;
	}

	*decoded = corrected_block >> 11;

	return errs;
}


int dstar_dv_decode_first_block (const unsigned char * d, int * errs)
{
	int bits[3];
	int i;
	int data;

	for (i=0; i < 3; i++) {
		bits[i] = 0;
	}

	for (i=0; i < 72; i++) {
		bits[ bit_pos1[i] ] |= (d[ i >> 3 ] & (0x80 >> (i & 0x07))) ? (1 << bit_pos2[i]) : 0;
	}

	*errs = golay2412( bits[0], & data );

	return data;

}

int dstar_dv_decode (const unsigned char * d, int data[3])
{
	int bits[3];
	int i;
	int errs;

	for (i=0; i < 3; i++) {
		bits[i] = 0;
	}

	for (i=0; i < 72; i++) {
		bits[ bit_pos1[i] ] |= (d[ i >> 3 ] & (0x80 >> (i & 0x07))) ? (1 << bit_pos2[i]) : 0;
	}

	errs = golay2412( bits[0], data );

	errs += golay2412( bits[1] ^ prng[ data[0] & 0x0fff ], data + 1 );

	data[2] = bits[2];

	return errs;
}

