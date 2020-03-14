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

#include "DStarDecode.h"

#define X22             0x00400000   /* vector representation of X^{22} */
#define X11             0x00000800   /* vector representation of X^{11} */
#define MASK12          0xfffff800   /* auxiliary vector for testing */
#define GENPOL          0x00000c75   /* generator polinomial, g(x) */

static const int bit_pos1[] = {
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

static const int bit_pos2[] = {
	23, 11, 23, 11, 23, 11,
	22, 10, 22, 10, 22, 10,
	21,  9, 21,  9, 21,  9,
	20,  8, 20,  8, 20,  8,
	19,  7, 19,  7, 19,  7,
	18,  6, 18,  6, 18,  6,
	17,  5, 17,  5, 17,  5,
	16,  4, 16,  4, 16,  4,
	15,  3, 15,  3, 15,  3,
	14,  2, 14,  2, 14,  2,
	13,  1, 13,  1, 13,  1,
	12,  0, 12,  0, 12,  0
};

CDStarDecode::CDStarDecode(void)
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

long CDStarDecode::arr2int(int *a, int r)
/*
 * Convert a binary vector of Hamming weight r, and nonzero positions in
 * array a[1]...a[r], to a long integer \sum_{i=1}^r 2^{a[i]-1}.
 */
{
	int i;
	long mul, result = 0, temp;

	for (i=1; i<=r; i++) {
		mul = 1;
		temp = a[i]-1;
		while (temp--)
			mul = mul << 1;
		result += mul;
	}
	return(result);
}

void CDStarDecode::nextcomb(int n, int r, int *a)
/*
 * Calculate next r-combination of an n-set.
 */
{
	int  i, j;

	a[r]++;
	if (a[r] <= n)
		return;
	j = r - 1;
	while (a[j] == n - r + j)
		j--;
	for (i = r; i >= j; i--)
		a[i] = a[j] + i - j + 1;
	return;
}

long CDStarDecode::get_syndrome(long pattern)
/*
 * Compute the syndrome corresponding to the given pattern, i.e., the
 * remainder after dividing the pattern (when considering it as the vector
 * representation of a polynomial) by the generator polynomial, GENPOL.
 * In the program this pattern has several meanings: (1) pattern = infomation
 * bits, when constructing the encoding table; (2) pattern = error pattern,
 * when constructing the decoding table; and (3) pattern = received vector, to
 * obtain its syndrome in decoding.
 */
{
//    long aux = X22, aux2;
	long aux = X22;

	if (pattern >= X11)
		while (pattern & MASK12) {
			while (!(aux & pattern))
				aux = aux >> 1;
			pattern ^= (aux/X11) * GENPOL;
		}
	return(pattern);
}

int CDStarDecode::golay2412(int data, int *decoded)
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

int CDStarDecode::Decode(const unsigned char *d, int data[3])
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
