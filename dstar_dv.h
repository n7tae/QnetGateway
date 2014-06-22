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

/* Call this function first before using any of the other functions */
void dstar_dv_init(void);

/*
This function decodes the first and most important Golay block
of a DSTAR Digital Voice frame. The function is provided with a
pointer to the 9-byte voice data. Result is the decoded
first block. The number of decoding errors is reported in the
variable errs and ranges from 0 to 4. Only 24 bits are
checked, the BER therefore is:  BER = errs / 24
 */
int dstar_dv_decode_first_block (const unsigned char * d, int * errs);

/*
This function decodes the both Golay blocks
of a DSTAR Digital Voice frame. The function is provided with a
pointer to the 9-byte voice data. Function result is
the number of decoding errors (0 to 8). Only 48 bits are
checked, the BER therefore is:  BER = errs / 48

The return value data[0] contains the first decoded golay block
(12 bits).  The return value data[1] contains the second decoded
golay block (12 bits). The return value data[2] contains the
unprotected rest of the frame (24 bits).
*/
int dstar_dv_decode (const unsigned char * d, int data[3]);

