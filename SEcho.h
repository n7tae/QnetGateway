#pragma once
/*
 *   Copyright 2018-2019 by Thomas Early, N7TAE
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

typedef struct echo_tag {
	bool is_linked;
	time_t last_time;
	unsigned short streamid;
	int fd;
	char message[24];
    SDSVT header;   // only used in qnlink (qngateway writes the header to the file)
	char file[FILENAME_MAX + 1];
} SECHO;
