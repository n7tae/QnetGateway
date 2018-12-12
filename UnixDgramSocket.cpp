/*
 *   Copyright (C) 2018 by Thomas Early N7TAE
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

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "UnixDgramSocket.h"

CUnixDgramReader::CUnixDgramReader() : fd(-1) {}

CUnixDgramReader::~CUnixDgramReader()
{
	Close();
}

bool CUnixDgramReader::Open(const char *path)	// returns true on failure
{
	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "CUnixDgramReader::Open: socket() failed: %s\n", strerror(errno));
		return true;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path+1, path, sizeof(addr.sun_path)-2);

	int rval = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (rval < 0) {
		fprintf(stderr, "CUnixDgramReader::Open: bind() failed: %s\n", strerror(errno));
		close(fd);
		fd = -1;
		return true;
	}
	return false;
}

ssize_t CUnixDgramReader::Read(void *buf, size_t size)
{
	if (fd >= 0)
		return read(fd, buf, size);
	return -1;
}

void CUnixDgramReader::Close()
{
	if (fd >= 0)
		close(fd);
	fd = -1;
}

int CUnixDgramReader::GetFD()
{
	return fd;
}

CUnixDgramWriter::CUnixDgramWriter() : fd(-1) {}

CUnixDgramWriter::~CUnixDgramWriter()
{
	Close();
}

bool CUnixDgramWriter::Open(const char *path)	// returns true on failure
{
	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "CUnixDgramWriter::Open: socket() failed: %s\n", strerror(errno));
		return true;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path+1, path, sizeof(addr.sun_path)-2);

	int rval = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (rval < 0) {
		fprintf(stderr, "CUnixDgramWriter::Open: connect() failed: %s\n", strerror(errno));
		close(fd);
		fd = -1;
		return true;
	}
	return false;
}

ssize_t CUnixDgramWriter::Write(void *buf, size_t size)
{
	if (fd >= 0)
		return write(fd, buf, size);
	return -1;
}

void CUnixDgramWriter::Close()
{
	if (fd >= 0)
		close(fd);
	fd = -1;
}

int CUnixDgramWriter::GetFD()
{
	return fd;
}
