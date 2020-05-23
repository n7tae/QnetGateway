#pragma once

/*
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

#include <sys/types.h>

class CUnixPacket {
public:
	CUnixPacket();
	virtual bool Open(const char *name) = 0;
	virtual void Close() = 0;
	bool Write(const void *buffer, const ssize_t size) const;
	ssize_t Read(void *buffer, const ssize_t size);
	int GetFD();
protected:
	int m_fd;
};

class CUnixPacketServer : public CUnixPacket {
public:
	CUnixPacketServer();
	~CUnixPacketServer();
	bool Open(const char *name);
	void Close();
protected:
	int m_server;
};

class CUnixPacketClient : public CUnixPacket {
public:
	~CUnixPacketClient();
	bool Open(const char *name);
	void Close();
};
