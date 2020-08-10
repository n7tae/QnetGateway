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

#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>

#include "UnixPacketSock.h"

CUnixPacket::CUnixPacket() : m_fd(-1), m_host(NULL) {}

ssize_t CUnixPacket::Read(void *buffer, const ssize_t size)
{
	if (0 > m_fd)
		return -1;
	ssize_t len = read(m_fd, buffer, size);
	if (len < 1)
	{
		if (-1 == len)
		{
			std::cerr << "Read error on '" << m_name << "': " << strerror(errno) << std::endl;
		}
		else if (0 == len)
		{
			std::cerr << "Read error on '" << m_name << "': EOF" << std::endl;
		}
		if (Restart())
			return -1;
		else
			return 0;
	}
	return len;
}

bool CUnixPacket::Write(const void *buffer, const ssize_t size)
{
	if (0 > m_fd)
		return true;
	ssize_t written = write(m_fd, buffer, size);
	if (written != size)
	{
		if (-1 == written)
		{
			std::cerr << "Write error on '" << m_name << "': " << strerror(errno) << std::endl;
		}
		else
		{
			std::cout << "Write error on '" << m_name << "': Only wrote " << written << " of " << size << " bytes" << std::endl;
		}
		return Restart();
	}
	return false;
}

bool CUnixPacket::Restart()
{
	if (! m_host->IsRunning())
		return true;
	std::cout << "Restarting '" << m_name << "'... " << std::endl;
	Close();
	std::string name(m_name);
	return Open(name.c_str(), m_host);
}

int CUnixPacket::GetFD()
{
	return m_fd;
}

CUnixPacketServer::CUnixPacketServer() : m_server(-1) {}

CUnixPacketServer::~CUnixPacketServer()
{
	Close();
}

bool CUnixPacketServer::Open(const char *name, CKRBase *host)
{
	m_server = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	m_host = host;
	if (m_server < 0)
	{
		std::cerr << "Cannot open '" << name << "' socket: " << strerror(errno) << std::endl;
		return true;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path+1, name, strlen(name));
	if (-1 == bind(m_server, (struct sockaddr *)&addr, sizeof(addr)))
	{
		std::cerr << "Cannot bind '" << name << "' socket: " << strerror(errno) << std::endl;
		Close();
		return true;
	}

	if (-1 == listen(m_server, 1))
	{
		std::cerr << "Cannot listen on '" << name << "' socket: " << strerror(errno) << std::endl;
		Close();
		return true;
	}

	m_fd = accept(m_server, nullptr, 0);
	if (m_fd < 0)
	{
		std::cerr << "Cannot accept on '" << name << "' socket: " << strerror(errno) << std::endl;
		Close();
		return true;
	}

	strncpy(m_name, name, 108);
	return false;
}

void CUnixPacketServer::Close()
{
	if (m_server >= 0)
	{
		close(m_server);
		m_server = -1;
	}
	if (m_fd >= 0)
	{
		close(m_fd);
		m_fd = -1;
	}
}

CUnixPacketClient::~CUnixPacketClient()
{
	Close();
}

bool CUnixPacketClient::Open(const char *name, CKRBase *host)
{
	m_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (m_fd < 0)
	{
		std::cerr << "Cannot open unix client socket " << name << std::endl;
		return true;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path+1, name, strlen(name));
	int rval = -1;
	int tries = 0;
	while (rval < 0)
	{
		rval = connect(m_fd, (struct sockaddr *)&addr, sizeof(addr));
		if (rval < 0)
		{
			if (ECONNREFUSED == errno)
			{
				if (0 == tries++ % 20)
					std::cout << "Waiting for " << name << " server to start..." << std::endl;
				std::this_thread::sleep_for(std::chrono::milliseconds(250));
			}
			else
			{
				std::cerr << "Cannot connect '" << name << "' socket: " << strerror(errno) << std::endl;
				Close();
				return true;
			}
		}
		if (! m_host->IsRunning())
		{
			Close();
			return true;
		}
	}

	m_host = host;
	strncpy(m_name, name, 108);
	return false;
}

void CUnixPacketClient::Close()
{
	if (m_fd >= 0)
	{
		close(m_fd);
		m_fd = -1;
	}
}
