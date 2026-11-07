/*
 *   Copyright (C) 2010-2013 by Jonathan Naylor G4KLX
 *   Copyright (C) 2019,2026 by Thomas A. Early N7TAE
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

#include "TCPReaderWriterClient.h"
#include <cstdio>
#include <cerrno>
#include <cassert>
#include <cstring>

CTCPReaderWriterClient::CTCPReaderWriterClient() : m_fd(-1)
{
}

bool CTCPReaderWriterClient::Open(const std::string &address, int family, const std::string &port, const bool debug)
{
	const char *where { "TCP Open ERROR:" };
	m_address	= address;
	m_port		= port;
	if (m_fd != -1)
	{
		fprintf(stderr, "%s port for '%s' is already open!\n", where, m_address.c_str());
		return true;
	}

	if (0 == m_address.size() || 0 == m_port.size() || 0 == std::stoul(m_port))
	{
		fprintf(stderr, "%s '[%s]:%s' is malformed!\n", where, m_address.c_str(), m_port.c_str());
		return true;
	}

	if (AF_INET!=family and AF_INET6!=family and AF_UNSPEC!=family)
	{
		fprintf(stderr, "%s family must be AF_INET, AF_INET6 or AF_UNSPEC\n", where);
		return true;
	}

	struct addrinfo hints;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	struct addrinfo *res;
	int s = EAI_AGAIN;
	int count = 0;
	while (s and count++<20)
	{
		// connecting to a server, so we can wait until it's ready
		s = getaddrinfo(m_address.c_str(), m_port.c_str(), &hints, &res);
		if (s && s != EAI_AGAIN)
		{
			fprintf(stderr, "%s getaddrinfo of %s: %s\n", where, m_address.c_str(), gai_strerror(s));
			return true;
		}
		std::this_thread::sleep_for(std::chrono::seconds(3));
	}

	if (EAI_AGAIN == s)
	{
		fprintf(stderr, "%s getaddrinfo of %s failed 20 times\n", where, m_address.c_str());
		return true;
	}

	struct addrinfo *rp;
	for (rp = res; rp != NULL; rp = rp->ai_next)
	{
		m_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (m_fd == -1)
		{
			if (debug) fprintf(stderr, "%s socket() error - %s\n", where, strerror(errno));
			continue;
		}

		int flag = 1;
		if (setsockopt(m_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)))
		{
			if (debug) fprintf(stderr, "%s setsockopt(TCP_NODELAY) - %s\n", where, strerror(errno));
			Close();
			continue;
		}
		if (connect(m_fd, rp->ai_addr, rp->ai_addrlen))
		{
			if (debug) fprintf(stderr, "%s connect() - %s\n", where, strerror(errno));
			Close();
			continue;
		}
		else
		{
			char buf[INET6_ADDRSTRLEN];
			void *addr;
			if (AF_INET == rp->ai_family)
			{
				struct sockaddr_in *addr4 = (struct sockaddr_in *)rp->ai_addr;
				addr = &(addr4->sin_addr);
			}
			else
			{
				struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)rp->ai_addr;
				addr = &(addr6->sin6_addr);
			}
			if (inet_ntop(rp->ai_family, addr, buf, INET6_ADDRSTRLEN))
				printf("Successfully connected to %s at [%s]:%s\n", m_address.c_str(), buf, m_port.c_str());
			break;
		}
	}
	freeaddrinfo(res);

	if (rp == NULL)
	{
		fprintf(stderr, "%s Could not connect to %s\n", where, m_address.c_str());
		m_fd = -1;
		return true;
	}

	return false;
}

int CTCPReaderWriterClient::ReadExact(uint8_t *buf, const unsigned int length)
{
	unsigned int read = 0U;

	do {
		int n = Read(buf + read, length - read);
		if (n < 1)
			return n;

		read += n;
	} while ((length - read) > 0U);

	return length;
}

int CTCPReaderWriterClient::Read(uint8_t* buffer, const unsigned int length)
{
	assert(buffer != NULL);
	assert(length > 0U);
	assert(m_fd != -1);

	ssize_t len = recv(m_fd, buffer, length, 0);
	if (len <= 0)
	{
		if (len < 0)
			fprintf(stderr, "TCP Read() ERROR: %s\n", strerror(errno));
		else
			fprintf(stderr, "TCP Read() ERROR: Port closed by server\n");
		return -1;
	}

	return len;
}

bool CTCPReaderWriterClient::ReadLine(std::string& line)
{
	uint8_t c;
	int rtv;

	do {
		rtv = Read(&c, 1);
		if (('\r' != c) and ('\n' != c) and (rtv == 1))
			line += c;
	} while(c != '\n' and rtv == 1);

	return (rtv <= 0) ? true : false;
}

bool CTCPReaderWriterClient::Write(const void *pvoid, const unsigned int length)
{
	assert(pvoid != NULL);
	assert(length > 0U);
	assert(m_fd != -1);
	unsigned int wrote = 0;
	uint8_t *buffer = (uint8_t *)pvoid;

	while (wrote < length) {
		ssize_t ret = send(m_fd, buffer+wrote, length-wrote, 0);
		if (ret <= 0)
		{
			if (ret < 0)
				fprintf(stderr, "ERROR - TCP Write send(): %s\n", strerror(errno));
			else
				fprintf(stderr, "ERROR - TCP Write: port closed by server\n");
			return true;
		}
		wrote += ret;
	}

	return false;
}

bool CTCPReaderWriterClient::WriteLine(std::string& line)
{
	line.append("\r\n");
	return Write(line.c_str(), line.size());
}

void CTCPReaderWriterClient::Close()
{
	if (m_fd != -1)
	{
		close(m_fd);
		m_fd = -1;
	}
}
