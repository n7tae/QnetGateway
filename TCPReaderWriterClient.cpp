/*
 *   Copyright (C) 2010-2013 by Jonathan Naylor G4KLX
 *   Copyright (C) 2019 by Thomas A. Early N7TAE
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


CTCPReaderWriterClient::CTCPReaderWriterClient(const std::string &address, int family, const std::string &port) :
m_address(address),
m_family(family),
m_port(port),
m_fd(-1)
{
}

CTCPReaderWriterClient::CTCPReaderWriterClient() : m_fd(-1)
{
}

CTCPReaderWriterClient::~CTCPReaderWriterClient()
{
}

bool CTCPReaderWriterClient::open(const std::string &address, int family, const std::string &port)
{
	m_address	= address;
	m_family	= family;
	m_port		= port;

	return open();
}

bool CTCPReaderWriterClient::open()
{
	if (m_fd != -1) {
		fprintf(stderr, "ERROR: port for '%s' is already open!\n", m_address.c_str());
		return true;
	}

	if (0 == m_address.size() || 0 == m_port.size() || 0 == std::stoul(m_port)) {
		fprintf(stderr, "ERROR: '%s:%s' is malformed!\n", m_address.c_str(), m_port.c_str());
		return true;
	}

	if (AF_INET!=m_family && AF_INET6!=m_family &&_UNSPEC!=m_family) {
		fprintf(stderr, "ERROR: family must be AF_INET, AF_INET6 or AF_UNSPEC\n");
		return true;
	}

	struct addrinfo hints;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	//hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = IPPROTO_TCP;

	struct addrinfo *res;
	int s = EAI_AGAIN;
	int count = 0;
	while (EAI_AGAIN==s and count++<20) {
		// connecting to a server, so we can wait until it's ready
		s = getaddrinfo(m_address.c_str(), m_port.c_str(), &hints, &res);
		std::this_thread::sleep_for(std::chrono::seconds(3));
	}
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		return true;
	}

	struct addrinfo *rp;
	for (rp = res; rp != NULL; rp = rp->ai_next) {
		m_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (m_fd == -1)
			continue;

		if (connect(m_fd, rp->ai_addr, rp->ai_addrlen)) {
			close();
			continue;
		} else {
			char buf[INET6_ADDRSTRLEN];
			if (inet_ntop(rp->ai_family, rp->ai_addr, buf, INET6_ADDRSTRLEN))
				fprintf(stderr, "Successfully connected %s to %s:%s\n", m_address.c_str(), buf, m_port.c_str());
			break;
		}
	}
	freeaddrinfo(res);

	if (rp == NULL) {
		fprintf(stderr, "Could not connect to any system returned by %s\n", m_address.c_str());
		m_fd = -1;
		return true;
	}

	return false;
}

int CTCPReaderWriterClient::read(unsigned char* buffer, unsigned int length)
{
	assert(buffer != NULL);
	assert(length > 0U);
	assert(m_fd != -1);

	ssize_t len = recv(m_fd, buffer, length, 0);
	if (len < 0) {
		fprintf(stderr, "Error returned from recv, err=%d\n", errno);
		return -1;
	}

	return len;
}

int CTCPReaderWriterClient::readLine(std::string& line)
{
	//maybe there is a better way to do this like reading blocks, pushing them for later calls
	//Nevermind, we'll read one char at a time for the time being.
	unsigned char c;
	int resultCode;
	int len = 0;
	line = "";

	do
	{
		resultCode = read(&c, 1);
		if(resultCode == 1){
			line += c;
			len++;
		}
	}while(c != '\n' && resultCode == 1);

	return resultCode <= 0 ? resultCode : len;
}

bool CTCPReaderWriterClient::write(const unsigned char* buffer, unsigned int length)
{
	assert(buffer != NULL);
	assert(length > 0U);
	assert(m_fd != -1);

	ssize_t ret = ::send(m_fd, (char *)buffer, length, 0);
	if (ret != ssize_t(length)) {
		fprintf(stderr, "Error returned from send, err=%d\n", errno);
		return false;
	}

	return true;
}

bool CTCPReaderWriterClient::writeLine(const std::string& line)
{
	std::string lineCopy(line);
	if(lineCopy.size() > 0 && lineCopy.at(lineCopy.size() - 1) != '\n')
		lineCopy.append("\n");

	size_t len = lineCopy.size();
	bool result = true;
	for(size_t i = 0; i < len && result; i++){
		unsigned char c = lineCopy.at(i);
		result = write(&c , 1);
	}

	return result;
}

void CTCPReaderWriterClient::close()
{
	if (m_fd != -1) {
		::close(m_fd);
		m_fd = -1;
	}
}
