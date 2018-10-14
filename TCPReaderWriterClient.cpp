/*
 *   Copyright (C) 2010-2013 by Jonathan Naylor G4KLX
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
//#include "UDPReaderWriter.h"
#include <cstdio>
#include <cerrno>
#include <cassert>
#include <cstring>


CTCPReaderWriterClient::CTCPReaderWriterClient(const std::string &address, unsigned int port, const std::string &localAddress) :
m_address(address),
m_port(port),
m_localAddress(localAddress),
m_fd(-1)
{
	assert(address.size());
	assert(port > 0U);
}

CTCPReaderWriterClient::CTCPReaderWriterClient(int fd) :
m_address(),
m_port(0U),
m_localAddress(),
m_fd(fd)
{
	assert(fd >= 0);
}

CTCPReaderWriterClient::CTCPReaderWriterClient() :
m_address(),
m_port(0U),
m_localAddress(),
m_fd(-1)
{
}

CTCPReaderWriterClient::~CTCPReaderWriterClient()
{
}

bool CTCPReaderWriterClient::open(const std::string& address, unsigned int port, const std::string& localAddress)
{
	m_address      = address;
	m_port         = port;
	m_localAddress = localAddress;

	return open();
}

bool CTCPReaderWriterClient::open()
{
	if (m_fd != -1)
		return true;

	if (0 == m_address.size() || m_port == 0U)
		return false;

	m_fd = ::socket(PF_INET, SOCK_STREAM, 0);
	if (m_fd < 0) {
		fprintf(stderr, "Cannot create the TCP client socket, err=%d\n", errno);
		return false;
	}

	if (m_localAddress.size()) {
		sockaddr_in addr;
		::memset(&addr, 0x00, sizeof(struct sockaddr_in));
		addr.sin_family = AF_INET;
		addr.sin_port   = 0U;
		addr.sin_addr.s_addr = ::inet_addr(m_localAddress.c_str());
		if (addr.sin_addr.s_addr == INADDR_NONE) {
			fprintf(stderr, "The address is invalid - %s\n", m_localAddress.c_str());
			close();
			return false;
		}

		if (::bind(m_fd, (sockaddr*)&addr, sizeof(sockaddr_in)) == -1) {
			fprintf(stderr, "Cannot bind the TCP client address, err=%d\n", errno);
			close();
			return false;
		}
	}

	struct sockaddr_in addr;
	::memset(&addr, 0x00, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port   = htons(m_port);
	addr.sin_addr   = lookup(m_address);

	if (addr.sin_addr.s_addr == INADDR_NONE) {
		close();
		return false;
	}

	if (::connect(m_fd, (sockaddr*)&addr, sizeof(struct sockaddr_in)) == -1) {
		fprintf(stderr, "Cannot connect the TCP client socket, err=%d\n", errno);
		close();
		return false;
	}

	int noDelay = 1;
	if (::setsockopt(m_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&noDelay, sizeof(noDelay)) == -1) {
		fprintf(stderr, "Cannot set the TCP client socket option, err=%d\n", errno);
		close();
		return false;
	}

	return true;
}

int CTCPReaderWriterClient::read(unsigned char* buffer, unsigned int length, unsigned int secs, unsigned int msecs)
{
	assert(buffer != NULL);
	assert(length > 0U);
	assert(m_fd != -1);

	// Check that the recv() won't block
	fd_set readFds;
	FD_ZERO(&readFds);
	FD_SET(m_fd, &readFds);

	// Return after timeout
	timeval tv;
	tv.tv_sec  = secs;
	tv.tv_usec = msecs * 1000;

	int ret = ::select(m_fd + 1, &readFds, NULL, NULL, &tv);
	if (ret < 0) {
		fprintf(stderr, "Error returned from TCP client select, err=%d\n", errno);
		return -1;
	}

	if (!FD_ISSET(m_fd, &readFds))
		return 0;

	ssize_t len = ::recv(m_fd, (char*)buffer, length, 0);
	if (len == 0) {
		return -2;
	} else if (len < 0) {
		fprintf(stderr, "Error returned from recv, err=%d\n", errno);
		return -1;
	}

	return len;
}

int CTCPReaderWriterClient::readLine(std::string& line, unsigned int secs)
{
	//maybe there is a better way to do this like reading blocks, pushing them for later calls
	//Nevermind, we'll read one char at a time for the time being.
	unsigned char c;
	int resultCode;
	int len = 0;
	line = "";

	do
	{
		resultCode = read(&c, 1, secs);
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

	//stupidly write one char after the other
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

in_addr CTCPReaderWriterClient::lookup(const std::string &hostname)
{
	in_addr addr;
	in_addr_t address = ::inet_addr(hostname.c_str());
	if (address != in_addr_t(-1)) {
		addr.s_addr = address;
		return addr;
	}

	struct hostent* hp = ::gethostbyname(hostname.c_str());
	if (hp != NULL) {
		::memcpy(&addr, hp->h_addr_list[0], sizeof(struct in_addr));
		return addr;
	}

	fprintf(stderr, "Cannot find address for host %s", hostname.c_str());

	addr.s_addr = INADDR_NONE;
	return addr;
}
