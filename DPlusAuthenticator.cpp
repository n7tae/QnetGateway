/*
 *   Copyright (C) 2010-2015 by Jonathan Naylor G4KLX
 *   Copyright (C) 2018 by Thomas A. Early N7TAE
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

#include <string>
#include <cassert>
#include <cstdio>
#include <cctype>
#include <cstring>
#include <thread>
#include <chrono>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "DPlusAuthenticator.h"
//#include "DStarDefines.h"
//#include "Utils.h"
//#include "Defs.h"

CDPlusAuthenticator::CDPlusAuthenticator(const std::string &loginCallsign, const std::string &address) :
m_loginCallsign(loginCallsign),
m_address(address)
{
	assert(loginCallsign.size());

	Trim(m_loginCallsign);
}

CDPlusAuthenticator::~CDPlusAuthenticator()
{
}

bool CDPlusAuthenticator::Process(std::map<std::string, std::string> &gwy_map, const bool reflectors, const bool repeaters)
// return true if everything went okay
{
	struct addrinfo hints, *infoptr;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET; // AF_INET means IPv4 only addresses
    hints.ai_socktype = SOCK_STREAM;

    int result = EAI_AGAIN;
	int count = 0;
    while (EAI_AGAIN==result && 20>count++) {	// we'll wait up to 60 seconds for this to work
        result = getaddrinfo(m_address.c_str(), NULL, &hints, &infoptr);
		if (EAI_AGAIN == result) {
			fprintf(stdout, "getaddrinfo not ready: please wait...\n");
			std::this_thread::sleep_for(std::chrono::seconds(3));
		}
    }
	if (result) {
		fprintf(stderr, "DPlus Authroization failed: %s\n", gai_strerror(result));
		return false;
	}

    struct addrinfo *p;
    char host[256];

	bool success = false;

    for (p = infoptr; p != NULL && !success; p = p->ai_next) {
        getnameinfo(p->ai_addr, p->ai_addrlen, host, sizeof(host), NULL, 0, NI_NUMERICHOST);
        printf("Trying %s from %s\n", host, m_address.c_str());
		success = authenticate(m_loginCallsign, std::string(host), gwy_map, reflectors, repeaters);
    }

    freeaddrinfo(infoptr);
    return success;
}

bool CDPlusAuthenticator::authenticate(const std::string &callsign, const std::string &hostname, std::map<std::string, std::string> &gwy_map, const bool reflectors, const bool repeaters)
{
	CTCPReaderWriterClient socket(hostname, 20001U);

	bool ret = socket.open();
	if (!ret)
		return false;

	unsigned char* buffer = new unsigned char[4096U];
	::memset(buffer, ' ', 56U);

	buffer[0U] = 0x38U;
	buffer[1U] = 0xC0U;
	buffer[2U] = 0x01U;
	buffer[3U] = 0x00U;

	::memcpy(buffer+4, callsign.c_str(), callsign.size());
	::memcpy(buffer+12, "DV019999", 8);
	::memcpy(buffer+28, "W7IB2", 5);
	::memcpy(buffer+40, "DHS0257", 7);

	ret = socket.write(buffer, 56U);
	if (!ret) {
		socket.close();
		delete[] buffer;
		return false;
	}

	ret = read(socket, buffer, 2U);

	while (ret) {
		unsigned int len = (buffer[1U] & 0x0FU) * 256U + buffer[0U];

		// Ensure that we get exactly len - 2U bytes from the TCP stream
		ret = read(socket, buffer + 2U, len - 2U);
		if (!ret) {
			fprintf(stderr, "Short read from %s:20001", hostname.c_str());
			return false;
		}

		if ((buffer[1U] & 0xC0U) != 0xC0U || buffer[2U] != 0x01U) {
			fprintf(stderr, "Invalid packet received from %s:20001", hostname.c_str());
			return false;
		}

		for (unsigned int i = 8U; (i + 25U) < len; i += 26U) {
			std::string address((char *)(buffer + i));
			std::string name((char *)(buffer + i + 16U));

			Trim(address);
			Trim(name);
			name.resize(8, ' ');

			// Get the active flag
			bool active = (buffer[i + 25U] & 0x80U) == 0x80U;

			// An empty name or IP address or an inactive gateway/reflector is not added
			if (address.size()>0U && name.size()>0U && active) {
				if (reflectors && 0==name.compare(0, 3, "REF"))
					gwy_map[name] = address.append(" 20001");
				else if (repeaters && name.compare(0, 3, "REF"))
					gwy_map[name] = address.append(" 20001");
			}
		}

		ret = read(socket, buffer, 2U);
	}

	printf("Authorized DPlus with %s using callsign %s\n", hostname.c_str(), callsign.c_str());
	printf("Added %d DPlus gateways\n", (int)gwy_map.size());
	socket.close();

	delete[] buffer;

	return true;
}

void CDPlusAuthenticator::Trim(std::string &s)
{
	auto it = s.begin();
	while (it!=s.end() && isspace(*it))
		s.erase(it);
	auto rit = s.rbegin();
	while (rit!=s.rend() && isspace(*rit)) {
		s.resize(s.size() - 1);
        rit = s.rbegin();
    }
}

bool CDPlusAuthenticator::read(CTCPReaderWriterClient &socket, unsigned char *buffer, unsigned int len) const
{
	unsigned int offset = 0U;

	do {
		int n = socket.read(buffer + offset, len - offset, 10U);
		if (n < 0)
			return false;

		offset += n;
	} while ((len - offset) > 0U);

	return true;
}
