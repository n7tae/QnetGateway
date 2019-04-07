#pragma once

/*
 *   Copyright (C) 2019 by Thomas Early N7TAE
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

#include <string.h>
#include <netinet/in.h>
#include <string>

class CSockAddress
{
public:
	CSockAddress()
	{
		Clear();
	}

	CSockAddress(const struct sockaddr_storage &from)
	{
		Clear();
		if (AF_INET == from.ss_family)
			memcpy(&addr, &from, sizeof(struct sockaddr_in));
		else
			memcpy(&addr, &from, sizeof(struct sockaddr_in6));
	}

	CSockAddress(const int family, const unsigned short port, const char *address)
	{
		Clear();
		if (AF_INET==family && address) {
			addr4->sin_family = AF_INET;
			addr4->sin_port = port;
			if (*address=='l' || *address =='L')
				inet_pton(AF_INET, "127.0.0.1", &(addr4->sin_addr));
			else if (*address=='a' || *address=='A')
				inet_pton(AF_INET, "0.0.0.0", &(addr4->sin_addr));
			else
				inet_pton(AF_INET, address, &(addr4->sin_addr));
		} else if (AF_INET6==family && address) {
			addr6->sin6_family = AF_INET6;
			addr6->sin6_port = port;
			if (*address=='l' || *address =='L')
				inet_pton(AF_INET6, "::1", &(addr6->sin6_addr));
			else if (*address=='a' || *address=='A')
				inet_pton(AF_INET6, "::", &(addr6->sin6_addr));
			else
				inet_pton(AF_INET6, address, &(addr6->sin6_addr));
		}
	}

	~CSockAddress() {}

	void Initialize(int family, uint16_t port = 0U, const char *address = NULL)
	{
		Clear();
		addr.ss_family = (sa_family_t)family;
		if (AF_INET == family) {
			addr4->sin_port = port;
			if (address) {
				if (*address=='l' || *address=='L')
					inet_pton(AF_INET, "127.0.0.1", &(addr4->sin_addr));
				else if (*address=='a' || *address=='A')
					inet_pton(AF_INET, "0.0.0.0", &(addr4->sin_addr));
				else
					inet_pton(AF_INET, address, &(addr4->sin_addr));
			}
		} else {
			addr6->sin6_port = port;
			if (address) {
				if (*address=='l' || *address=='L')
					inet_pton(AF_INET6, "::1", &(addr6->sin6_addr));
				else if (*address=='a' || *address=='A')
					inet_pton(AF_INET6, "::", &(addr6->sin6_addr));
				else
					inet_pton(AF_INET, address, &(addr6->sin6_addr));
			}
		}
	}

	CSockAddress &operator=(CSockAddress &from)
	{
		Clear();
		if (AF_INET == from.addr.ss_family)
			memcpy(&addr, &from, sizeof(struct sockaddr_in));
		else
			memcpy(&addr, &from, sizeof(struct sockaddr_in6));
		return *this;
	}

	bool operator==(CSockAddress &from)
	{
		if (addr.ss_family == from.addr.ss_family) {
			if (AF_INET == addr.ss_family)
				return (0==memcmp(addr4, &from, sizeof(struct sockaddr_in)));
			else
				return (0==memcmp(addr6, &from, sizeof(struct sockaddr_in6)));
		} else
			return false;
	}

	bool AddressIsZero()
	{
		if (AF_INET == addr.ss_family) {
			return (addr4->sin_addr.s_addr == 0U);
		} else {
			for (unsigned int i=0; i<16; i++) {
				if (addr6->sin6_addr.s6_addr[i])
					return false;
			}
			return true;
		}
	}

	void ClearAddress()
	{
		if (AF_INET == addr.ss_family) {
			addr4->sin_addr.s_addr = 0U;
		} else {
			memset(&(addr6->sin6_addr.s6_addr), 0, 16);
		}
	}

	const char *GetAddress()
	{
		if (AF_INET == addr.ss_family) {
			if (NULL == inet_ntop(AF_INET, &(addr4->sin_addr), straddr, INET6_ADDRSTRLEN))
				return "ERROR";
		} else {
			if (NULL == inet_ntop(AF_INET6, &(addr6->sin6_addr), straddr, INET6_ADDRSTRLEN))
				return "ERROR";
		}

		return straddr;
	}

	unsigned short GetPort()
	{
		if (AF_INET == addr.ss_family)
			return addr4->sin_port;
		else
			return addr6->sin6_port;
	}

	struct sockaddr *GetPointer()
	{
		return (struct sockaddr *)&addr;
	}

	size_t GetSize()
	{
		if (AF_INET == addr.ss_family)
			return sizeof(struct sockaddr_in);
		else
			return sizeof(struct sockaddr_in6);
	}

	void Clear()
	{
		memset(&addr, 0, sizeof(struct sockaddr_storage));
	}

private:
	struct sockaddr_storage addr;
	struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;
	char straddr[INET6_ADDRSTRLEN];
};
