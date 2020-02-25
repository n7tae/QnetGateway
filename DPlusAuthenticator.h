#pragma once
/*
 *   Copyright (C) 2010-2013 by Jonathan Naylor G4KLX
 *   Copyright (C) 2018-2019 by Thomas A. Early N7TAE
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
**/

#include <netinet/in.h>
#include <map>
#include <string>
#include "TCPReaderWriterClient.h"

class CDPlusAuthenticator {
public:
	CDPlusAuthenticator(const std::string &loginCallsign, const std::string &address);
	~CDPlusAuthenticator();

	bool Process(std::map<std::string, std::string> &gwy_map, const bool reflectors, const bool repeaters);

private:
	std::string m_loginCallsign;
	std::string m_address;
	CTCPReaderWriterClient client;

	void Trim(std::string &s);
	bool authenticate(std::map<std::string, std::string> &gwy_map, const bool reflectors, const bool repeaters);
};
