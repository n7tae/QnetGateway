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

#include <string>
#include <regex>
#include <cmath>
#include <iostream>

#include "Utilities.h"
#include "Location.h"

CLocation::CLocation()
{
	gps = std::regex("[^0-9]([0-9]{1,2})([0-9]{2}\\.[0-9]{1,}),?([NS])[/,]([0-9]{1,3})([0-9]{2}\\.[0-9]{1,}),?([WE])", std::regex::extended);
}

// returns true on success
bool CLocation::Parse(const char *instr)
{
	std::string s(instr);
	std::cmatch cm;
	trim(s);
	if (s.size() < 20)
		return false;

	if (! std::regex_search(s.c_str(), cm, gps, std::regex_constants::match_default))
	{
		//std::cerr << "Unsuccessful gps parse of '" << s << "'" << std::endl;
		return false;
	}

	auto size = cm.size();
	if (size != 7)
	{
		std::cerr << "Bad CRC Match for " << s << ":";
		for (unsigned i=0; i<size; i++)
			std::cerr << " [" << cm[i] << "]";
		std::cerr << std::endl;
		return false;
	}

	double deg = stod(cm[1]);
	if (90.0 < deg)
	{
		std::cout << "Latitude degree " << deg << " is out of range" << std::endl;
		return false;
	}

	double min = stod(cm[2]);
	if (60.0 < min)
	{
		std::cout << "Latitude minutes " << min << " is out of range" << std::endl;
		return false;
	}

	latitude = deg + min / 60.0;
	if ('S' == cm[3])
		latitude = 0.0 - latitude;

	deg = stod(cm[4]);
	if (180.0 < deg)
	{
		std::cout << "Longitude degree " << deg << " is out of range" << std::endl;
		return false;
	}

	min = stod(cm[5]);
	if (60.0 < min)
	{
		std::cout << "Longitude minutes " << min << " is out of range" << std::endl;
		return false;
	}

	longitude = deg + min / 60.0;
	if ('W' == cm[6])
		longitude = 0.0 - longitude;

	double lat = latitude + 90.0;
	double lon = longitude + 180.0;
	maidenhead[0] = 'A' +  (int(lon) / 20);
	maidenhead[1] = 'A' +  (int(lat) / 10);
	maidenhead[2] = '0' + ((int(lon) % 20) / 2);
	maidenhead[3] = '0' +  (int(lat) % 10);
	maidenhead[4] = 'a' +  (int(lon * 12.0) % 24);
	maidenhead[5] = 'a' +  (int(lat * 24.0) % 24);
	maidenhead[6] = '\0';

	return true;
}

const char *CLocation::APRS(std::string &call, const char *station)
{
	char last;
	call.resize(8, ' ');
	last = call.at(7);
	auto pos = call.find(' ');
	if (call.npos != pos)
	{
		call.resize(pos+1);
	}
	double latmin, lonmin;
	double lat = modf(fabs(latitude), &latmin);
	latmin *= 60.0;
	double lon = modf(fabs(longitude), &lonmin);
	lonmin *= 60.0;
	if (last == ' ')
		snprintf(aprs, 128, "%s>APDPRS,DSTAR*,qAR,%s:!%02d%04.2f%c/%03d%04.2f%c/A\r\n", call.c_str(), station, int(lat), latmin, (latitude>=0) ? 'N' : 'S', int(lon), lonmin, (longitude>=0) ? 'E' : 'W');
	else
		snprintf(aprs, 128, "%s-%c>APDPRS,DSTAR*,qAR,%s:!%02d%04.2f%c/%03d%04.2f%c/A\r\n", call.c_str(), last, station, int(lat), latmin, (latitude>=0) ? 'N' : 'S', int(lon), lonmin, (longitude>=0) ? 'E' : 'W');

	return aprs;
}

double CLocation::Latitude() const
{
	return latitude;
}

double CLocation::Longitude() const
{
	return longitude;
}

const char* CLocation::MaidenHead() const
{
	return maidenhead;
}
