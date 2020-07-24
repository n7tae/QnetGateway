/*
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

#pragma once

#include <string>
#include <map>

class CQnetConfigure
{
public:
	CQnetConfigure();
	virtual ~CQnetConfigure();
	bool Initialize(const char *configfile);
	bool GetValue(const std::string &path, const std::string &mod, bool        &value);
	bool GetValue(const std::string &path, const std::string &mod, double      &value, const double min, const double max);
	bool GetValue(const std::string &path, const std::string &mod, int         &value, const int    min, const int    max);
	bool GetValue(const std::string &path, const std::string &mod, std::string &value, const int    min, const int    max);
	bool KeyExists(const std::string &key);

private:
	std::map<std::string, std::string> defaults;
	std::map<std::string, std::string> cfg;

	char *Trim(char *s);
	bool ReadConfigFile(const char *file, std::map<std::string, std::string> &amap);
	bool GetDefaultBool  (const std::string &key, const std::string &mod, bool        &dval);
	bool GetDefaultDouble(const std::string &key, const std::string &mod, double      &dval);
	bool GetDefaultInt   (const std::string &key, const std::string &mod, int         &dval);
	bool GetDefaultString(const std::string &key, const std::string &mod, std::string &dval);
};
