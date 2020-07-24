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

#include <cstdio>
#include <cstring>
#include "QnetConfigure.h"

CQnetConfigure::CQnetConfigure()
{
}

CQnetConfigure::~CQnetConfigure()
{
	defaults.empty();
	cfg.empty();
}

char *CQnetConfigure::Trim(char *s)
{
	size_t len = strlen(s);
	while (len && isspace(s[len-1]))
		s[--len] = '\0';
	while (*s && len && isspace(*s))
		len = strlen(++s);
	return s;
}

bool CQnetConfigure::ReadConfigFile(const char *configfile, std::map<std::string, std::string> &amap)
{
	FILE *fp = fopen(configfile, "r");
	if (fp)
	{
		char line[2048];
		while (fgets(line, 2048, fp))
		{
			char *key = strtok(line, "=");
			key = Trim(key);
			if (strlen(key) && '#' != *key)
			{
				char *val = strtok(NULL, "\r\n");
				char *val2 = Trim(val);
				if ('\'' ==  val2[0])
				{
					if ('\'' == val2[1])
						val[0] = '\0';
					else
						val = strtok(val2, "'");
				}
				else
					val = strtok(val2, "# \t");
				amap[key] = val;
			}
		}
		fclose(fp);
		return false;
	}
	fprintf(stderr, "could not open file %s\n", configfile);
	return true;
}

#ifndef CFG_DIR
#define CFG_DIR "/usr/local/etc"
#endif

bool CQnetConfigure::Initialize(const char *file)
{
	std::string filename(CFG_DIR);
	filename.append("/defaults");
	if (ReadConfigFile(filename.c_str(), defaults))
		return true;
	return ReadConfigFile(file, cfg);
}

bool CQnetConfigure::KeyExists(const std::string &key)
{
	return (cfg.end() != cfg.find(key));
}

bool CQnetConfigure::GetDefaultBool(const std::string &path, const std::string &mod, bool &dvalue)
{
	std::string value;
	if (GetDefaultString(path, mod, value))
		return true;	// No default value defined!
	if ('0'==value.at(0) || 'f'==value.at(0) || 'F'==value.at(0))
		dvalue = false;
	else if ('1'==value.at(0) || 't'==value.at(0) || 'T'==value.at(0))
		dvalue = true;
	else
	{
		fprintf(stderr, "%s=%s doesn't seem to be a boolean!\n", path.c_str(), value.c_str());
		return true;
	}
	return false;
}

bool CQnetConfigure::GetDefaultDouble(const std::string &path, const std::string &mod, double &dvalue)
{
	std::string value;
	if (GetDefaultString(path, mod, value))
		return true;	// No default value defined!
	dvalue = std::stod(value);
	return false;
}

bool CQnetConfigure::GetDefaultInt(const std::string &path, const std::string &mod, int &dvalue)
{
	std::string value;
	if (GetDefaultString(path, mod, value))
		return true;	// No default value defined!
	dvalue = std::stoi(value);
	return false;
}

bool CQnetConfigure::GetDefaultString(const std::string &path, const std::string &mod, std::string &dvalue)
{
	std::string search, search_again;
	if (mod.empty())
	{
		search = path + "_d";	// there is no mod, so this is a simple search
	}
	else
	{
		search_again = mod;		// we're looking from a module value. We may have to look for non-generic module parameters
		if (0==path.compare(0, 7, "module_") && ('a'==path.at(7) || 'b'==path.at(7) || 'c'==path.at(7)) && '_'==path.at(8))
		{
			// path begins with module_{a|b|c}_
			if (0==mod.compare("dvrptr") || 0==mod.compare("dvap") || 0==mod.compare("mmdvmhost") || 0==mod.compare("mmdvmmodem") || 0==mod.compare("itap") || 0==mod.compare("thumbdv"))
			{
				// and the module is recognized
				search = path;
				search.replace(7, 1, 1, 'x');
				search_again += path.substr(8);	// now the search_again path might look like dvap_frequency, for example.
			}
			else
			{
				fprintf(stderr, "Unrecognized module type = '%s'\n", mod.c_str());
				return true;
			}
		}
		else
		{
			fprintf(stderr, "%s looks like an ilformed request from module '%s'\n", path.c_str(), mod.c_str());
			return true;
		}
	}
	auto it = defaults.find(search);
	if (defaults.end() == it)
	{
		it = defaults.find(search_again);
		if (defaults.end() == it)
			return true;
	}
	dvalue = it->second;
	return false;
}

bool CQnetConfigure::GetValue(const std::string &path, const std::string &mod, bool &value)
{
	auto it = cfg.find(path);
	if (cfg.end() == it)
	{
		bool dvalue;
		if (GetDefaultBool(path, mod, dvalue))
		{
			fprintf(stderr, "%s not found in either the cfg file or the defaults file!\n", path.c_str());
			return true;
		}
		value = dvalue;	// found a value in the defaults
	}
	else  	// found a value in the cfg file
	{
		char c = it->second.at(0);
		if ('0'==c || 'f'==c || 'F'==c)
			value = false;
		else if ('1'==c || 't'==c || 'T'==c)
			value = true;
		else
		{
			fprintf(stderr, "%s=%s doesn't seem to define a boolean\n", path.c_str(), it->second.c_str());
			return true;
		}
	}
	printf("%s = %s\n", path.c_str(), value ? "true" : "false");
	return false;
}

bool CQnetConfigure::GetValue(const std::string &path, const std::string &mod, double &value, const double min, const double max)
{
	auto it = cfg.find(path);
	if (cfg.end() == it)
	{
		double dvalue;
		if (GetDefaultDouble(path, mod, dvalue))
		{
			fprintf(stderr, "%s not found in either the cfg file or the defaults file!\n", path.c_str());
			return true;
		}
		if (dvalue < min || dvalue > max)
		{
			fprintf(stderr, "Default value %s=%g is out of acceptable range\n", path.c_str(), value);
			return true;
		}
		value = dvalue;
	}
	else
	{
		value = std::stod(it->second);
		if (value < min || value > max)
		{
			fprintf(stderr, "%s=%g is out of acceptable range\n", path.c_str(), value);
			return true;
		}
	}
	printf("%s = %g\n", path.c_str(), value);
	return false;
}

bool CQnetConfigure::GetValue(const std::string &path, const std::string &mod, int &value, const int min, const int max)
{
	auto it = cfg.find(path);
	if (cfg.end() == it)
	{
		int dvalue;
		if (GetDefaultInt(path, mod, dvalue))
		{
			fprintf(stderr, "%s not found in either the cfg file or the defaults file\n", path.c_str());
			return true;
		}
		if (dvalue < min || dvalue > max)
		{
			fprintf(stderr, "Default value %s=%d is out of acceptable range\n", path.c_str(), value);
			return true;
		}
		value = dvalue;
	}
	else
	{
		value = std::stoi(it->second);
		if (value < min || value > max)
		{
			fprintf(stderr, "%s=%s is out of acceptable range\n", path.c_str(), it->second.c_str());
			return true;
		}
	}
	printf("%s = %d\n", path.c_str(), value);
	return false;
}

bool CQnetConfigure::GetValue(const std::string &path, const std::string &mod, std::string &value, int min, int max)
{
	auto it = cfg.find(path);
	if (cfg.end() == it)
	{
		std::string dvalue;
		if (GetDefaultString(path, mod, dvalue))
		{
			fprintf(stderr, "%s not found in either the cfg file or the defaults file\n", path.c_str());
			return true;
		}
		int l = dvalue.length();
		if (min-1>=l || l>max)
		{
			printf("Default value %s='%s' is wrong size\n", path.c_str(), value.c_str());
			return true;
		}
		value.assign(dvalue);
	}
	else
	{
		value.assign(it->second);
		int l = value.length();
		if (l<min || l>max)
		{
			printf("%s='%s' is wrong size\n", path.c_str(), value.c_str());
			return true;
		}
	}
	printf("%s = '%s'\n", path.c_str(), value.c_str());
	return false;
}
