/*
 *   Copyright (C) 2010 by Scott Lawson KI4LKF
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <string>
#include "QnetConfigure.h"

bool isamod[3] = { false, false, false };
std::string announce_dir;
std::string qnvoice_file;

/* process configuration file */
bool read_config(const char *cfgFile)
{
	CQnetConfigure cfg;

	printf("Reading file %s\n", cfgFile);
	if (cfg.Initialize(cfgFile))
		return true;

	for (int m=0; m<3; m++)
	{
		std::string path("module_");
		path.append(std::to_string(m));
		std::string type;
		if (cfg.KeyExists(path))
		{
			cfg.GetValue(path, "", type, 1, 16);
			if (strcasecmp(type.c_str(), "dvap") && strcasecmp(type.c_str(), "dvrptr") && strcasecmp(type.c_str(), "mmdvm") && strcasecmp(type.c_str(), "itap"))
			{
				printf("module type '%s' is invalid\n", type.c_str());
				return true;
			}
			isamod[m] = true;
		}
	}

	std::string path("file_");
	cfg.GetValue(path+"announce_dir", "", announce_dir, 2, FILENAME_MAX);
	cfg.GetValue(path+"qnvoice_file", "", qnvoice_file, 2, FILENAME_MAX);

	return false;
}

void ToUpper(std::string &str)
{
	for (unsigned int i=0; i<str.size(); i++)
		if (islower(str[i]))
			str[i] = toupper(str[i]);
}

int main(int argc, char *argv[])
{
	char RADIO_ID[21];

	if (argc != 4)
	{
		printf("Usage: %s <module> <datFile> <txtMsg>\n", argv[0]);
		printf("Where...\n");
		printf("        <module>  is one of your modules: A, B or C\n");
		printf("        <datFile> is an installed voice file in the configured\n");
		printf("                  directory, for example \"unlinked.dat\"\n");
		printf("        <txtMsg>  is an up to 20-character text message\n");
		return 0;
	}
	char module = argv[1][0];

	std::string cfgfile(CFG_DIR);
	cfgfile += "/qn.cfg";
	if (read_config(cfgfile.c_str()))
		return 1;

	if (islower(module))
		module = toupper(module);
	if ((module != 'A') && (module != 'B') && (module != 'C'))
	{
		printf("module must be one of A B C\n");
		return 1;
	}

	char pathname[FILENAME_MAX];
	snprintf(pathname, FILENAME_MAX, "%s/%s", announce_dir.c_str(), argv[2]);

	FILE *fp = fopen(pathname, "rb");
	if (!fp)
	{
		printf("Failed to find file %s for reading\n", pathname);
		return 1;
	}
	fclose(fp);

	memset(RADIO_ID, '_', 20);
	RADIO_ID[20] = '\0';

	unsigned int len = strlen(argv[3]);
	strncpy(RADIO_ID, argv[3], len > 20 ? 20 : len);
	for (int i=0; i<20; i++)
		if (isspace(RADIO_ID[i]))
			RADIO_ID[i] = '_';

	fp = fopen(qnvoice_file.c_str(), "w");
	if (fp)
	{
		fprintf(fp, "%c_%s_%s\n", module, argv[2], RADIO_ID);
		fclose(fp);
	}
	else
	{
		printf("Failed to open %s for writing", qnvoice_file.c_str());
		return 1;
	}

	return 0;
}
