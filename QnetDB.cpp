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
#include "QnetDB.h"

bool CQnetDB::Open(const char *name)
{
	if (sqlite3_open(name, &db))
		return true;

	std::string sql =	"DROP TABLE IF EXISTS LHEARD;";

	char *eMsg;
	if (SQLITE_OK != sqlite3_exec(db, sql.c_str(), NULL, 0, &eMsg)) {
		fprintf(stderr, "CQnetDB::Open drop table error: %s\n", eMsg);
		sqlite3_free(eMsg);
		return true;
	}

	sql =	"CREATE TABLE LHEARD("
				"mycall		TEXT PRIMARY KEY, "
				"sfx		TEXT, "
				"urcall		TEXT, "
				"lasttime	INT NOT NULL"
			") WITHOUT ROWID;";

	if (SQLITE_OK != sqlite3_exec(db, sql.c_str(), NULL, 0, &eMsg)) {
		fprintf(stderr, "CQnetDB::Open create table error: %s\n", eMsg);
		sqlite3_free(eMsg);
		return true;
	}

	return false;
}

bool CQnetDB::Update(const char *mycall, const char *sfx, const char *urcall)
{
	if (NULL == db)
		return false;
	std::string sql = "REPLACE INTO LHEARD (mycall,sfx,urcall,lasttime) VALUES ('";
	sql.append(mycall);
	sql.append("','");
	sql.append(sfx);
	sql.append("','");
	sql.append(urcall);
	sql.append("',");
	sql.append("strftime('%s','now'));");

	char *eMsg;
	if (SQLITE_OK != sqlite3_exec(db, sql.c_str(), NULL, 0, &eMsg)) {
		fprintf(stderr, "CQnetDB::Update error: %s\n", eMsg);
		sqlite3_free(eMsg);
		return true;
	}

	return false;
}
