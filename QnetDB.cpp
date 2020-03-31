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
	if (sqlite3_open(name, &db)) {
		fprintf(stderr, "CQnetDB::Open: can't open %s\n", name);
		return true;
	} else
		return false;
}

bool CQnetDB::Init()
{
	std::string sql("DROP TABLE IF EXISTS LHEARD;");

	char *eMsg;
	if (SQLITE_OK != sqlite3_exec(db, sql.c_str(), NULL, 0, &eMsg)) {
		fprintf(stderr, "CQnetDB::Open drop table LHEARD error: %s\n", eMsg);
		sqlite3_free(eMsg);
		return true;
	}

	sql.assign("CREATE TABLE LHEARD("
				"callsign	TEXT PRIMARY KEY, "
				"sfx		TEXT, "
				"module		TEXT, "
				"reflector	TEXT, "
				"lasttime	INT NOT NULL"
			") WITHOUT ROWID;");

	if (SQLITE_OK != sqlite3_exec(db, sql.c_str(), NULL, 0, &eMsg)) {
		fprintf(stderr, "CQnetDB::Open create table LHEARD error: %s\n", eMsg);
		sqlite3_free(eMsg);
		return true;
	}

	sql.assign("DROP TABLE IF EXISTS LINKSTATUS;");

	if (SQLITE_OK != sqlite3_exec(db, sql.c_str(), NULL, 0, &eMsg)) {
		fprintf(stderr, "CQnetDB::Open drop table LINKSTATUS error: %s\n", eMsg);
		sqlite3_free(eMsg);
		return true;
	}

	sql.assign("CREATE TABLE LINKSTATUS("
				"ip_address		TEXT PRIMARY KEY, "
				"from_mod		TEXT NOT NULL, "
				"to_callsign    TEXT NOT NULL, "
				"to_mod			TEXT NOT NULL, "
				"linked_time	INT NOT NULL"
			") WITHOUT ROWID;");

	if (SQLITE_OK != sqlite3_exec(db, sql.c_str(), NULL, 0, &eMsg)) {
		fprintf(stderr, "CQnetDB::Open create table LINKSTATUS error: %s\n", eMsg);
		sqlite3_free(eMsg);
		return true;
	}

	return false;
}

bool CQnetDB::UpdateLH(const char *callsign, const char *sfx, const char module, const char *reflector)
{
	if (NULL == db)
		return false;
	std::string sql("REPLACE INTO LHEARD (callsign,sfx,module,reflector,lasttime) VALUES ('");
	sql.append(callsign);
	sql.append("','");
	sql.append(sfx);
	sql.append("','");
	sql.append(1, module);
	sql.append("','");
	sql.append(reflector);
	sql.append("',");
	sql.append("strftime('%s','now'));");

	char *eMsg;
	if (SQLITE_OK != sqlite3_exec(db, sql.c_str(), NULL, 0, &eMsg)) {
		fprintf(stderr, "CQnetDB::UpdateLH error: %s\n", eMsg);
		sqlite3_free(eMsg);
		return true;
	}

	return false;
}

bool CQnetDB::UpdateLS(const char *address, const char from_mod, const char *to_callsign, const char to_mod, time_t linked_time)
{
	if (NULL == db)
		return false;
	std::string sql = "REPLACE INTO LINKSTATUS (ip_address,from_mod,to_callsign,to_mod,linked_time) VALUES ('";
	sql.append(address);
	sql.append("','");
	sql.append(1, from_mod);
	sql.append("','");
	sql.append(to_callsign);
	sql.append("','");
	sql.append(1, to_mod);
	sql.append("',");
	sql.append(std::to_string(linked_time).c_str());
	sql.append(");");

	char *eMsg;
	if (SQLITE_OK != sqlite3_exec(db, sql.c_str(), NULL, 0, &eMsg)) {
		fprintf(stderr, "CQnetDB::UpdateLS error: %s\n", eMsg);
		sqlite3_free(eMsg);
		return true;
	}

	return false;
}

bool CQnetDB::DeleteLS(const char *address)
{
	if (NULL == db)
		return false;
	std::string sql("DELETE FROM LINKSTATUS WHERE ip_address=='");
	sql.append(address);
	sql.append("';");

	char *eMsg;
	if (SQLITE_OK != sqlite3_exec(db, sql.c_str(), NULL, 0, &eMsg)) {
		fprintf(stderr, "CQnetDB::DeleteLS error: %s\n", eMsg);
		sqlite3_free(eMsg);
		return true;
	}

	return false;
}

bool CQnetDB::FindLS(const char mod, std::list<CLink> &linklist)
{
	if (NULL == db)
		return false;
	std::string sql("SELECT ip_address,to_callsign,to_mod,linked_time FROM LINKSTATUS WHERE from_mod=='");
	sql.append(1, mod);
	sql.append("';");

	sqlite3_stmt *stmt;
	int rval = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
	if (SQLITE_OK != rval) {
		fprintf(stderr, "CQnetDB::FindLS error: %d\n", rval);
		return true;
	}

	while (SQLITE_ROW == sqlite3_step(stmt)) {
		std::string cs((const char *)sqlite3_column_text(stmt, 1));
		std::string mod((const char *)sqlite3_column_text(stmt, 2));
		if (mod.at(0) != 'p') {
			cs.resize(7, ' ');
			cs.append(mod);
		}
		linklist.push_back(CLink(cs, sqlite3_column_text(stmt, 0), sqlite3_column_int(stmt, 3)));
	}

	sqlite3_finalize(stmt);
	return false;
}
