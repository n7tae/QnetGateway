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
#include <sstream>
#include <thread>

#include "QnetDB.h"

bool CQnetDB::Open(const char *name)
{
	if (sqlite3_open_v2(name, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL))
	{
		fprintf(stderr, "CQnetDB::Open: can't open %s\n", name);
		return true;
	}
	auto rval = sqlite3_busy_timeout(db, 1000);
	if (SQLITE_OK != rval)
	{
		fprintf(stderr, "sqlite3_busy_timeout returned %d\n", rval);
	}

	return Init();
}

bool CQnetDB::Init()
{
	char *eMsg;

	std::string sql("CREATE TABLE IF NOT EXISTS LHEARD("
					"callsign	TEXT PRIMARY KEY, "
					"sfx		TEXT DEFAULT '    ', "
					"message    TEXT DEFAULT '                    ', "
					"maidenhead TEXT DEFAULT '      ', "
					"latitude   REAL DEFAULT 0.0, "
					"longitude  REAL DEFAULT 0.0, "
					"module		TEXT, "
					"reflector	TEXT, "
					"lasttime	INT NOT NULL"
					") WITHOUT ROWID;");

	if (SQLITE_OK != sqlite3_exec(db, sql.c_str(), NULL, 0, &eMsg))
	{
		fprintf(stderr, "CQnetDB::Init [%s] error: %s\n", sql.c_str(), eMsg);
		sqlite3_free(eMsg);
		return true;
	}

	sql.assign("CREATE TABLE IF NOT EXISTS LINKSTATUS("
			   "ip_address		TEXT PRIMARY KEY, "
			   "from_mod		TEXT NOT NULL, "
			   "to_callsign    TEXT NOT NULL, "
			   "to_mod			TEXT NOT NULL, "
			   "linked_time	INT NOT NULL"
			   ") WITHOUT ROWID;");

	if (SQLITE_OK != sqlite3_exec(db, sql.c_str(), NULL, 0, &eMsg))
	{
		fprintf(stderr, "CQnetDB::Init [%s] error: %s\n", sql.c_str(), eMsg);
		sqlite3_free(eMsg);
		return true;
	}

	sql.assign("CREATE TABLE IF NOT EXISTS GATEWAYS("
			   "name		TEXT PRIMARY KEY, "
			   "address	TEXT NOT NULL, "
			   "port		INT NOT NULL"
			   ") WITHOUT ROWID;");

	if (SQLITE_OK != sqlite3_exec(db, sql.c_str(), NULL, 0, &eMsg))
	{
		fprintf(stderr, "CQnetDB::Init [%s] error: %s\n", sql.c_str(), eMsg);
		sqlite3_free(eMsg);
		return true;
	}
	return false;
}

static int countcallback(void *count, int /*argc*/, char **argv, char ** /*azColName*/)
{
	auto c = (int *)count;
	*c = atoi(argv[0]);
	return 0;
}

bool CQnetDB::UpdateLH(const char *callsign, const char *sfx, const char module, const char *reflector)
{
	if (NULL == db)
		return false;
	std::stringstream sql;
	sql << "SELECT COUNT(*) FROM LHEARD WHERE callsign='" << callsign << "';";

	int count = 0;

	char *eMsg;
	if (SQLITE_OK != sqlite3_exec(db, sql.str().c_str(), countcallback, &count, &eMsg))
	{
		fprintf(stderr, "CQnetDB::UpdateLH [%s] error: %s\n", sql.str().c_str(), eMsg);
		sqlite3_free(eMsg);
		return true;
	}

	sql.clear();

	if (count)
	{
		sql << "UPDATE LHEARD SET sfx = '" << sfx << "', module = '" << module << "', reflector = '" << reflector << "', lasttime = strftime('%s','now') WHERE callsign = '" << callsign << "';";
	}
	else
	{
		sql << "INSERT INTO LHEARD (callsign, sfx, module, reflector, lasttime) VALUES ('" << callsign << "', '" << sfx << "', '" << module << "', '" << reflector << "', strftime('%s','now'));";
	}

	if (SQLITE_OK != sqlite3_exec(db, sql.str().c_str(), NULL, 0, &eMsg))
	{
		fprintf(stderr, "CQnetDB::UpdateLH [%s] error: %s\n", sql.str().c_str(), eMsg);
		sqlite3_free(eMsg);
		return true;
	}

	return false;
}

bool CQnetDB::UpdatePosition(const char *callsign, const char *maidenhead, double latitude, double longitude)
{
	if (NULL == db)
		return false;
	std::stringstream sql;
	sql << "UPDATE LHEARD SET maidenhead = '" << maidenhead << "', latitude = " << latitude << ", longitude = " << longitude << ", lasttime = strftime('%s','now') WHERE callsign='" << callsign << "';";

	char *eMsg;
	if (SQLITE_OK != sqlite3_exec(db, sql.str().c_str(), NULL, 0, &eMsg))
	{
		fprintf(stderr, "CQnetDB::UpdatePosition [%s] error: %s\n", sql.str().c_str(), eMsg);
		sqlite3_free(eMsg);
		return true;
	}

	return false;
}

bool CQnetDB::UpdateMessage(const char *callsign, const char *message)
{
	if (NULL == db)
		return false;
	std::stringstream sql;
	sql << "UPDATE LHEARD SET message = '" << message << "', lasttime = strftime('%s','now') WHERE callsign='" << callsign << "';";

	char *eMsg;
	if (SQLITE_OK != sqlite3_exec(db, sql.str().c_str(), NULL, 0, &eMsg))
	{
		fprintf(stderr, "CQnetDB::UpdateMessage [%s] error: %s\n", sql.str().c_str(), eMsg);
		sqlite3_free(eMsg);
		return true;
	}

	return false;
}

bool CQnetDB::UpdateLS(const char *address, const char from_mod, const char *to_callsign, const char to_mod, time_t linked_time)
{
	if (NULL == db)
		return false;
	std::stringstream sql;
	sql << "INSERT OR REPLACE INTO LINKSTATUS (ip_address, from_mod, to_callsign, to_mod, linked_time) VALUES ('" << address << "', '" << from_mod << "', '" << to_callsign << "', '" << to_mod << "', " << linked_time << ");";

	char *eMsg;
	if (SQLITE_OK != sqlite3_exec(db, sql.str().c_str(), NULL, 0, &eMsg))
	{
		fprintf(stderr, "CQnetDB::UpdateLS [%s] error: %s\n", sql.str().c_str(), eMsg);
		sqlite3_free(eMsg);
		return true;
	}

	return false;
}

bool CQnetDB::UpdateGW(const char *name, const char *address, unsigned short port)
{
	if (NULL == db)
		return true;
	std::string n(name);
	n.resize(6, ' ');
	std::stringstream sql;
	sql << "INSERT OR REPLACE INTO GATEWAYS (name, address, port) VALUES ('" << n << "', '" << address << "', " << port << ");";

	char *eMsg;
	if (SQLITE_OK != sqlite3_exec(db, sql.str().c_str(), NULL, 0, &eMsg))
	{
		fprintf(stderr, "CQnetDB::UpdateGW [%s] error: %s\n", sql.str().c_str(), eMsg);
		sqlite3_free(eMsg);
		return true;
	}

	return false;
}

bool CQnetDB::UpdateGW(CHostQueue &hqueue)
{
	if (NULL == db)
		return false;

	char *eMsg;
	if (SQLITE_OK != sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, 0, &eMsg))
	{
		fprintf(stderr, "CQnetDB::UpdateGW BEGIN TRANSATION error: %s\n", eMsg);
		sqlite3_free(eMsg);
		return true;
	}

	while (!hqueue.Empty())
	{
		auto h = hqueue.Pop();
		UpdateGW(h.name.c_str(), h.addr.c_str(), h.port);
	}

	if (SQLITE_OK != sqlite3_exec(db, "COMMIT TRANSACTION;", NULL, 0, &eMsg))
	{
		fprintf(stderr, "CQnetDB::UpdateGW COMMIT TRANSACTION error: %s\n", eMsg);
		sqlite3_free(eMsg);
		return true;
	}
	return false;
}

bool CQnetDB::DeleteLS(const char *address)
{
	if (NULL == db)
		return false;
	std::stringstream sql;
	sql << "DELETE FROM LINKSTATUS WHERE ip_address=='" << address << "';";

	char *eMsg;
	if (SQLITE_OK != sqlite3_exec(db, sql.str().c_str(), NULL, 0, &eMsg))
	{
		fprintf(stderr, "CQnetDB::DeleteLS [%s] error: %s\n", sql.str().c_str(), eMsg);
		sqlite3_free(eMsg);
		return true;
	}

	return false;
}

bool CQnetDB::FindLS(const char mod, std::list<CLink> &linklist)
{
	if (NULL == db)
		return false;
	std::stringstream sql;
	sql << "SELECT ip_address,to_callsign,to_mod,linked_time FROM LINKSTATUS WHERE from_mod=='" << mod << "';";

	sqlite3_stmt *stmt;
	int rval = sqlite3_prepare_v2(db, sql.str().c_str(), -1, &stmt, 0);
	if (SQLITE_OK != rval)
	{
		fprintf(stderr, "CQnetDB::FindLS [%s] error\n", sql.str().c_str());
		return true;
	}

	while (SQLITE_ROW == sqlite3_step(stmt))
	{
		std::string cs((const char *)sqlite3_column_text(stmt, 1));
		std::string mod((const char *)sqlite3_column_text(stmt, 2));
		if (mod.at(0) != 'p')
		{
			cs.resize(7, ' ');
			cs.append(mod);
		}
		linklist.push_back(CLink(cs, sqlite3_column_text(stmt, 0), sqlite3_column_int(stmt, 3)));
	}

	sqlite3_finalize(stmt);
	return false;
}

bool CQnetDB::FindGW(const char *name, std::string &address, unsigned short &port)
// returns true if NOT found
{
	if (NULL == db)
		return false;
	std::string n(name);
	n.resize(6, ' ');
	std::stringstream sql;
	sql << "SELECT address, port FROM GATEWAYS WHERE name=='" << n << "';";

	sqlite3_stmt *stmt;
	int rval = sqlite3_prepare_v2(db, sql.str().c_str(), -1, &stmt, 0);
	if (SQLITE_OK != rval)
	{
		fprintf(stderr, "CQnetDB::FindGW error: %d\n", rval);
		return true;
	}

	if (SQLITE_ROW == sqlite3_step(stmt))
	{
		address.assign((const char *)sqlite3_column_text(stmt, 0));
		port = (unsigned short)(sqlite3_column_int(stmt, 1));
		sqlite3_finalize(stmt);
		return false;
	}
	else
	{
		sqlite3_finalize(stmt);
		return true;
	}
}

bool CQnetDB::FindGW(const char *name)
// returns true if found
{
	if (NULL == db)
		return false;
	std::string n(name);
	n.resize(6, ' ');
	std::stringstream sql;
	sql << "SELECT address,port FROM GATEWAYS WHERE name=='" << n << "';";

	sqlite3_stmt *stmt;
	int rval = sqlite3_prepare_v2(db, sql.str().c_str(), -1, &stmt, 0);
	if (SQLITE_OK != rval)
	{
		fprintf(stderr, "CQnetDB::FindGW error: %d\n", rval);
		return true;
	}

	if (SQLITE_ROW == sqlite3_step(stmt))
	{
		sqlite3_finalize(stmt);
		return true;
	}
	else
	{
		sqlite3_finalize(stmt);
		return false;
	}
}

void CQnetDB::ClearLH()
{
	if (NULL == db)
		return;

	char *eMsg;

	if (SQLITE_OK != sqlite3_exec(db, "DELETE FROM LHEARD;", NULL, 0, &eMsg))
	{
		fprintf(stderr, "CQnetDB::ClearLH error: %s\n", eMsg);
		sqlite3_free(eMsg);
	}
}

void CQnetDB::ClearLS()
{
	if (NULL == db)
		return;

	char *eMsg;

	if (SQLITE_OK != sqlite3_exec(db, "DELETE FROM LINKSTATUS;", NULL, 0, &eMsg))
	{
		fprintf(stderr, "CQnetDB::ClearLS error: %s\n", eMsg);
		sqlite3_free(eMsg);
	}
}

void CQnetDB::ClearGW()
{
	if (NULL == db)
		return;

	char *eMsg;

	if (SQLITE_OK != sqlite3_exec(db, "DELETE FROM GATEWAYS;", NULL, 0, &eMsg))
	{
		fprintf(stderr, "CQnetDB::ClearGW error: %s\n", eMsg);
		sqlite3_free(eMsg);
	}
}

int CQnetDB::Count(const char *table)
{
	if (NULL == db)
		return 0;

	std::string sql("SELECT COUNT(*) FROM ");
	sql.append(table);
	sql.append(";");

	int count = 0;

	char *eMsg;
	if (SQLITE_OK != sqlite3_exec(db, sql.c_str(), countcallback, &count, &eMsg))
	{
		fprintf(stderr, "CQnetDB::Count error: %s\n", eMsg);
		sqlite3_free(eMsg);
	}

	return count;
}
