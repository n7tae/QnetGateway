/*
 *   Copyright (c) 2020 by Thomas A. Early N7TAE
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
#include <mutex>
#include <unordered_map>

class CCacheManager {
public:
	CCacheManager() {}
	~CCacheManager() {}

	// the bodies of these public functions are mux locked to access the maps and the private functions.
	// for these find functions, if a map value can't be found the returned string will be empty.
	void findUserData(const std::string &user, std::string &rptr, std::string &gate, std::string &addr);
	void findRptrData(const std::string &rptr, std::string &gate, std::string &addr);
	std::string findUserTime(const std::string &user);
	std::string findUserAddr(const std::string &user);
	std::string findNameNick(const std::string &name);
	std::string findUserRepeater(const std::string &user);
	std::string findGateAddress(const std::string &gate);
	std::string findServerUser();
	void eraseGate(const std::string &gate);
	void eraseName(const std::string &name);
	void clearGate();

	void updateUser(const std::string &user, const std::string &rptr, const std::string &gate, const std::string &addr, const std::string &time);
	void updateRptr(const std::string &rptr, const std::string &gate, const std::string &addr);
	void updateGate(const std::string &gate, const std::string &addr);
	void updateName(const std::string &name, const std::string &nick);

private:
	// these three functions aren't mux locked, that's why they're private
	std::string findUserRptr(const std::string &user);
	std::string findRptrGate(const std::string &rptr);
	std::string findGateAddr(const std::string &gate);

	std::unordered_map<std::string, std::string> UserTime;
	std::unordered_map<std::string, std::string> UserRptr;
	std::unordered_map<std::string, std::string> RptrGate;
	std::unordered_map<std::string, std::string> GateAddr;
	std::unordered_map<std::string, std::string> NameNick;
	std::mutex mux;
};
