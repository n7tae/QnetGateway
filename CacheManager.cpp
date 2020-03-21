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

#include "CacheManager.h"

void CCacheManager::findUserData(const std::string &user, std::string &rptr, std::string &gate, std::string &addr)
{
	mux.lock();
	rptr.assign(findUserRptr(user));
	gate.assign(findRptrGate(rptr));
	addr.assign(findGateAddr(gate));
	mux.unlock();
}

void CCacheManager::findRptrData(const std::string &rptr, std::string &gate, std::string &addr)
{
	mux.lock();
	gate.assign(findRptrGate(rptr));
	addr.assign(findGateAddr(gate));
	mux.unlock();
}

std::string CCacheManager::findUserAddr(const std::string &user)
{
	mux.lock();
	std::string addr(findGateAddr(findRptrGate(findUserRptr(user))));
	mux.unlock();

	return addr;
}

std::string CCacheManager::findUserTime(const std::string &user)
{
	std::string utime;
	if (user.empty())
		return utime;
	mux.lock();
	auto itt = UserTime.find(user);
	if (itt != UserTime.end())
		utime.assign(itt->second);
	mux.unlock();
	return utime;
}

std::string CCacheManager::findUserRepeater(const std::string &user)
{
	mux.lock();
	std::string rptr(findUserRptr(user));
	mux.unlock();
	return rptr;
}

std::string CCacheManager::findGateAddress(const std::string &gate)
{
	mux.lock();
	std::string addr(findGateAddr(gate));
	mux.unlock();
	return addr;
}

std::string CCacheManager::findNameNick(const std::string &name)
{
	std::string nick;
	if (name.empty())
		return nick;
	mux.lock();
	auto itn = NameNick.find(name);
	if (itn != NameNick.end())
		nick.assign(itn->second);
	mux.unlock();
	return nick;
}

std::string CCacheManager::findServerUser()
{
	std::string suser;
	mux.lock();
	for (auto it=NameNick.begin(); it!=NameNick.end(); it++) {
		if (0 == it->first.compare(0, 2, "s-")) {
			suser.assign(it->first);
			break;
		}
	}
	mux.unlock();
	return suser;
}

void CCacheManager::updateUser(const std::string &user, const std::string &rptr, const std::string &gate, const std::string &addr, const std::string &time)
{
	if (user.empty())
		return;

	mux.lock();
	if (! time.empty())
		UserTime[user] = time;

	if (rptr.empty()) {
		mux.unlock();
		return;
	}

	UserRptr[user] = rptr;

	if (gate.empty() || addr.empty()) {
		mux.unlock();
		return;
	}

	if (rptr.compare(0, 7, gate, 0, 7))
		RptrGate[rptr] = gate;	// only do this if they differ

	GateAddr[gate] = addr;
	mux.unlock();
}

void CCacheManager::updateRptr(const std::string &rptr, const std::string &gate, const std::string &addr)
{
	if (rptr.empty() || gate.empty())
		return;

	mux.lock();
	RptrGate[rptr] = gate;
	if (addr.empty()) {
		mux.unlock();
		return;
	}
	GateAddr[gate] = addr;
	mux.unlock();
}

void CCacheManager::updateGate(const std::string &G, const std::string &addr)
{
	if (G.empty() || addr.empty())
		return;
	std::string gate(G);
	auto p = gate.find('_');
	while (gate.npos != p) {
		gate[p] = ' ';
		p = gate.find('_');
	}
	mux.lock();
	GateAddr[gate] = addr;
	mux.unlock();
}

void CCacheManager::updateName(const std::string &name, const std::string &nick)
{
	if (name.empty() || nick.empty())
		return;
	mux.lock();
	NameNick[name] = nick;
	mux.unlock();
}

void CCacheManager::eraseGate(const std::string &gate)
{
	mux.lock();
	GateAddr.erase(gate);
	mux.unlock();
}

void CCacheManager::eraseName(const std::string &name)
{
	mux.lock();
	NameNick.erase(name);
	mux.unlock();
}

void CCacheManager::clearGate()
{
	mux.lock();
	GateAddr.clear();
	NameNick.clear();
	mux.unlock();
}

// these last three functions are private and not mux locked.
std::string CCacheManager::findUserRptr(const std::string &user)
{
	std::string rptr;
	if (user.empty())
		return rptr;
	auto it = UserRptr.find(user);
	if (it != UserRptr.end())
		rptr.assign(it->second);
	return rptr;
}

std::string CCacheManager::findRptrGate(const std::string &rptr)
{
	std::string gate;
	if (rptr.empty())
		return gate;
	auto it = RptrGate.find(rptr);
	if (it == RptrGate.end()) {
		gate.assign(rptr);
		gate[7] = 'G';
	} else
		gate.assign(it->second);
	return gate;
}

std::string CCacheManager::findGateAddr(const std::string &gate)
{
	std::string addr;
	if (gate.empty())
		return addr;
	auto ita = GateAddr.find(gate);
	if (ita != GateAddr.end())
		addr.assign(ita->second);
	return addr;
}
