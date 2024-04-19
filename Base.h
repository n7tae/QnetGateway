#pragma once

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

// base class for all modems

#include <string>
#include <atomic>

class CBase
{
public:
	CBase() { keep_running = true; }
	virtual ~CBase() {}
	virtual bool Initialize(const std::string &path) = 0;
	virtual void Run() = 0;
	virtual void Close() = 0;
	void Stop() { keep_running = false; }
protected:
	std::atomic<bool> keep_running;
	void AddFDSet(int &max, int newfd, fd_set *set)
	{
		if (newfd > max)
			max = newfd;
		FD_SET(newfd, set);
	}
};

class CModem : public CBase
{
public:
	CModem(int index = -1) : CBase(), m_index(index) {}
	virtual ~CModem() {}

protected:
	int m_index;
};
