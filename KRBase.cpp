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

#include <csignal>
#include <iostream>

#include "KRBase.h"

std::atomic<bool> CKRBase::keep_running(true);

CKRBase::CKRBase()
{
	std::signal(SIGINT, CKRBase::SigHandler);
	std::signal(SIGHUP, CKRBase::SigHandler);
	std::signal(SIGTERM, CKRBase::SigHandler);
}

bool CKRBase::IsRunning()
{
	return keep_running;
}

void CKRBase::SetState(bool state)
{
	keep_running = state;
}

void CKRBase::SigHandler(int sig)
{
	switch (sig)
	{
	case SIGINT:
	case SIGHUP:
	case SIGTERM:
		keep_running = false;
		break;
	default:
		std::cerr << "caught an unexpected signal=" << sig << std::endl;
		break;
	}
}

void CKRBase::AddFDSet(int &max, int newfd, fd_set *set)
{
	if (newfd > max)
		max = newfd;
	FD_SET(newfd, set);
}
