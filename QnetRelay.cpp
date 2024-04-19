/*
 *   Copyright (C) 2018-2021 by Thomas A. Early N7TAE
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

#include <exception>
#include <cstdio>
#include <cctype>
#include <cstring>
#include <csignal>
#include <ctime>
#include <memory>
#include <cstdlib>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "QnetRelay.h"
#include "QnetTypeDefs.h"
#include "QnetConfigure.h"

#define RELAY_VERSION "QnetRelay-20307"

bool CQnetRelay::Initialize(const std::string &cfgfile)
{
	if (ReadConfig(cfgfile))
		return true;

	msock = OpenSocket(MMDVM_INTERNAL_IP, MMDVM_OUT_PORT);
	if (msock < 0)
		return true;

	std::string name("Gate2Modem");
	name.append(1, RPTR_MOD);
	printf("Opening %s\n", name.c_str());
	if (FromGate.Open(name.c_str()))
		return true;
	name.assign("Modem");
	name.append(1, RPTR_MOD);
	name.append("2Gate");
	ToGate.SetUp(name.c_str());

	return false;
}

int CQnetRelay::OpenSocket(const std::string &address, unsigned short port)
{
	if (! port)
	{
		printf("ERROR: OpenSocket: non-zero port must be specified.\n");
		return -1;
	}

	int fd = ::socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
	{
		printf("Cannot create the UDP socket, err: %d, %s\n", errno, strerror(errno));
		return -1;
	}

	sockaddr_in addr;
	::memset(&addr, 0, sizeof(sockaddr_in));
	addr.sin_family      = AF_INET;
	addr.sin_port        = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (! address.empty())
	{
		addr.sin_addr.s_addr = ::inet_addr(address.c_str());
		if (addr.sin_addr.s_addr == INADDR_NONE)
		{
			printf("The local address is invalid - %s\n", address.c_str());
			close(fd);
			return -1;
		}
	}

	int reuse = 1;
	if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) == -1)
	{
		printf("Cannot set the UDP socket %s:%u option, err: %d, %s\n", address.c_str(), port, errno, strerror(errno));
		close(fd);
		return -1;
	}

	if (::bind(fd, (sockaddr*)&addr, sizeof(sockaddr_in)) == -1)
	{
		printf("Cannot bind the UDP socket %s:%u address, err: %d, %s\n", address.c_str(), port, errno, strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

void CQnetRelay::Run()
{
	int fd = FromGate.GetFD();

	printf("msock=%d, gateway=%d\n", msock, fd);

	keep_running = true;

	while (keep_running)
	{
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(msock, &readfds);
		FD_SET(fd, &readfds);
		int maxfs = (msock > fd) ? msock : fd;

		// don't care about writefds and exceptfds:
		// and we'll wait as long as needed
		int ret = ::select(maxfs+1, &readfds, NULL, NULL, NULL);
		if (ret < 0)
		{
			printf("ERROR: Run: select returned err=%d, %s\n", errno, strerror(errno));
			break;
		}
		if (ret == 0)
			continue;

		// there is something to read!
		unsigned char buf[100];
		sockaddr_in addr;
		memset(&addr, 0, sizeof(sockaddr_in));
		socklen_t size = sizeof(sockaddr);
		ssize_t len;

		if (FD_ISSET(msock, &readfds))
		{
			len = ::recvfrom(msock, buf, 100, 0, (sockaddr *)&addr, &size);

			if (len < 0)
			{
				fprintf(stderr, "ERROR: Run: recvfrom(mmdvmhost) return error %d: %s\n", errno, strerror(errno));
				break;
			}

			if (ntohs(addr.sin_port) != MMDVM_IN_PORT)
				fprintf(stderr, "DEBUG: Run: read from msock but port was %u, expected %u.\n", ntohs(addr.sin_port), MMDVM_IN_PORT);

		}

		if (FD_ISSET(fd, &readfds))
		{
			len = FromGate.Read(buf, 100);

			if (len < 0)
			{
				fprintf(stderr, "ERROR: Run: ToGate.Read() returned error %d: %s\n", errno, strerror(errno));
				break;
			}
		}

		if (len == 0)
		{
			fprintf(stderr, "DEBUG: Run: read zero bytes from %u\n", ntohs(addr.sin_port));
			continue;
		}

		if (0 == memcmp(buf, "DSRP", 4))
		{
			//printf("read %d bytes from MMDVMHost\n", (int)len);
			if (ProcessMMDVM(len, buf))
				break;
		}
		else if (0 == ::memcmp(buf, "DSVT", 4))
		{
			//printf("read %d bytes from MMDVMHost\n", (int)len);
			if (ProcessGateway(len, buf))
				break;
		}
		else
		{
			char title[5];
			for (int i=0; i<4; i++)
				title[i] = (buf[i]>=0x20u && buf[i]<0x7fu) ? buf[i] : '.';
			title[4] = '\0';
			fprintf(stderr, "DEBUG: Run: received unknow packet '%s' len=%d\n", title, (int)len);
		}
	}
}

void CQnetRelay::Close()
{
	::close(msock);
	FromGate.Close();
}

int CQnetRelay::SendTo(const int fd, const unsigned char *buf, const int size, const std::string &address, const unsigned short port)
{
	sockaddr_in addr;
	::memset(&addr, 0, sizeof(sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = ::inet_addr(address.c_str());
	addr.sin_port = htons(port);

	int len = ::sendto(fd, buf, size, 0, (sockaddr *)&addr, sizeof(sockaddr_in));
	if (len < 0)
		printf("ERROR: SendTo: fd=%d failed sendto %s:%u err: %d, %s\n", fd, address.c_str(), port, errno, strerror(errno));
	else if (len != size)
		printf("ERROR: SendTo: fd=%d tried to sendto %s:%u %d bytes, actually sent %d.\n", fd, address.c_str(), port, size, len);
	return len;
}

bool CQnetRelay::ProcessGateway(const int len, const unsigned char *raw)
{
	if (27==len || 56==len)   //here is dstar data
	{
		SDSVT dsvt;
		::memcpy(dsvt.title, raw, len);	// transfer raw data to SDSVT struct

		SDSRP dsrp;	// destination
		// fill in some inital stuff
		::memcpy(dsrp.title, "DSRP", 4);
		dsrp.voice.id = dsvt.streamid;	// voice or header is the same position
		dsrp.voice.seq = dsvt.ctrl;	// ditto
		if (27 == len)  	// write an AMBE packet
		{
			dsrp.tag = 0x21U;
			if (log_qso && (dsrp.voice.seq & 0x40))
				printf("Sent DSRP end of streamid=%04x\n", ntohs(dsrp.voice.id));
			if ((dsrp.voice.seq & ~0x40U) > 20)
				printf("DEBUG: ProcessGateway: unexpected voice sequence number %d\n", dsrp.voice.seq);
			dsrp.voice.err = 0;	// NOT SURE WHERE TO GET THIS FROM THE INPUT buf
			memcpy(dsrp.voice.ambe, dsvt.vasd.voice, 12);
			int ret = SendTo(msock, dsrp.title, 21, MMDVM_TARGET_IP, MMDVM_IN_PORT);
			if (ret != 21)
			{
				printf("ERROR: ProcessGateway: Could not write AMBE mmdvmhost packet\n");
				return true;
			}
		}
		else  			// write a Header packet
		{
			dsrp.tag = 0x20U;
			if (dsrp.header.seq)
			{
//				printf("DEBUG: ProcessGateway: unexpected pkt.header.seq %d, resetting to 0\n", pkt.header.seq);
				dsrp.header.seq = 0;
			}
			//memcpy(dsrp.header.flag, dsvt.hdr.flag, 41);
			memcpy(dsrp.header.flag, dsvt.hdr.flag,   3);
			if (IS_DSTARREPEATER)
			{
				memcpy(dsrp.header.r1,   dsvt.hdr.rpt2,   8);
				memcpy(dsrp.header.r2,   dsvt.hdr.rpt1,   8);
			}
			else
			{
				memcpy(dsrp.header.r1,   dsvt.hdr.rpt1,   8);
				memcpy(dsrp.header.r2,   dsvt.hdr.rpt2,   8);
			}
			memcpy(dsrp.header.ur,   dsvt.hdr.urcall, 8);
			memcpy(dsrp.header.my,   dsvt.hdr.mycall, 8);
			memcpy(dsrp.header.nm,   dsvt.hdr.sfx,    4);
			memcpy(dsrp.header.pfcs, dsvt.hdr.pfcs,   2);
			int ret = SendTo(msock, dsrp.title, 49, MMDVM_TARGET_IP, MMDVM_IN_PORT);
			if (ret != 49)
			{
				printf("ERROR: ProcessGateway: Could not write Header mmdvmhost packet\n");
				return true;
			}
			if (log_qso)
				printf("Sent DSRP to %u, streamid=%04x ur=%.8s r1=%.8s r2=%.8s my=%.8s/%.4s\n", MMDVM_IN_PORT, ntohs(dsrp.header.id), dsrp.header.ur, dsrp.header.r2, dsrp.header.r1, dsrp.header.my, dsrp.header.nm);
		}

	}
	else
		printf("DEBUG: ProcessGateway: unusual packet size read len=%d\n", len);
	return false;
}

bool CQnetRelay::ProcessMMDVM(const int len, const unsigned char *raw)
{
	static unsigned short id = 0U;
	SDSRP dsrp;
	if (len < 65)
		::memcpy(dsrp.title, raw, len);	// transfer raw data to SDSRP struct

	if (49==len || 21==len || len==24)
	{
		// grab the stream id if this is a header
		if (49 == len)
		{
			if (dsrp.header.id == id)
				return false;
			id = dsrp.header.id;
		}
		else
		{
			if (dsrp.voice.id != id)
				return false;
		}

		SDSVT dsvt;	// destination
		// sets most of the params
		::memcpy(dsvt.title, "DSVT", 4);
		dsvt.config = (len==49) ? 0x10U : 0x20U;
		memset(dsvt.flaga, 0U, 3U);
		dsvt.id = 0x20U;
		dsvt.flagb[0] = 0x0U;
		dsvt.flagb[1] = 0x1U;
		dsvt.flagb[2] = ('B'==RPTR_MOD) ? 0x1U : (('C'==RPTR_MOD) ? 0x2U : 0x3U);
		dsvt.streamid = id;

		if (49 == len)  	// header
		{
			dsvt.ctrl = 0x80;
			//memcpy(dsvt.hdr.flag, dsrp.header.flag, 41);
			memcpy(dsvt.hdr.flag,   dsrp.header.flag, 3);
			memcpy(dsvt.hdr.rpt1,   dsrp.header.r1,   8);
			memcpy(dsvt.hdr.rpt2,   dsrp.header.r2,   8);
			memcpy(dsvt.hdr.urcall, dsrp.header.ur,   8);
			memcpy(dsvt.hdr.mycall, dsrp.header.my,   8);
			memcpy(dsvt.hdr.sfx,    dsrp.header.nm,   4);
			memcpy(dsvt.hdr.pfcs,   dsrp.header.pfcs, 2);
			if (ToGate.Write(dsvt.title, 56))
			{
				printf("ERROR: ProcessMMDVM: Could not write gateway header packet\n");
				return true;
			}
			if (log_qso)
				printf("Sent DSVT streamid=%04x ur=%.8s r1=%.8s r2=%.8s my=%.8s/%.4s\n", ntohs(dsvt.streamid), dsvt.hdr.urcall, dsvt.hdr.rpt1, dsvt.hdr.rpt2, dsvt.hdr.mycall, dsvt.hdr.sfx);
		}
		else  	// ambe
		{
			dsvt.ctrl = dsrp.header.seq;
			memcpy(dsvt.vasd.voice, dsrp.voice.ambe, (21==len)?12:15);

			if (ToGate.Write(dsvt.title, 27))
			{
				printf("ERROR: ProcessMMDVM: Could not write gateway voice packet\n");
				return true;
			}

			if (log_qso && dsvt.ctrl&0x40)
				printf("Sent DSVT end of streamid=%04x\n", ntohs(dsvt.streamid));
		}
	}
	else if (len < 65 && dsrp.tag == 0xAU)
	{
//		printf("MMDVM Poll: '%s'\n", (char *)mpkt.poll_msg);
	}
	else
		printf("DEBUG: ProcessMMDVM: unusual packet len=%d\n", len);
	return false;
}

// process configuration file and return true if there was a problem
bool CQnetRelay::ReadConfig(const std::string &cfgFile)
{
	CQnetConfigure cfg;
	printf("Reading file %s\n", cfgFile.c_str());
	if (cfg.Initialize(cfgFile))
		return true;

	const std::string estr;	// an empty GetDefaultString

	std::string mmdvm_path("module_");
	std::string type;
	if (0 > m_index)
	{
		// we need to find the lone mmdvmhost module
		for (int i=0; i<3; i++)
		{
			std::string test(mmdvm_path);
			test.append(1, 'a'+i);
			if (cfg.KeyExists(test))
			{
				cfg.GetValue(test, estr, type, 1, 16);
				if (type.compare("mmdvmhost"))
					continue;	// this ain't it!
				mmdvm_path.assign(test);
				m_index = i;
				break;
			}
		}
		if (0 > m_index)
		{
			fprintf(stderr, "Error: no 'mmdvmhost' module found\n!");
			return true;
		}
	}
	else
	{
		// make sure mmdvmhost module is defined
		mmdvm_path.append(1, 'a' + m_index);
		if (cfg.KeyExists(mmdvm_path))
		{
			cfg.GetValue(mmdvm_path, estr, type, 1, 16);
			if (type.compare("mmdvmhost"))
			{
				fprintf(stderr, "%s = %s is not 'mmdvmhost' type!\n", mmdvm_path.c_str(), type.c_str());
				return true;
			}
		}
		else
		{
			fprintf(stderr, "Module '%c' is not defined.\n", 'a'+m_index);
			return true;
		}
	}
	RPTR_MOD = 'A' + m_index;

	cfg.GetValue(mmdvm_path+"_internal_ip", type, MMDVM_INTERNAL_IP, 7, IP_SIZE);
	cfg.GetValue(mmdvm_path+"_target_ip", type, MMDVM_TARGET_IP, 7, IP_SIZE);

	int i;
	cfg.GetValue(mmdvm_path+"_local_port", type, i, 10000, 65535);
	MMDVM_IN_PORT = (unsigned short)i;
	cfg.GetValue(mmdvm_path+"_gateway_port", type, i, 10000, 65535);
	MMDVM_OUT_PORT = (unsigned short)i;

	cfg.GetValue(mmdvm_path+"_is_dstarrepeater", type, IS_DSTARREPEATER);
	cfg.GetValue("log_qso", estr, log_qso);

	return false;
}

std::unique_ptr<CQnetRelay> prelay;

static void SignalHandler(int sig)
{
	switch (sig)
	{
	case SIGINT:
	case SIGHUP:
	case SIGTERM:
		if (prelay)
			prelay->Stop();
		break;

	default:
		fprintf(stderr, "Caught an unexpected signal: %d\n", sig);
		break;
	}
}

int main(int argc, const char **argv)
{
	setbuf(stdout, NULL);
	if (2 != argc)
	{
		fprintf(stderr, "usage: %s path_to_config_file\n", argv[0]);
		return 1;
	}

	if ('-' == argv[1][0])
	{
		printf("%s Copyright (C) 2018-2024 by Thomas A. Early N7TAE\n", RELAY_VERSION);
		printf("QnetRelay comes with ABSOLUTELY NO WARRANTY; see the LICENSE for details.\n");
		printf("This is free software, and you are welcome to distribute it\nunder certain conditions that are discussed in the LICENSE file.\n");
		return 0;
	}

	const char *qn = strstr(argv[0], "qnrelay");
	if (NULL == qn)
	{
		fprintf(stderr, "Error finding 'qnrelay' in %s!\n", argv[0]);
		return 1;
	}
	qn += 7;
	int module;
	switch (*qn)
	{
	case 0:
		module = -1;
		break;
	case 'a':
		module = 0;
		break;
	case 'b':
		module = 1;
		break;
	case 'c':
		module = 2;
		break;
	default:
		fprintf(stderr, "assigned module must be a, b or c\n");
		return 1;
	}

	prelay = std::unique_ptr<CQnetRelay>(new CQnetRelay(module));

	if (!prelay)
	{
		fprintf(stderr, "Could not make a CQnetRelay!\n");
		return EXIT_FAILURE;
	}

	if (prelay->Initialize(argv[1]))
	{
		prelay.reset();
		return EXIT_FAILURE;
	}

	prelay->Run();

	prelay->Close();

	printf("%s is closing.\n", argv[0]);

	return EXIT_SUCCESS;
}
