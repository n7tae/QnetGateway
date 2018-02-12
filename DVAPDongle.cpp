/*
 *   Copyright 2017-2018 by Thomas Early, N7TAE
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
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <termios.h>
#include <time.h>
#include <sys/file.h>
#include <sys/select.h>

#include "DVAPDongle.h"

extern void traceit(const char *fmt,...);

CDVAPDongle::CDVAPDongle() : MAX_REPL_CNT(20u)
{
}

CDVAPDongle::~CDVAPDongle()
{
}

bool CDVAPDongle::Initialize(char *serialno, int frequency, int offset, int power, int squelch)
{
	bool ok = false;
	char device[128];

	do {
		for (int i = 0; i < 32; i++) {
			sprintf(device, "/dev/ttyUSB%d", i);

			if (access(device, R_OK | W_OK) != 0)
				continue;

			ok = OpenSerial(device);
			if (!ok)
				continue;

			if (flock(serfd, LOCK_EX | LOCK_NB) != 0) {
				close(serfd);
				serfd = -1;
				ok = false;
				traceit("Device %s is already locked/used\n", device);
				continue;
			}
			traceit("Device %s now locked for exclusive use\n", device);

			ok = get_ser(device, serialno);
			if (!ok) {
				close(serfd);
				serfd = -1;
				continue;
			}
			break;
		}
		if (!ok)
			break;

		ok = get_name();
		if (!ok)
			break;

		ok = get_fw();
		if (!ok)
			break;


		ok = set_modu();
		if (!ok)
			break;

		ok = set_mode();
		if (!ok)
			break;

		ok = set_sql(squelch);
		if (!ok)
			break;

		ok = set_pwr(power);
		if (!ok)
			break;

		ok = set_off(offset);
		if (!ok)
			break;

		ok = set_freq(frequency);
		if (!ok)
			break;

		ok = start_dvap();
		if (!ok)
			break;

	} while (false);

	if (!ok) {
		if (serfd != -1) {
			Stop();
			close(serfd);
			serfd = -1;
		}
		return false;
	}
	return true;
}

REPLY_TYPE CDVAPDongle::GetReply(SDVAP_REGISTER &dr)
{
	dr.header = dr.param.control = 0;
	unsigned int off = 2;
	int rc = read_from_dvp(&dr.header, 2);	// read the header
	if (rc == 0)
		return RT_TIMEOUT;
	if (rc != 2)
		return RT_ERR;

	switch (dr.header) {
		case 0x5u:
		case 0x6u:
		case 0x7u:
		case 0x8u:
		case 0xcu:
		case 0xdu:
		case 0x10u:
		case 0x2005u:
		case 0x2007u:
		case 0x602fu:
		case 0xa02fu:
		case 0xc012u:
			break;	// these are all expected headers
		default:
			traceit("unknown header=0x%d\n", (unsigned)dr.header);
			if (syncit())
				return RT_ERR;
			return RT_TIMEOUT;
	}
	// read the rest of the register
	uint16_t len = dr.header & 0x1fff;
	while (off < len) {
		uint8_t *ptr = (uint8_t *)&dr;
		rc = read_from_dvp(ptr + off, len - off);
		if (rc < 0)
			return RT_TIMEOUT;
		if (rc > 0)
			off += rc;
	}
	// okay, now we'll parse the register and return its type
	switch (dr.header) {
		case 0x5u:
			switch (dr.param.control) {
				case 0x18u:
					if (dr.param.byte)
						return RT_START;
					else
						return RT_STOP;
				case 0x28u:
					if (0x1u==dr.param.ustr[0])
						return RT_MODU;
					break;
				case 0x80u:
					return RT_SQL;
				case 0x2au:
					if (0x0u==dr.param.ustr[0])
						return RT_MODE;
					break;
			}
			break;
		case 0x6u:
			switch (dr.param.control) {
				case 0x138u:
					return RT_PWR;
				case 0x400u:
					return RT_OFF;
			}
			break;
		case 0x7u:
			if (0x4u==dr.param.control && 0x1u==dr.param.ustr[0])
				return RT_FW;
			break;
		case 0x8u:
			if (0x220u==dr.param.control)
				return RT_FREQ;
			break;
		case 0xcu:
			if (0x230u==dr.param.control)
				return RT_FREQ_LIMIT;
			break;
		case 0xdu:
			if (0x2u==dr.param.control)
				return RT_SER;
			break;
		case 0x10u:
			if (0x1u==dr.param.control)
				return RT_NAME;
			break;
		case 0x2005u:
			if (0x118u==dr.param.control)
				return RT_PTT;
			break;
		case 0x2007u:
			if (0x90u==dr.param.control)
				return RT_STS;
			break;
		case 0x602fu:
			return RT_HDR_ACK;
		case 0xa02fu:
			return RT_HDR;
		case 0xc012u:
			return RT_DAT;
	}
	traceit("Unrecognized data from dvap: header=%#x control=%#x\n", (unsigned)dr.header, (unsigned)dr.param.control);
	if (syncit())
		return RT_ERR;
	return RT_TIMEOUT;
}

bool CDVAPDongle::syncit()
{
	unsigned char data[7];
	struct timeval tv;
	fd_set fds;
	short cnt = 0;

	traceit("Starting syncing dvap\n");
	memset(data,  0x00, 7);
	dvapreg.header = 0x2007u;
	dvapreg.param.control = 0x90u;

	while (memcmp(data, &dvapreg, 4) != 0) {
		FD_ZERO(&fds);
		FD_SET(serfd, &fds);
		tv.tv_sec  = 0;
		tv.tv_usec = 1000;
		int n = select(serfd + 1, &fds, NULL, NULL, &tv);
		if (n <= 0) {
			cnt ++;
			if (cnt > 100) {
				traceit("syncit() uncessful...stopping\n");
				return true;
			}
		} else {
			unsigned char c;
			n = read_from_dvp(&c, 1);
			if (n > 0) {
				data[0] = data[1];
				data[1] = data[2];
				data[2] = data[3];
				data[3] = data[4];
				data[4] = data[5];
				data[5] = data[6];
				data[6] = c;

				cnt = 0;
			}
		}
	}
	traceit("Stopping syncing dvap\n");
	return false;
}

bool CDVAPDongle::get_ser(char *dvp, char *dvap_serial_number)
{
	unsigned cnt = 0;
	REPLY_TYPE reply;
	dvapreg.header = 0x2004u;
	dvapreg.param.control = 0x2u;

	int rc = write_to_dvp(&dvapreg, 4);
	if (rc != 4) {
		traceit("Failed to send request to get dvap serial#\n");
		return false;
	}

	do {
		usleep(5000);

		reply = GetReply(dvapreg);
		cnt ++;
		if (cnt >= MAX_REPL_CNT) {
			traceit("Reached max number of requests to receive dvap serial#\n");
			return false;
		}
	} while (reply != RT_SER);

	if (0 == strcmp(dvapreg.param.sstr, dvap_serial_number)) {
		traceit("Using %s:  %s, because serial number matches your dvap_rptr.cfg\n", dvp, dvap_serial_number);
		return true;
	}
	traceit("Device %s has serial %s, but does not match your config value %s\n", dvp, dvapreg.param.sstr, dvap_serial_number);
	return false;
}

bool CDVAPDongle::get_name()
{
	unsigned cnt = 0;
	REPLY_TYPE reply;
	dvapreg.header = 0x2004u;
	dvapreg.param.control = 0x1u;

	int rc = write_to_dvp(&dvapreg, 4);
	if (rc != 4) {
		traceit("Failed to send request to get dvap name\n");
		return false;
	}

	do {
		usleep(5000);

		reply = GetReply(dvapreg);
		cnt ++;
		if (cnt >= MAX_REPL_CNT) {
			traceit("Reached max number of requests to receive dvap name\n");
			return false;
		}
	} while (reply != RT_NAME);

	if (0x10u!=dvapreg.header || 0x1u!=dvapreg.param.control || strncmp(dvapreg.param.sstr, "DVAP Dongle", 11)) {
		traceit("Failed to receive dvap name, got %s\n", dvapreg.param.sstr);
		return false;
	}

	traceit("Device name: %.*s\n", 11, dvapreg.param.sstr);
	return true;
}

bool CDVAPDongle::get_fw()
{
	unsigned cnt = 0;
	REPLY_TYPE reply;
	dvapreg.header = 0x2005u;
	dvapreg.param.control = 0x4u;
	dvapreg.param.ustr[0] = 0x1u;

	int rc = write_to_dvp(&dvapreg, 5);
	if (rc != 5) {
		traceit("Failed to send request to get dvap fw\n");
		return false;
	}

	do {
		usleep(5000);

		reply = GetReply(dvapreg);
		cnt ++;
		if (cnt >= MAX_REPL_CNT) {
			traceit("Reached max number of requests to receive dvap fw\n");
			return false;
		}
	} while (reply != RT_FW);

	unsigned int ver = dvapreg.param.ustr[1] + 256 * dvapreg.param.ustr[2];
	traceit("dvap fw ver: %u.%u\n", ver / 100, ver % 100);

	return true;
}

bool CDVAPDongle::set_modu()
{
	unsigned cnt = 0;
	REPLY_TYPE reply;
	dvapreg.header = 0x5u;
	dvapreg.param.control = 0x28u;
	dvapreg.param.ustr[0] = 0x1u;

	int rc = write_to_dvp(&dvapreg, 5);
	if (rc != 5) {
		traceit("Failed to send request to set dvap modulation\n");
		return false;
	}

	do {
		usleep(5000);

		reply = GetReply(dvapreg);

		cnt ++;
		if (cnt >= MAX_REPL_CNT) {
			traceit("Reached max number of requests to set dvap modulation\n");
			return false;
		}
	} while (reply != RT_MODU);

	return true;
}

bool CDVAPDongle::set_mode()
{
	unsigned cnt = 0;
	REPLY_TYPE reply;
	dvapreg.header = 0x5u;
	dvapreg.param.control = 0x2au;
	dvapreg.param.ustr[0] = 0x0u;

	int rc = write_to_dvp(&dvapreg, 5);
	if (rc != 5) {
		traceit("Failed to send request to set dvap mode\n");
		return false;
	}

	do {
		usleep(5000);

		reply = GetReply(dvapreg);

		cnt ++;
		if (cnt >= MAX_REPL_CNT) {
			traceit("Reached max number of requests to set dvap mode\n");
			return false;
		}
	} while (reply != RT_MODE);

	return true;
}

bool CDVAPDongle::set_sql(int squelch)
{
	unsigned cnt = 0;
	REPLY_TYPE reply;

	dvapreg.header = 0x5u;
	dvapreg.param.control = 0x80u;
	if (squelch < -128) {
		traceit("Squelch setting of %d too small, resetting...\n", squelch);
		squelch = -128;
	} else if (squelch > -45) {
		traceit("Squelch setting of %d too large, resetting...\n", squelch);
		squelch = -45;
	}
	dvapreg.param.byte = (int8_t)squelch;

	int rc = write_to_dvp(&dvapreg, 5);
	if (rc != 5) {
		traceit("Failed to send request to set dvap sql\n");
		return false;
	}

	do {
		usleep(5000);

		reply = GetReply(dvapreg);

		cnt ++;
		if (cnt >= MAX_REPL_CNT) {
			traceit("Reached max number of requests to set dvap sql\n");
			return false;
		}
	} while (reply != RT_SQL);
	traceit("DVAP squelch is %d dB\n", (int)dvapreg.param.byte);
	return true;
}

bool CDVAPDongle::set_pwr(int power)
{
	unsigned cnt = 0;
	REPLY_TYPE reply;

	dvapreg.header = 0x6u;
	dvapreg.param.control = 0x138u;
	if (power < -12) {
		traceit("Power setting of %d is too low, resetting...\n", power);
		power = -12;
	} else if (power > 10) {
		traceit("Power setting of %d is too high, resetting...\n", power);
		power = 10;
	}
	dvapreg.param.word = (int16_t)power;

	int rc = write_to_dvp(&dvapreg, 6);
	if (rc != 6) {
		traceit("Failed to send request to set dvap pwr\n");
		return false;
	}

	do {
		usleep(5000);

		reply = GetReply(dvapreg);

		cnt ++;
		if (cnt >= MAX_REPL_CNT) {
			traceit("Reached max number of requests to set dvap pwr\n");
			return false;
		}
	} while (reply != RT_PWR);
	traceit("DVAP power is %d dB\n", (int)dvapreg.param.word);
	return true;
}

bool CDVAPDongle::set_off(int offset)
{
	unsigned cnt = 0;
	REPLY_TYPE reply;

	dvapreg.header = 0x6u;
	dvapreg.param.control = 0x400u;
	if (offset < -2000) {
		traceit("Offset of %d is too low, resetting...\n", offset);
		offset = -2000;
	} else if (offset > 2000) {
		traceit("Offset of %d is too high, resetting...\n", offset);
		offset = 2000;
	}
	dvapreg.param.word = (int16_t)offset;

	int rc = write_to_dvp(&dvapreg, 6);
	if (rc != 6) {
		traceit("Failed to send request to set dvap offset\n");
		return false;
	}

	do {
		usleep(5000);

		reply = GetReply(dvapreg);

		cnt ++;
		if (cnt >= MAX_REPL_CNT) {
			traceit("Reached max number of requests to set dvap offset\n");
			return false;
		}
	} while (reply != RT_OFF);
	traceit("DVAP offset is %d Hz\n", (int)dvapreg.param.word);
	return true;
}

bool CDVAPDongle::set_freq(int frequency)
{
	unsigned cnt = 0;
	REPLY_TYPE reply;

	// first get the frequency limits
	dvapreg.header = 0x2004u;
	dvapreg.param.control = 0x230u;

	int rc = write_to_dvp(&dvapreg, 4);
	if (rc != 4) {
		traceit("Failed to send request for frequency limits\n");
		return false;
	}

	do {
		usleep(5000);

		reply = GetReply(dvapreg);

		cnt++;
		if (cnt >= MAX_REPL_CNT) {
			traceit("Reached max number of requests for dvap frequency limits\n");
			return false;
		}
	} while (reply != RT_FREQ_LIMIT);
	traceit("DVAP Frequency limits are from %d to %d Hz\n", dvapreg.param.twod[0], dvapreg.param.twod[1]);

	// okay, now we know the frequency limits, get on with the show...
	if (frequency < dvapreg.param.twod[0]) {
		traceit("Frequency of %d is too small, resetting...\n", frequency);
		frequency = dvapreg.param.twod[0];
	} else if (frequency > dvapreg.param.twod[1]) {
		traceit("Frequency of %d is too large, resetting...\n", frequency);
		frequency = dvapreg.param.twod[1];
	}

	cnt = 0;
	dvapreg.header = 0x8u;
	dvapreg.param.control = 0x220u;
	dvapreg.param.dword = frequency;

	rc = write_to_dvp(&dvapreg, 8);
	if (rc != 8) {
		traceit("Failed to send request to set dvap frequency\n");
		return false;
	}

	do {
		usleep(5000);

		reply = GetReply(dvapreg);

		cnt ++;
		if (cnt >= MAX_REPL_CNT) {
			traceit("Reached max number of requests to set dvap frequency\n");
			return false;
		}
	} while (reply != RT_FREQ);
	traceit("DVAP frequency is %d Hz\n", dvapreg.param.dword);
	return true;
}

bool CDVAPDongle::start_dvap()
{
	unsigned cnt = 0;
	REPLY_TYPE reply;

	dvapreg.header = 0x5u;
	dvapreg.param.control = 0x18u;
	dvapreg.param.byte = 0x1;

	int rc = write_to_dvp(&dvapreg, 5);
	if (rc != 5) {
		traceit("Failed to send request to start the dvap dongle\n");
		return false;
	}

	do {
		usleep(5000);

		reply = GetReply(dvapreg);

		cnt ++;
		if (cnt >= MAX_REPL_CNT) {
			traceit("Reached max number of requests to start the dvap dongle\n");
			return false;
		}
	} while (reply != RT_START);

	return true;
}

void CDVAPDongle::SendRegister(SDVAP_REGISTER &dr)
{
	unsigned int len = dr.header & 0x1fff;
	write_to_dvp(&dr, len);
	return;
}

int CDVAPDongle::write_to_dvp(const void *buffer, const unsigned int len)
{
	unsigned int ptr = 0;

	if (len == 0)
		return 0;

	uint8_t *buf = (uint8_t *)buffer;
	while (ptr < len) {
		ssize_t n = write(serfd, buf + ptr, len - ptr);
		if (n < 0) {
			traceit("Error %d writing to dvap, message=%s\n", errno, strerror(errno));
			return -1;
		}

		if (n > 0)
			ptr += n;
	}

	return len;
}

int CDVAPDongle::read_from_dvp(void *buffer, unsigned int len)
{
	unsigned int off = 0;
	fd_set fds;
	int n;
	struct timeval tv;
	ssize_t temp_len;
	uint8_t *buf = (uint8_t *)buffer;

	if (len == 0)
		return 0;

	while (off < len) {
		FD_ZERO(&fds);
		FD_SET(serfd, &fds);

		if (off == 0) {
			tv.tv_sec  = 0;
			tv.tv_usec = 0;
			n = select(serfd + 1, &fds, NULL, NULL, &tv);
			if (n == 0)
				return 0; // nothing to read from the dvap
		} else
			n = select(serfd + 1, &fds, NULL, NULL, NULL);

		if (n < 0) {
			traceit("select error=%d on dvap\n", errno);
			return -1;
		}

		if (n > 0) {
			temp_len = read(serfd, buf + off, len - off);
			if (temp_len > 0)
				off += temp_len;
		}
	}

	return len;
}

bool CDVAPDongle::OpenSerial(char *device)
{
	static termios t;

	serfd = open(device, O_RDWR | O_NOCTTY | O_NDELAY, 0);
	if (serfd < 0) {
		traceit("Failed to open device [%s], error=%d, message=%s\n", device, errno, strerror(errno));
		return false;
	}

	if (isatty(serfd) == 0) {
		traceit("Device %s is not a tty device\n", device);
		close(serfd);
		serfd = -1;
		return false;
	}

	if (tcgetattr(serfd, &t) < 0) {
		traceit("tcgetattr failed for %s, error=%d, message-%s\n", device, errno, strerror(errno));
		close(serfd);
		serfd = -1;
		return false;
	}

	t.c_lflag    &= ~(ECHO | ECHOE | ICANON | IEXTEN | ISIG);
	t.c_iflag    &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON | IXOFF | IXANY);
	t.c_cflag    &= ~(CSIZE | CSTOPB | PARENB | CRTSCTS);
	t.c_cflag    |= CS8;
	t.c_oflag    &= ~(OPOST);
	t.c_cc[VMIN]  = 0;
	t.c_cc[VTIME] = 10;

	cfsetospeed(&t, B230400);
	cfsetispeed(&t, B230400);

	if (tcsetattr(serfd, TCSANOW, &t) < 0) {
		traceit("tcsetattr failed for %s, error=%dm message=%s\n", device, errno, strerror(errno));
		close(serfd);
		serfd = -1;
		return false;
	}

	return true;
}

void CDVAPDongle::Stop()
{
	SDVAP_REGISTER dvap;
	dvap.header = 0x5u;
	dvap.param.control = 0x18u;
	dvap.param.byte = 0;
	write_to_dvp(&dvap, 5);
	return;
}

int CDVAPDongle::KeepAlive()
{
	SDVAP_REGISTER dvap;
	dvap.header = 0x6003u;
	dvap.nul = 0x0u;
	return write_to_dvp(&dvap, 3);
}
