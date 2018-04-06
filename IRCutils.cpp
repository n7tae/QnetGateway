#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdarg>
#include <ctime>
#include <string>
#include <vector>
#include <iostream>
#include <istream>
#include <ostream>
#include <iterator>
#include <sstream>
#include <algorithm>

#include "IRCutils.h"
// not needed, defined in /usr/include/features.h
//#define _XOPEN_SOURCE

time_t parseTime(const std::string str)
{
	struct tm stm;
	strptime(str.c_str(), "%Y-%m-%d %H:%M:%S", &stm);
	return mktime(&stm);
}

std::vector<std::string> stringTokenizer(const std::string &s)
{
        std::stringstream ss(s);
        std::istream_iterator<std::string> it(ss);
        std::istream_iterator<std::string> end;
        std::vector<std::string> result(it, end);
        return result;
}

int getAllIPV4Addresses(const char * name, unsigned short port, unsigned int * num, struct sockaddr_in * addr, unsigned int max_addr)
{

	struct addrinfo hints;
	struct addrinfo * res;

	memset(&hints, 0x00, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	int r = getaddrinfo(name, NULL, &hints, &res);

	if (r == 0) {
		struct addrinfo * rp;
		unsigned int numAddr = 0;

		for (rp = res; rp != NULL; rp = rp->ai_next) {
			if (rp->ai_family == AF_INET)
				numAddr ++;
		}

		if (numAddr > 0) {
			if (numAddr > max_addr)
				numAddr = max_addr;

			int * shuffle = new int[numAddr];

			unsigned int i;

			for (i=0; i < numAddr; i++)
				shuffle[i] = i;

			for (i=0; i < (numAddr - 1); i++) {
				if (rand() & 1) {
					int tmp;
					tmp = shuffle[i];
					shuffle[i] = shuffle[i+1];
					shuffle[i+1] = tmp;
				}
			}

			for (i=(numAddr - 1); i > 0; i--) {
				if (rand() & 1) {
					int tmp;
					tmp = shuffle[i];
					shuffle[i] = shuffle[i-1];
					shuffle[i-1] = tmp;
				}
			}

			for (rp = res, i=0 ; (rp != NULL) && (i < numAddr); rp = rp->ai_next) {
				if (rp->ai_family == AF_INET) {
					memcpy( addr+shuffle[i], rp->ai_addr, sizeof (struct sockaddr_in) );

					addr[shuffle[i]].sin_port = htons(port);

					i++;
				}
			}

			delete[] shuffle;
		}

		*num = numAddr;

		freeaddrinfo(res);

		return 0;

	} else {
		printf("getaddrinfo: %s\n", gai_strerror(r));

		return 1;
	}


}

void safeStringCopy (char *dest, const char *src, unsigned int buf_size)
{
	unsigned int i = 0;

	while (i<(buf_size - 1)  &&  src[i] != 0) {
		dest[i] = src[i];
		i++;
	}

	dest[i] = 0;
}

char *getCurrentTime(void)
{
	time_t now = time(NULL);
	struct tm* tm;
	struct tm tm_buf;
	static char buffer[25];

	gmtime_r(&now, &tm_buf);
	tm = &tm_buf;

	strftime(buffer, sizeof buffer, "%Y-%m-%d %H:%M:%S", tm);

	return buffer;
}

void ToUpper(std::string &str)
{
	for (auto it=str.begin(); it!=str.end(); it++) {
		if (islower(*it))
			*it = toupper(*it);
	}
}

void ToLower(std::string &str)
{
	for (auto it=str.begin(); it!=str.end(); it++) {
		if (isupper(*it))
			*it = tolower(*it);
	}
}


void ReplaceChar(std::string &str, char from, char to)
{
	for (auto it=str.begin(); it!=str.end(); it++) {
		if (from == *it)
			*it = to;
	}
}
