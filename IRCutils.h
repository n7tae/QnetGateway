#pragma once

#include <string>
#include <vector>
#include <ctime>

time_t parseTime(const std::string str);

std::vector<std::string> stringTokenizer(const std::string &str);

int getAllIPV4Addresses(const char *name, unsigned short port, unsigned int *num, struct sockaddr_in *addr, unsigned int max_addr);

void safeStringCopy (char * dest, const char * src, unsigned int buf_size);

char *getCurrentTime(void);

void traceit(const char *fmt,...);

void ToUpper(std::string &str);

void ToLower(std::string &str);

void ReplaceChar(std::string &str, char from, char to);
