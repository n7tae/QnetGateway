#pragma once

#include <future>

#include "IRCReceiver.h"
#include "IRCMessageQueue.h"
#include "IRCProtocol.h"
#include "IRCApplication.h"

class IRCClient
{
public:
	IRCClient(IRCApplication *app, const std::string &update_channel, const std::string &hostName, unsigned int port, const std::string &callsign, const std::string &password,
	           const std::string &versionInfo, const std::string &localAddr);

	virtual ~IRCClient();
	bool startWork();
	void stopWork();

protected:
	virtual void Entry();

private:
	char host_name[100];
	char local_addr[100];
	unsigned int port;
	std::string callsign;
	std::string password;

	bool terminateThread;

	IRCReceiver *recv;
	IRCMessageQueue *recvQ;
	IRCMessageQueue *sendQ;
	IRCProtocol *proto;
    std::future<void> client_thread;
	IRCApplication *app;

};
