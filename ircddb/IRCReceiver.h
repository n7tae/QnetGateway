#pragma once
#include <future>
#include "IRCMessageQueue.h"
#include "../TCPReaderWriterClient.h"

class IRCReceiver
{
public:
	IRCReceiver(CTCPReaderWriterClient *ircSock, IRCMessageQueue *q);
	virtual ~IRCReceiver();
	bool startWork();
	void stopWork();

protected:
	virtual void Entry();

private:
	CTCPReaderWriterClient *ircSock;
	bool terminateThread;
	int sock;
	IRCMessageQueue *recvQ;
    std::future<void> rec_thread;
};
