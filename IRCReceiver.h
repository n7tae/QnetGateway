#pragma once
#include <future>
#include "IRCMessageQueue.h"

class IRCReceiver
{
public:
	IRCReceiver(int sock, IRCMessageQueue *q);
	virtual ~IRCReceiver();
	bool startWork();
	void stopWork();

protected:
	virtual void Entry();

private:
	bool terminateThread;
	int sock;
	IRCMessageQueue *recvQ;
    std::future<void> rec_thread;
};
