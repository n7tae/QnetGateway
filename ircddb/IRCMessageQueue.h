#pragma once

#include <mutex>

#include "IRCMessage.h"


class IRCMessageQueueItem
{
public:
	IRCMessageQueueItem( IRCMessage * m ) {
		msg = m;
	}

	~IRCMessageQueueItem() {
	}

	IRCMessage * msg;

	IRCMessageQueueItem * prev;
	IRCMessageQueueItem * next;
};


class IRCMessageQueue
{
public:
	IRCMessageQueue();

	~IRCMessageQueue();

	bool isEOF();

	void signalEOF();

	bool messageAvailable();

	IRCMessage * getMessage();

	IRCMessage * peekFirst();

	void putMessage ( IRCMessage * m );

private:

	bool eof;

	IRCMessageQueueItem * first;
	IRCMessageQueueItem * last;

	std::mutex accessMutex;

};
