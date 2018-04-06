#include "IRCMessageQueue.h"


IRCMessageQueue::IRCMessageQueue()
{
	eof = false;
	first = NULL;
	last = NULL;

}

IRCMessageQueue::~IRCMessageQueue()
{
	while (messageAvailable()) {
		IRCMessage * m = getMessage();

		delete m;
	}
}


bool IRCMessageQueue::isEOF()
{
	return eof;
}


void IRCMessageQueue::signalEOF()
{
	eof = true;
}


bool IRCMessageQueue::messageAvailable()
{
	accessMutex.lock();

	IRCMessageQueueItem *m = first;

	accessMutex.unlock();

	return (m != NULL);
}


IRCMessage * IRCMessageQueue::peekFirst()
{
	accessMutex.lock();

	IRCMessageQueueItem * k = first;

	accessMutex.unlock();

	if ( k == NULL ) {
		return NULL;
	}

	return k->msg;
}


IRCMessage * IRCMessageQueue::getMessage()
{
	accessMutex.lock();

	IRCMessageQueueItem * k;

	if (first == NULL) {
		return NULL;
	}

	k = first;

	first = k -> next;

	if (k -> next == NULL) {
		last = NULL;
	} else {
		k -> next -> prev = NULL;
	}


	IRCMessage * msg = k -> msg;

	delete k;

	accessMutex.unlock();

	return msg;
}


void IRCMessageQueue::putMessage( IRCMessage * m )
{
	accessMutex.lock();

	//printf("IRCMessageQueue::putMessage\n");

	IRCMessageQueueItem * k = new IRCMessageQueueItem(m);

	k -> prev = last;
	k -> next = NULL;

	if (last == NULL) {
		first = k;
	} else {
		last -> next = k;
	}

	last = k;

	accessMutex.unlock();
}

