#pragma once

#include <string>
#include "IRCMessageQueue.h"

class IRCApplication
{
public:

	virtual void userJoin(const std::string& nick, const std::string& name, const std::string& host) = 0;
	virtual void userLeave(const std::string& nick) = 0;
	virtual void userChanOp(const std::string& nick, bool op) = 0;
	virtual void userListReset(void) = 0;

	virtual void msgChannel(IRCMessage * m) = 0;
	virtual void msgQuery(IRCMessage * m) = 0;

	virtual void setCurrentNick(const std::string& nick) = 0;
	virtual void setTopic(const std::string& topic) = 0;

	virtual void setBestServer(const std::string& ircUser) = 0;

	virtual void setSendQ(IRCMessageQueue *s) = 0;
	virtual IRCMessageQueue *getSendQ(void) = 0;

	virtual void putReplyMessage(IRCMessage *m) = 0;
	virtual void sendPing(const std::string &to, const std::string &from) = 0;

	virtual ~IRCApplication() {}

};
