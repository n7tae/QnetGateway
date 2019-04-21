#pragma once

#include <string>
#include <future>

#include "IRCDDB.h"
#include "IRCApplication.h"

class IRCDDBAppPrivate;

class IRCDDBApp : public IRCApplication
{
public:
	IRCDDBApp(const std::string &update_channel);

	virtual ~IRCDDBApp();

	virtual void userJoin(const std::string &nick, const std::string &name, const std::string &host);

	virtual void userLeave(const std::string &nick);

	virtual void userChanOp(const std::string &nick, bool op);
	virtual void userListReset();

	virtual void msgChannel(IRCMessage *m);
	virtual void msgQuery(IRCMessage *m);

	virtual void setCurrentNick(const std::string &nick);
	virtual void setTopic(const std::string &topic);

	virtual void setBestServer(const std::string &ircUser);

	virtual void setSendQ(IRCMessageQueue *s);
	virtual IRCMessageQueue *getSendQ();

	virtual void putReplyMessage(IRCMessage *m);
	virtual void sendPing(const std::string &to, const std::string &from);

	bool startWork();
	void stopWork();

	IRCDDB_RESPONSE_TYPE getReplyMessageType();

	IRCMessage *getReplyMessage();

	bool findUser(const std::string &s);
	bool findRepeater(const std::string &s);
	bool findGateway(const std::string &s);

	bool sendHeard(const std::string &myCall, const std::string &myCallExt, const std::string &yourCall, const std::string &rpt1, const std::string &rpt2, unsigned char flag1, unsigned char flag2, unsigned char flag3, const std::string &destination, const std::string &tx_msg, const std::string &tx_stats);

	int getConnectionState();

	void rptrQRG(const std::string &rptrcall, double txFrequency, double duplexShift, double range, double agl);

	void rptrQTH(const std::string &rtprcall, double latitude, double longitude, const std::string &desc1, const std::string &desc2, const std::string &infoURL, const std::string &swVersion);

	void kickWatchdog(const std::string &wdInfo);

protected:
	virtual void Entry();

private:
	void doUpdate(std::string &msg);
	void doNotFound(std::string &msg, std::string &retval);
	std::string getIPAddress(std::string &zonerp_cs);
	bool findServerUser();
	IRCDDBAppPrivate *d;
	std::future<void> worker_thread;
};
