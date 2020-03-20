#pragma once

#include <string>
#include <future>
#include <map>
#include <mutex>
#include <regex>

#include "IRCDDB.h"
#include "IRCMessageQueue.h"

class IRCDDBAppGateObject
{
public:

	std::string nick;
	std::string name;
	std::string host;
	bool op;
	unsigned int usn;

	IRCDDBAppGateObject() {}

	IRCDDBAppGateObject(const std::string &n, const std::string &nm, const std::string &h) {
		nick = n;
		name = nm;
		host = h;
		op = false;
		usn = counter;
		counter++;
	}
	static unsigned int counter;
};

class IRCDDBAppRptrObject
{
public:

	std::string arearp_cs;
	time_t lastChanged;
	std::string zonerp_cs;

	IRCDDBAppRptrObject() {
	}

	IRCDDBAppRptrObject(time_t dt, std::string &repeaterCallsign, std::string &gatewayCallsign) {
		arearp_cs = repeaterCallsign;
		lastChanged = dt;
		zonerp_cs = gatewayCallsign;

		if (dt > maxTime) {
			maxTime = dt;
		}
	}

	static time_t maxTime;
};

class IRCDDBApp
{
public:
	IRCDDBApp(const std::string &update_channel, CCacheManager *cache);
	~IRCDDBApp();

	void userJoin(const std::string &nick, const std::string &name, const std::string &host);

	void userLeave(const std::string &nick);

	void userChanOp(const std::string &nick, bool op);
	void userListReset();

	void msgChannel(IRCMessage *m);
	void msgQuery(IRCMessage *m);

	void setCurrentNick(const std::string &nick);
	void setTopic(const std::string &topic);

	void setBestServer(const std::string &ircUser);

	void setSendQ(IRCMessageQueue *s);
	IRCMessageQueue *getSendQ();

	void putReplyMessage(IRCMessage *m);
	void sendPing(const std::string &to, const std::string &from);

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
	void Entry();

private:
	void doUpdate(std::string &msg);
	void doNotFound(std::string &msg, std::string &retval);
	std::string getIPAddress(std::string &zonerp_cs);
	bool findServerUser();
	std::future<void> worker_thread;
	IRCMessageQueue *sendQ;
	IRCMessageQueue replyQ;
	CCacheManager *cache;

	std::map<std::string, IRCDDBAppGateObject> user;
	std::mutex userMapMutex;
	std::map<std::string, IRCDDBAppRptrObject> rptrMap;
	std::mutex rptrMapMutex;
	std::map<std::string, std::string> moduleMap;
	std::mutex moduleMapMutex;
	std::map<std::string, std::string> locationMap;
	std::mutex locationMapMutex;
	std::map<std::string, std::string> urlMap;
	std::mutex urlMapMutex;
	std::map<std::string, std::string> swMap;
	std::mutex swMapMutex;

	std::string currentServer;
	std::string myNick;

	std::regex tablePattern, datePattern, timePattern, dbPattern, modulePattern;

	int state;
	int timer;
	int infoTimer;
	int wdTimer;

	std::string updateChannel;
	std::string channelTopic;
	std::string bestServer;
	std::string wdInfo;

	bool initReady;
	bool terminateThread;
};
