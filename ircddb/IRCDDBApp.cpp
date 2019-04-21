#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <mutex>
#include <map>
#include <string>
#include <regex>

#include "IRCDDBApp.h"
#include "IRCutils.h"

class IRCDDBAppUserObject
{
public:

	std::string nick;
	std::string name;
	std::string host;
	bool op;
	unsigned int usn;

	IRCDDBAppUserObject() {}

	IRCDDBAppUserObject(const std::string &n, const std::string &nm, const std::string &h) {
		nick = n;
		name = nm;
		host = h;
		op = false;
		usn = counter;
		counter++;
	}
	static unsigned int counter;
};

unsigned int IRCDDBAppUserObject::counter = 0;

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

time_t IRCDDBAppRptrObject::maxTime((time_t)950000000);  // February 2000

class IRCDDBAppPrivate
{
public:
	IRCDDBAppPrivate()
	{
		wdTimer = -1;
	}

	IRCMessageQueue *sendQ;
	IRCMessageQueue replyQ;

	std::map<std::string, IRCDDBAppUserObject> user;
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

IRCDDBApp::IRCDDBApp(const std::string &u_chan)
	: d(new IRCDDBAppPrivate)
{

	d->sendQ = NULL;
	d->initReady = false;

	userListReset();

	d->state = 0;
	d->timer = 0;
	d->myNick = "none";

	d->updateChannel = u_chan;

	d->terminateThread = false;
	d->tablePattern  = std::regex("^[0-9]$");
	d->datePattern   = std::regex("^20[0-9][0-9]-((1[0-2])|(0[1-9]))-((3[01])|([12][0-9])|(0[1-9]))$");
	d->timePattern   = std::regex("^((2[0-3])|([01][0-9])):[0-5][0-9]:[0-5][0-9]$");
	d->dbPattern     = std::regex("^[0-9A-Z_]{8}$");
	d->modulePattern = std::regex("^.*[ABCD]D?$");
}

IRCDDBApp::~IRCDDBApp()
{
	if (d->sendQ != NULL) {
		delete d->sendQ;
	}
	delete d;
}

void IRCDDBApp::rptrQTH(const std::string &rptrcall, double latitude, double longitude, const std::string &desc1, const std::string &desc2, const std::string &infoURL, const std::string &swVersion)
{
	char pos[32];
	snprintf(pos, 32, "%+09.5f %+010.5f", latitude, longitude);

	std::string d1 = desc1;
	std::string d2 = desc2;
	std::string rcall = rptrcall;

	d1.resize(20, '_');
	d2.resize(20, '_');

	std::regex nonValid("[^a-zA-Z0-9 +&(),./'-_]+");

	std::smatch sm;
	while (std::regex_search(d1, sm, nonValid))
		d1.erase(sm.position(0), sm.length());
	while (std::regex_search(d2, sm, nonValid))
		d2.erase(sm.position(0), sm.length());

	ReplaceChar(d1, ' ', '_');
	ReplaceChar(d2, ' ', '_');
	ReplaceChar(rcall, ' ', '_');
	std::string aspace(" ");
	std::string f = rcall + aspace + std::string(pos) + aspace + d1 + aspace + d2;

	d->locationMapMutex.lock();
	d->locationMap[rptrcall] = f;
	d->locationMapMutex.unlock();

	printf("IRCDDB RPTRQTH: %s\n", f.c_str());

	std::regex urlNonValid("[^[:graph:]]+");

	std::string url = infoURL;
	while (std::regex_search(url, sm, nonValid))
		url.erase(sm.position(0), sm.length());

	std::string g = rcall + aspace + url;

	d->urlMapMutex.lock();
	d->urlMap[rptrcall] = g;
	d->urlMapMutex.unlock();

	printf("IRCDDB RPTRURL: %s\n", g.c_str());

	std::string sw = swVersion;
	while (std::regex_search(sw, sm, nonValid))
		sw.erase(sm.position(0), sm.length());

	std::string h = rcall + std::string(" ") + sw;
	d->swMapMutex.lock();
	d->swMap[rptrcall] = h;
	d->swMapMutex.unlock();

	printf("IRCDDB RPTRSW: %s\n", h.c_str());

	d->infoTimer = 5; // send info in 5 seconds
}

void IRCDDBApp::rptrQRG(const std::string &rptrcall, double txFrequency, double duplexShift, double range, double agl)
{

	if (std::regex_match(rptrcall, d->modulePattern)) {

		std::string c = rptrcall;
		ReplaceChar(c, ' ', '_');

		char f[48];
		snprintf(f, 48, "%011.5f %+010.5f %06.2f %06.1f", txFrequency, duplexShift, range / 1609.344, agl);
		std::string g = c + std::string(" ") + f;

		d->moduleMapMutex.lock();
		d->moduleMap[rptrcall] = g;
		d->moduleMapMutex.unlock();

		printf("IRCDDB RPTRQRG: %s\n", g.c_str());

		d->infoTimer = 5; // send info in 5 seconds
	}
}

void IRCDDBApp::kickWatchdog(const std::string &s)
{
	if (s.length() > 0) {

		std::regex nonValid("[^[:graph:]]+");
		std::smatch sm;
		std::string u = s;
		while (std::regex_search(u, sm, nonValid))
			u.erase(sm.position(0), sm.length());
		d->wdInfo = u;

		if (u.length() > 0)
			d->wdTimer = 1;
	}
}

int IRCDDBApp::getConnectionState()
{
	return d->state;
}

IRCDDB_RESPONSE_TYPE IRCDDBApp::getReplyMessageType()
{
	IRCMessage * m = d->replyQ.peekFirst();
	if (m == NULL) {
		return IDRT_NONE;
	}

	std::string msgType = m->getCommand();

	if (msgType == std::string("IDRT_USER")) {
		return IDRT_USER;
	} else if (msgType == std::string("IDRT_REPEATER")) {
		return IDRT_REPEATER;
	} else if (msgType == std::string("IDRT_GATEWAY")) {
		return IDRT_GATEWAY;
	} else if (msgType == std::string("IDRT_PING")) {
		return IDRT_PING;
	}

	printf("IRCDDBApp::getMessageType: unknown msg type: %s\n", msgType.c_str());

	return IDRT_NONE;
}

IRCMessage *IRCDDBApp::getReplyMessage()
{
	return d->replyQ.getMessage();
}

void IRCDDBApp::putReplyMessage(IRCMessage *m)
{
	d->replyQ.putMessage(m);
}

bool IRCDDBApp::startWork()
{
	d->terminateThread = false;
	worker_thread = std::async(std::launch::async, &IRCDDBApp::Entry, this);
	return true;
}

void IRCDDBApp::stopWork()
{
	d->terminateThread = true;
	worker_thread.get();
}

void IRCDDBApp::userJoin(const std::string &nick, const std::string &name, const std::string &host)
{
	std::string lnick = nick;
	ToLower(lnick);

	IRCDDBAppUserObject u(lnick, name, host);

	d->userMapMutex.lock();
	d->user[lnick] = u;
	d->userMapMutex.unlock();

	//printf("add %d: (%s) (%s)\n", d->user.size(), nick.c_str(), host.c_str());

	if (d->initReady) {
		unsigned hyphenPos = nick.find('-');

		if ((hyphenPos >= 4) && (hyphenPos <= 6)) {
			std::string gatewayCallsign = nick.substr(0, hyphenPos);
			ToUpper(gatewayCallsign);
			gatewayCallsign.resize(7, '_');
			gatewayCallsign.push_back('G');

			IRCMessage *m2 = new IRCMessage("IDRT_GATEWAY");
			m2->addParam(gatewayCallsign);
			m2->addParam(host);
			d->replyQ.putMessage(m2);
		}
	}
	//printf("user %d\n", u.usn);
}

void IRCDDBApp::userLeave(const std::string &nick)
{
	std::string lnick = nick;
	ToLower(lnick);

	d->userMapMutex.lock();
	d->user.erase(lnick);
	d->userMapMutex.unlock();

	// printf("rm %d: %s\n" d->user.size(), nick.c_str());

	if (d->currentServer.length() > 0) {
		if (d->user.count(d->myNick) != 1) {
			printf("IRCDDBApp::userLeave: could not find own nick\n");
			return;
		}

		IRCDDBAppUserObject me = d->user[d->myNick];

		if (me.op == false) {
			// if I am not op, then look for new server

			if (d->currentServer == lnick) {
				// currentServer = null;
				d->state = 2;  // choose new server
				d->timer = 200;
				d->initReady = false;
			}
		}
	}
}

void IRCDDBApp::userListReset()
{
	d->userMapMutex.lock();
	d->user.clear();
	d->userMapMutex.unlock();
}

void IRCDDBApp::setCurrentNick(const std::string &nick)
{
	d->myNick = nick;
	printf("IRCDDBApp::setCurrentNick %s\n", nick.c_str());
}

void IRCDDBApp::setBestServer(const std::string &ircUser)
{
	d->bestServer = ircUser;
	printf("IRCDDBApp::setBestServer %s\n", ircUser.c_str());
}

void IRCDDBApp::setTopic(const std::string &topic)
{
	d->channelTopic = topic;
}

bool IRCDDBApp::findServerUser()
{
	d->userMapMutex.lock();

	bool found = false;

	std::map<std::string, IRCDDBAppUserObject>::iterator it;

	for (it=d->user.begin(); it!=d->user.end(); ++it) {
		IRCDDBAppUserObject u = it->second;
		if (0==u.nick.compare(0, 2, "s-") && u.op && d->myNick.compare(u.nick) && 0==u.nick.compare(d->bestServer)) {
			d->currentServer = u.nick;
			found = true;
			break;
		}
	}

	if (found) {
		d->userMapMutex.unlock();
		return true;
	}

	if (d->bestServer.length() == 8) {
		for(it=d->user.begin(); it!=d->user.end(); ++it) {
			IRCDDBAppUserObject u = it->second;
			if (0==u.nick.compare(0, 7, d->bestServer) && u.op && d->myNick.compare(u.nick) ) {
				d->currentServer = u.nick;
				found = true;
				break;
			}
		}
	}

	if (found) {
		d->userMapMutex.unlock();
		return true;
	}

	for(it = d->user.begin(); it != d->user.end(); ++it) {
		IRCDDBAppUserObject u = it->second;
		if (0==u.nick.compare(0, 2, "s-") && u.op && d->myNick.compare(u.nick)) {
			d->currentServer = u.nick;
			found = true;
			break;
		}
	}

	d->userMapMutex.unlock();
	return found;
}

void IRCDDBApp::userChanOp(const std::string &nick, bool op)
{
	std::string lnick = nick;
	ToLower(lnick);

	d->userMapMutex.lock();
	if (d->user.count(lnick) == 1) {
		d->user[lnick].op = op;
	}
	d->userMapMutex.unlock();
}

void IRCDDBApp::sendPing(const std::string &to, const std::string &from)
{
	std::string t = to.substr(0, 7);

	ReplaceChar(t, '_', ' ');
	while (isspace(t[t.length()-1]))
		t.pop_back();
	ToLower(t);

	d->userMapMutex.lock();
	for (int j=1; j <= 4; j++) {
		std::string ircUser = t + std::string("-") + std::to_string(j);

		if (1 == d->user.count(ircUser)) {
			std::string f(from);
			ReplaceChar(f, ' ', '_');
			IRCMessage *rm = new IRCMessage(ircUser, "IDRT_PING");
			rm->addParam(f);
			std::string out;
			rm->composeMessage(out);
			out.pop_back();
			out.pop_back();
			printf("IRCDDBApp::sendPing: %s\n", out.c_str());
			d->sendQ->putMessage(rm);
			break;
		}
	}
	d->userMapMutex.unlock();

}

static const int numberOfTables = 2;

std::string IRCDDBApp::getIPAddress(std::string &zonerp_cs)
{
	d->userMapMutex.lock();
	std::string gw = zonerp_cs;

	ReplaceChar(gw, '_', ' ');
	while (isspace(gw[gw.length()-1]))
		gw.pop_back();
	ToLower(gw);

	unsigned int max_usn = 0;
	std::string ipAddr;

	for (int j=1; j <= 4; j++) {
		std::string ircUser = gw + std::string("-") + std::to_string(j);

		if (d->user.count(ircUser) == 1) {
			IRCDDBAppUserObject o = d->user[ircUser];

			if (o.usn >= max_usn) {
				max_usn = o.usn;
				ipAddr = o.host;
			}
		}
		// printf("getIP %d (%s) (%s)\n", i, ircUser.c_str(), ipAddr.c_str());

	}
	d->userMapMutex.unlock();
	return ipAddr;
}

bool IRCDDBApp::findGateway(const std::string &gwCall)
{
	std::string s = gwCall.substr(0,6);
	IRCMessage *m2 = new IRCMessage("IDRT_GATEWAY");
	m2->addParam(gwCall);
	m2->addParam(getIPAddress(s));
	d->replyQ.putMessage(m2);

	return true;
}

bool IRCDDBApp::findRepeater(const std::string &rptrCall)
{
	std::string arearp_cs = rptrCall;
	ReplaceChar(arearp_cs, ' ', '_');

	std::string zonerp_cs;

	d->rptrMapMutex.lock();

	std::string s("NONE");

	if (d->rptrMap.count(arearp_cs) == 1) {
		IRCDDBAppRptrObject o = d->rptrMap[arearp_cs];
		zonerp_cs = o.zonerp_cs;
		ReplaceChar(zonerp_cs, '_', ' ');
		zonerp_cs[7] = 'G';
		s = o.zonerp_cs;
	}
	d->rptrMapMutex.unlock();

	IRCMessage *m2 = new IRCMessage("IDRT_REPEATER");
	m2->addParam(rptrCall);
	m2->addParam(zonerp_cs);
	m2->addParam(getIPAddress(s));
	d->replyQ.putMessage(m2);
	return true;
}

bool IRCDDBApp::sendHeard(const std::string &myCall,
                          const std::string &myCallExt,
                          const std::string &yourCall,
                          const std::string &rpt1,
                          const std::string &rpt2,
                          unsigned char flag1,
                          unsigned char flag2,
                          unsigned char flag3,
                          const std::string &destination,
                          const std::string &tx_msg,
                          const std::string &tx_stats)
{

	std::string my = myCall;
	std::string myext = myCallExt;
	std::string ur = yourCall;
	std::string r1 = rpt1;
	std::string r2 = rpt2;
	std::string dest = destination;

	std::regex nonValid("[^A-Z0-9/_]");
	char underScore = '_';
	std::smatch sm;
	while (std::regex_search(my, sm, nonValid))
		my[sm.position(0)] = underScore;
	while (std::regex_search(myext, sm, nonValid))
		myext[sm.position(0)] = underScore;
	while (std::regex_search(ur, sm, nonValid))
		ur[sm.position(0)] = underScore;
	while (std::regex_search(r1, sm, nonValid))
		r1[sm.position(0)] = underScore;
	while (std::regex_search(r2, sm, nonValid))
		r2[sm.position(0)] = underScore;
	while (std::regex_search(dest, sm, nonValid))
		dest[sm.position(0)] = underScore;

	bool statsMsg = (tx_stats.length() > 0);

	std::string srv = d->currentServer;
	IRCMessageQueue *q = getSendQ();

	if ((srv.length() > 0) && (d->state >= 6) && (q != NULL)) {
		std::string cmd("UPDATE ");

		cmd.append(getCurrentTime());

		cmd.append(" ");

		cmd.append(my);
		cmd.append(" ");
		cmd.append(r1);
		cmd.append(" ");
		if (!statsMsg) {
			cmd.append("0 ");
		}
		cmd.append(r2);
		cmd.append(" ");
		cmd.append(ur);
		cmd.append(" ");

		char flags[16];
		snprintf(flags, 16, "%02X %02X %02X", flag1, flag2, flag3);

		cmd.append(flags);
		cmd.append(" ");
		cmd.append(myext);

		if (statsMsg) {
			cmd.append(" # ");
			cmd.append(tx_stats);
		} else {
			cmd.append(" 00 ");
			cmd.append(dest);

			if (tx_msg.length() == 20) {
				cmd.append(" ");
				cmd.append(tx_msg);
			}
		}


		IRCMessage *m = new IRCMessage(srv, cmd);

		q->putMessage(m);
		return true;
	} else
		return false;
}

bool IRCDDBApp::findUser(const std::string &usrCall)
{
	std::string srv = d->currentServer;
	IRCMessageQueue *q = getSendQ();

	if ((srv.length() > 0) && (d->state >= 6) && (q != NULL)) {
		std::string usr = usrCall;

		ReplaceChar(usr, ' ', '_');

		IRCMessage *m = new IRCMessage(srv, std::string("FIND ") + usr );

		q->putMessage(m);
	} else {
		IRCMessage *m2 = new IRCMessage("IDRT_USER");
		m2->addParam(usrCall);
		m2->addParam("");
		m2->addParam("");
		m2->addParam("");
		m2->addParam("");
		d->replyQ.putMessage(m2);
	}

	return true;
}

void IRCDDBApp::msgChannel(IRCMessage *m)
{
	if (0==m->getPrefixNick().compare(0, 2, "s-") && (m->numParams >= 2)) { // server msg
		doUpdate(m->params[1]);
	}
}

void IRCDDBApp::doNotFound(std::string &msg, std::string &retval)
{
	int tableID = 0;

	std::vector<std::string> tkz = stringTokenizer(msg);

	if (0u == tkz.size())
		return;  // no text in message

	std::string tk = tkz.front();
	tkz.erase(tkz.begin());


	if (std::regex_match(tk, d->tablePattern)) {
		long tableID = std::stol(tk);

		if ((tableID < 0) || (tableID >= numberOfTables)) {
			printf("invalid table ID %ld", tableID);
			return;
		}

		if (0u == tkz.size())
			return;  // received nothing but the tableID

		tk = tkz.front();
		tk.erase(tk.begin());
	}

	if (tableID == 0) {
		if (! std::regex_match(tk, d->dbPattern))
			return; // no valid key

		retval = tk;
	}
}

void IRCDDBApp::doUpdate(std::string &msg)
{
	int tableID = 0;

	std::vector<std::string> tkz = stringTokenizer(msg);

	if (0u == tkz.size())
		return;  // no text in message

	std::string tk = tkz.front();
	tkz.erase(tkz.begin());

	if (std::regex_match(tk, d->tablePattern)) {
		tableID = stol(tk);
		if ((tableID < 0) || (tableID >= numberOfTables)) {
			printf("invalid table ID %d", tableID);
			return;
		}

		if (0 == tkz.size())
			return;  // received nothing but the tableID

		tk = tkz.front();
		tkz.erase(tkz.begin());
	}

	if (std::regex_match(tk, d->datePattern)) {
		if (0 == tkz.size())
			return;  // nothing after date string

		std::string timeToken = tkz.front();
		tkz.erase(tkz.begin());

		if (! std::regex_match(timeToken, d->timePattern))
			return; // no time string after date string

		time_t dt = parseTime(std::string(tk + " " + timeToken));

		if ((tableID == 0) || (tableID == 1)) {
			if (0 == tkz.size())
				return;  // nothing after time string

			std::string key = tkz.front();
			tkz.erase(tkz.begin());

			if (! std::regex_match(key, d->dbPattern))
				return; // no valid key

			if (0 == tkz.size())
				return;  // nothing after time string

			std::string value = tkz.front();
			tkz.erase(tkz.begin());

			if (! std::regex_match(value, d->dbPattern))
				return; // no valid key

			//printf("TABLE %d %s %s\n", tableID, key.c_str(), value.c_str());

			if (tableID == 1) {
				d->rptrMapMutex.lock();

				IRCDDBAppRptrObject newRptr(dt, key, value);

				d->rptrMap[key] = newRptr;

				if (d->initReady) {
					std::string arearp_cs = key;
					std::string zonerp_cs = value;

					ReplaceChar(arearp_cs, '_', ' ');
					ReplaceChar(zonerp_cs, '_', ' ');
					zonerp_cs[7] = 'G';

					IRCMessage *m2 = new IRCMessage("IDRT_REPEATER");
					m2->addParam(arearp_cs);
					m2->addParam(zonerp_cs);
					m2->addParam(getIPAddress(value));
					d->replyQ.putMessage(m2);
				}
				d->rptrMapMutex.unlock();
			} else if ((tableID == 0) && d->initReady) {
				d->rptrMapMutex.lock();

				std::string userCallsign = key;
				std::string arearp_cs = value;
				std::string zonerp_cs;
				std::string ip_addr;

				ReplaceChar(userCallsign, '_', ' ');
				ReplaceChar(arearp_cs, '_', ' ');

				if (d->rptrMap.end() != d->rptrMap.find(value)) {
					IRCDDBAppRptrObject o = d->rptrMap[value];
					zonerp_cs = o.zonerp_cs;
					ReplaceChar(zonerp_cs, '_', ' ');
					zonerp_cs[7] = 'G';

					ip_addr = getIPAddress(o.zonerp_cs);
				}

				IRCMessage *m2 = new IRCMessage("IDRT_USER");
				m2->addParam(userCallsign);
				m2->addParam(arearp_cs);
				m2->addParam(zonerp_cs);
				m2->addParam(ip_addr);
				m2->addParam(tk + std::string(" ") + timeToken);
				d->replyQ.putMessage(m2);

				d->rptrMapMutex.unlock();

			}
		}
	}
}

static std::string getTableIDString(int tableID, bool spaceBeforeNumber)
{
	if (tableID == 0) {
		return std::string("");
	} else if ((tableID > 0) && (tableID < numberOfTables)) {
		if (spaceBeforeNumber) {
			return std::string(" ") + std::to_string(tableID);
		} else {
			return std::to_string(tableID) + std::string(" ");
		}
	} else {
		return std::string(" TABLE_ID_OUT_OF_RANGE ");
	}
}

void IRCDDBApp::msgQuery(IRCMessage *m)
{

	if (0 == strcmp(m->getPrefixNick().substr(0,2).c_str(), "s-") && (m->numParams >= 2)) { // server msg
		std::string msg = m->params[1];
		std::vector<std::string> tkz = stringTokenizer(msg);

		if (0 == tkz.size())
			return;  // no text in message

		std::string cmd = tkz.front();
		tkz.erase(tkz.begin());

		if (cmd == std::string("UPDATE")) {
			std::string restOfLine;
			while (tkz.size()) {
				restOfLine += tkz.front();
				tkz.erase(tkz.begin());
				if (tkz.size())
					restOfLine += " ";
			}
			doUpdate(restOfLine);
		} else if (cmd == std::string("LIST_END")) {
			if (d->state == 5) { // if in sendlist processing state
				d->state = 3;  // get next table
			}
		} else if (cmd == std::string("LIST_MORE")) {
			if (d->state == 5) { // if in sendlist processing state
				d->state = 4;  // send next SENDLIST
			}
		} else if (cmd == std::string("NOT_FOUND")) {
			std::string callsign;
			std::string restOfLine;
			while (tkz.size()) {
				restOfLine += tkz.front();
				tkz.erase(tkz.begin());
				if (tkz.size())
					restOfLine += " ";
			}
			doNotFound(restOfLine, callsign);

			if (callsign.length() > 0) {
				ReplaceChar(callsign, '_', ' ');

				IRCMessage *m2 = new IRCMessage("IDRT_USER");
				m2->addParam(callsign);
				m2->addParam("");
				m2->addParam("");
				m2->addParam("");
				m2->addParam("");
				d->replyQ.putMessage(m2);
			}
		}
	}
}

void IRCDDBApp::setSendQ(IRCMessageQueue *s)
{
	d->sendQ = s;
}

IRCMessageQueue *IRCDDBApp::getSendQ()
{
	return d->sendQ;
}

static std::string getLastEntryTime(int tableID)
{

	if (tableID == 1) {
		struct tm *ptm = gmtime(&IRCDDBAppRptrObject::maxTime);
		char tstr[80];
		strftime(tstr, 80, "%Y-%m-%d %H:%M:%S", ptm);
		std::string max = tstr;
		return max;
	}

	return "DBERROR";
}

void IRCDDBApp::Entry()
{
	int sendlistTableID = 0;

	while (!d->terminateThread) {

		if (d->timer > 0) {
			d->timer--;
		}

		switch(d->state) {
		case 0:  // wait for network to start

			if (getSendQ() != NULL) {
				d->state = 1;
			}
			break;

		case 1:
			// connect to db
			d->state = 2;
			d->timer = 200;
			break;

		case 2:   // choose server
			printf("IRCDDBApp: state=2 choose new 's-'-user\n");
			if (getSendQ() == NULL) {
				d->state = 10;
			} else {
				if (findServerUser()) {
					sendlistTableID = numberOfTables;

					d->state = 3; // next: send "SENDLIST"
				} else if (d->timer == 0) {
					d->state = 10;
					IRCMessage *m = new IRCMessage("QUIT");

					m->addParam("no op user with 's-' found.");

					IRCMessageQueue * q = getSendQ();
					if (q != NULL) {
						q->putMessage(m);
					}
				}
			}
			break;

		case 3:
			if (getSendQ() == NULL) {
				d->state = 10; // disconnect DB
			} else {
				sendlistTableID --;
				if (sendlistTableID < 0) {
					d->state = 6; // end of sendlist
				} else {
					printf("IRCDDBApp: state=3 tableID=%d\n", sendlistTableID);
					d->state = 4; // send "SENDLIST"
					d->timer = 900; // 15 minutes max for update
				}
			}
			break;

		case 4:
			if (getSendQ() == NULL) {
				d->state = 10; // disconnect DB
			} else {
				if (1 == sendlistTableID) {
					IRCMessage *m = new IRCMessage(d->currentServer, std::string("SENDLIST") + getTableIDString(sendlistTableID, true)
					                                + std::string(" ") + getLastEntryTime(sendlistTableID));

					IRCMessageQueue *q = getSendQ();
					if (q != NULL)
						q->putMessage(m);

					d->state = 5; // wait for answers
				} else
					d->state = 3; // don't send SENDLIST for this table (tableID 0), go to next table
			}
			break;

		case 5: // sendlist processing
			if (getSendQ() == NULL) {
				d->state = 10; // disconnect DB
			} else if (d->timer == 0) {
				d->state = 10; // disconnect DB
				IRCMessage *m = new IRCMessage("QUIT");

				m->addParam("timeout SENDLIST");

				IRCMessageQueue *q = getSendQ();
				if (q != NULL) {
					q->putMessage(m);
				}

			}
			break;

		case 6:
			if (getSendQ() == NULL) {
				d->state = 10; // disconnect DB
			} else {
				printf("IRCDDBApp: state=6 initialization completed\n");

				d->infoTimer = 2;

				d->initReady = true;
				d->state = 7;
			}
			break;


		case 7: // standby state after initialization
			if (getSendQ() == NULL)
				d->state = 10; // disconnect DB

			if (d->infoTimer > 0) {
				d->infoTimer--;

				if (d->infoTimer == 0) {
					d->moduleMapMutex.lock();

					for (auto itl = d->locationMap.begin(); itl != d->locationMap.end(); itl++) {
						std::string value = itl->second;
						IRCMessage *m = new IRCMessage(d->currentServer, std::string("IRCDDB RPTRQTH: ") + value);

						IRCMessageQueue * q = getSendQ();
						if (q != NULL) {
							q->putMessage(m);
						}
					}

					for (auto itu = d->urlMap.begin(); itu != d->urlMap.end(); itu++) {
						std::string value = itu->second;
						IRCMessage * m = new IRCMessage(d->currentServer, std::string("IRCDDB RPTRURL: ") + value);

						IRCMessageQueue * q = getSendQ();
						if (q != NULL) {
							q->putMessage(m);
						}
					}

					for(auto itm = d->moduleMap.begin(); itm != d->moduleMap.end(); itm++) {
						std::string value = itm->second;
						IRCMessage * m = new IRCMessage(d->currentServer, std::string("IRCDDB RPTRQRG: ") + value);

						IRCMessageQueue *q = getSendQ();
						if (q != NULL) {
							q->putMessage(m);
						}
					}

					for(auto its = d->swMap.begin(); its != d->swMap.end(); its++) {
						std::string value = its->second;
						IRCMessage * m = new IRCMessage(d->currentServer, std::string("IRCDDB RPTRSW: ") + value);

						IRCMessageQueue *q = getSendQ();
						if (q != NULL) {
							q->putMessage(m);
						}
					}

					d->moduleMapMutex.unlock();
				}
			}

			if (d->wdTimer > 0) {
				d->wdTimer--;
				if (d->wdTimer <= 0) {
					d->wdTimer = 900;  // 15 minutes

					IRCMessage *m = new IRCMessage(d->currentServer, std::string("IRCDDB WATCHDOG: ") +
							getCurrentTime() + std::string(" ") + d->wdInfo + std::string(" 1"));

					IRCMessageQueue *q = getSendQ();
					if (q != NULL)
						q->putMessage(m);
					else
						delete m;
				}
			}
			break;

		case 10:
			// disconnect db
			d->state = 0;
			d->timer = 0;
			d->initReady = false;
			break;

		}

		sleep(1);

	} // while

	return;
} // Entry()
