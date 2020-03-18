#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <string>

#include "IRCDDBApp.h"
#include "IRCutils.h"

unsigned int IRCDDBAppGateObject::counter = 0;

time_t IRCDDBAppRptrObject::maxTime((time_t)950000000);  // February 2000

IRCDDBApp::IRCDDBApp(const std::string &u_chan)
{
	wdTimer = -1;
	sendQ = NULL;
	initReady = false;

	userListReset();

	state = 0;
	timer = 0;
	myNick = "none";

	updateChannel = u_chan;

	terminateThread = false;
	tablePattern  = std::regex("^[0-9]$");
	datePattern   = std::regex("^20[0-9][0-9]-((1[0-2])|(0[1-9]))-((3[01])|([12][0-9])|(0[1-9]))$");
	timePattern   = std::regex("^((2[0-3])|([01][0-9])):[0-5][0-9]:[0-5][0-9]$");
	dbPattern     = std::regex("^[0-9A-Z_]{8}$");
	modulePattern = std::regex("^.*[ABCD]D?$");
}

IRCDDBApp::~IRCDDBApp()
{
	if (sendQ != NULL) {
		delete sendQ;
	}
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

	locationMapMutex.lock();
	locationMap[rptrcall] = f;
	locationMapMutex.unlock();

	//printf("IRCDDB RPTRQTH: %s\n", f.c_str());

	std::regex urlNonValid("[^[:graph:]]+");

	std::string url = infoURL;
	while (std::regex_search(url, sm, nonValid))
		url.erase(sm.position(0), sm.length());

	std::string g = rcall + aspace + url;

	urlMapMutex.lock();
	urlMap[rptrcall] = g;
	urlMapMutex.unlock();

	//printf("IRCDDB RPTRURL: %s\n", g.c_str());

	std::string sw = swVersion;
	while (std::regex_search(sw, sm, nonValid))
		sw.erase(sm.position(0), sm.length());

	std::string h = rcall + std::string(" ") + sw;
	swMapMutex.lock();
	swMap[rptrcall] = h;
	swMapMutex.unlock();

	//printf("IRCDDB RPTRSW: %s\n", h.c_str());

	infoTimer = 5; // send info in 5 seconds
}

void IRCDDBApp::rptrQRG(const std::string &rptrcall, double txFrequency, double duplexShift, double range, double agl)
{

	if (std::regex_match(rptrcall, modulePattern)) {

		std::string c = rptrcall;
		ReplaceChar(c, ' ', '_');

		char f[48];
		snprintf(f, 48, "%011.5f %+010.5f %06.2f %06.1f", txFrequency, duplexShift, range / 1609.344, agl);
		std::string g = c + std::string(" ") + f;

		moduleMapMutex.lock();
		moduleMap[rptrcall] = g;
		moduleMapMutex.unlock();

		//printf("IRCDDB RPTRQRG: %s\n", g.c_str());

		infoTimer = 5; // send info in 5 seconds
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
		wdInfo = u;

		if (u.length() > 0)
			wdTimer = 1;
	}
}

int IRCDDBApp::getConnectionState()
{
	return state;
}

IRCDDB_RESPONSE_TYPE IRCDDBApp::getReplyMessageType()
{
	IRCMessage * m = replyQ.peekFirst();
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
	return replyQ.getMessage();
}

void IRCDDBApp::putReplyMessage(IRCMessage *m)
{
	replyQ.putMessage(m);
}

bool IRCDDBApp::startWork()
{
	terminateThread = false;
	worker_thread = std::async(std::launch::async, &IRCDDBApp::Entry, this);
	return true;
}

void IRCDDBApp::stopWork()
{
	terminateThread = true;
	worker_thread.get();
}

void IRCDDBApp::userJoin(const std::string &nick, const std::string &name, const std::string &host)
{
	std::string lnick = nick;
	ToLower(lnick);

	IRCDDBAppGateObject u(lnick, name, host);

	userMapMutex.lock();
	user[lnick] = u;
	userMapMutex.unlock();

	//printf("add %d: (%s) (%s)\n", user.size(), nick.c_str(), host.c_str());

	if (initReady) {
		unsigned hyphenPos = nick.find('-');

		if ((hyphenPos >= 4) && (hyphenPos <= 6)) {
			std::string gatewayCallsign = nick.substr(0, hyphenPos);
			ToUpper(gatewayCallsign);
			gatewayCallsign.resize(7, '_');
			gatewayCallsign.push_back('G');

			IRCMessage *m2 = new IRCMessage("IDRT_GATEWAY");
			m2->addParam(gatewayCallsign);
			m2->addParam(host);
			replyQ.putMessage(m2);
		}
	}
	//printf("user %d\n", u.usn);
}

void IRCDDBApp::userLeave(const std::string &nick)
{
	std::string lnick = nick;
	ToLower(lnick);

	userMapMutex.lock();
	user.erase(lnick);
	userMapMutex.unlock();

	// printf("rm %d: %s\n" user.size(), nick.c_str());

	if (currentServer.length() > 0) {
		if (user.count(myNick) != 1) {
			printf("IRCDDBApp::userLeave: could not find own nick\n");
			return;
		}

		IRCDDBAppGateObject me = user[myNick];

		if (me.op == false) {
			// if I am not op, then look for new server

			if (currentServer == lnick) {
				// currentServer = null;
				state = 2;  // choose new server
				timer = 200;
				initReady = false;
			}
		}
	}
}

void IRCDDBApp::userListReset()
{
	userMapMutex.lock();
	user.clear();
	userMapMutex.unlock();
}

void IRCDDBApp::setCurrentNick(const std::string &nick)
{
	myNick = nick;
	printf("IRCDDBApp::setCurrentNick %s\n", nick.c_str());
}

void IRCDDBApp::setBestServer(const std::string &ircUser)
{
	bestServer = ircUser;
	printf("IRCDDBApp::setBestServer %s\n", ircUser.c_str());
}

void IRCDDBApp::setTopic(const std::string &topic)
{
	channelTopic = topic;
}

bool IRCDDBApp::findServerUser()
{
	userMapMutex.lock();

	bool found = false;

	std::map<std::string, IRCDDBAppGateObject>::iterator it;

	for (it=user.begin(); it!=user.end(); ++it) {
		IRCDDBAppGateObject u = it->second;
		if (0==u.nick.compare(0, 2, "s-") && u.op && myNick.compare(u.nick) && 0==u.nick.compare(bestServer)) {
			currentServer = u.nick;
			found = true;
			break;
		}
	}

	if (found) {
		userMapMutex.unlock();
		return true;
	}

	if (bestServer.length() == 8) {
		for(it=user.begin(); it!=user.end(); ++it) {
			IRCDDBAppGateObject u = it->second;
			if (0==u.nick.compare(0, 7, bestServer) && u.op && myNick.compare(u.nick) ) {
				currentServer = u.nick;
				found = true;
				break;
			}
		}
	}

	if (found) {
		userMapMutex.unlock();
		return true;
	}

	for(it = user.begin(); it != user.end(); ++it) {
		IRCDDBAppGateObject u = it->second;
		if (0==u.nick.compare(0, 2, "s-") && u.op && myNick.compare(u.nick)) {
			currentServer = u.nick;
			found = true;
			break;
		}
	}

	userMapMutex.unlock();
	return found;
}

void IRCDDBApp::userChanOp(const std::string &nick, bool op)
{
	std::string lnick = nick;
	ToLower(lnick);

	userMapMutex.lock();
	if (user.count(lnick) == 1) {
		user[lnick].op = op;
	}
	userMapMutex.unlock();
}

void IRCDDBApp::sendPing(const std::string &to, const std::string &from)
{
	std::string t = to.substr(0, 7);

	ReplaceChar(t, '_', ' ');
	while (isspace(t[t.length()-1]))
		t.pop_back();
	ToLower(t);

	userMapMutex.lock();
	for (int j=1; j <= 4; j++) {
		std::string ircUser = t + std::string("-") + std::to_string(j);

		if (1 == user.count(ircUser)) {
			std::string f(from);
			ReplaceChar(f, ' ', '_');
			IRCMessage *rm = new IRCMessage(ircUser, "IDRT_PING");
			rm->addParam(f);
			std::string out;
			rm->composeMessage(out);
			out.pop_back();
			out.pop_back();
			//printf("IRCDDBApp::sendPing: %s\n", out.c_str());
			sendQ->putMessage(rm);
			break;
		}
	}
	userMapMutex.unlock();

}

static const int numberOfTables = 2;

std::string IRCDDBApp::getIPAddress(std::string &zonerp_cs)
{
	userMapMutex.lock();
	std::string gw = zonerp_cs;

	ReplaceChar(gw, '_', ' ');
	while (isspace(gw[gw.length()-1]))
		gw.pop_back();
	ToLower(gw);

	unsigned int max_usn = 0;
	std::string ipAddr;

	for (int j=1; j <= 4; j++) {
		std::string ircUser = gw + std::string("-") + std::to_string(j);

		if (user.count(ircUser) == 1) {
			IRCDDBAppGateObject o = user[ircUser];

			if (o.usn >= max_usn) {
				max_usn = o.usn;
				ipAddr = o.host;
			}
		}
		// printf("getIP %d (%s) (%s)\n", i, ircUser.c_str(), ipAddr.c_str());

	}
	userMapMutex.unlock();
	return ipAddr;
}

bool IRCDDBApp::findGateway(const std::string &gwCall)
{
	std::string s = gwCall.substr(0,6);
	IRCMessage *m2 = new IRCMessage("IDRT_GATEWAY");
	m2->addParam(gwCall);
	m2->addParam(getIPAddress(s));
	replyQ.putMessage(m2);

	return true;
}

bool IRCDDBApp::findRepeater(const std::string &rptrCall)
{
	std::string arearp_cs = rptrCall;
	ReplaceChar(arearp_cs, ' ', '_');

	std::string zonerp_cs;

	rptrMapMutex.lock();

	std::string s("NONE");

	if (rptrMap.count(arearp_cs) == 1) {
		IRCDDBAppRptrObject o = rptrMap[arearp_cs];
		zonerp_cs = o.zonerp_cs;
		ReplaceChar(zonerp_cs, '_', ' ');
		zonerp_cs[7] = 'G';
		s = o.zonerp_cs;
	}
	rptrMapMutex.unlock();

	IRCMessage *m2 = new IRCMessage("IDRT_REPEATER");
	m2->addParam(rptrCall);
	m2->addParam(zonerp_cs);
	m2->addParam(getIPAddress(s));
	replyQ.putMessage(m2);
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

	std::string srv = currentServer;
	IRCMessageQueue *q = getSendQ();

	if ((srv.length() > 0) && (state >= 6) && (q != NULL)) {
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
	std::string srv = currentServer;
	IRCMessageQueue *q = getSendQ();

	if ((srv.length() > 0) && (state >= 6) && (q != NULL)) {
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
		replyQ.putMessage(m2);
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


	if (std::regex_match(tk, tablePattern)) {
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
		if (! std::regex_match(tk, dbPattern))
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

	if (std::regex_match(tk, tablePattern)) {
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

	if (std::regex_match(tk, datePattern)) {
		if (0 == tkz.size())
			return;  // nothing after date string

		std::string timeToken = tkz.front();
		tkz.erase(tkz.begin());

		if (! std::regex_match(timeToken, timePattern))
			return; // no time string after date string

		time_t dt = parseTime(std::string(tk + " " + timeToken));

		if ((tableID == 0) || (tableID == 1)) {
			if (0 == tkz.size())
				return;  // nothing after time string

			std::string key = tkz.front();
			tkz.erase(tkz.begin());

			if (! std::regex_match(key, dbPattern))
				return; // no valid key

			if (0 == tkz.size())
				return;  // nothing after time string

			std::string value = tkz.front();
			tkz.erase(tkz.begin());

			if (! std::regex_match(value, dbPattern))
				return; // no valid key

			//printf("TABLE %d %s %s\n", tableID, key.c_str(), value.c_str());

			if (tableID == 1) {
				rptrMapMutex.lock();

				IRCDDBAppRptrObject newRptr(dt, key, value);

				rptrMap[key] = newRptr;

				if (initReady) {
					std::string arearp_cs = key;
					std::string zonerp_cs = value;

					ReplaceChar(arearp_cs, '_', ' ');
					ReplaceChar(zonerp_cs, '_', ' ');
					zonerp_cs[7] = 'G';

					IRCMessage *m2 = new IRCMessage("IDRT_REPEATER");
					m2->addParam(arearp_cs);
					m2->addParam(zonerp_cs);
					m2->addParam(getIPAddress(value));
					replyQ.putMessage(m2);
				}
				rptrMapMutex.unlock();
			} else if ((tableID == 0) && initReady) {
				rptrMapMutex.lock();

				std::string userCallsign = key;
				std::string arearp_cs = value;
				std::string zonerp_cs;
				std::string ip_addr;

				ReplaceChar(userCallsign, '_', ' ');
				ReplaceChar(arearp_cs, '_', ' ');

				if (rptrMap.end() != rptrMap.find(value)) {
					IRCDDBAppRptrObject o = rptrMap[value];
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
				replyQ.putMessage(m2);

				rptrMapMutex.unlock();

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
			if (state == 5) { // if in sendlist processing state
				state = 3;  // get next table
			}
		} else if (cmd == std::string("LIST_MORE")) {
			if (state == 5) { // if in sendlist processing state
				state = 4;  // send next SENDLIST
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
				replyQ.putMessage(m2);
			}
		}
	}
}

void IRCDDBApp::setSendQ(IRCMessageQueue *s)
{
	sendQ = s;
}

IRCMessageQueue *IRCDDBApp::getSendQ()
{
	return sendQ;
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

	while (!terminateThread) {

		if (timer > 0) {
			timer--;
		}

		switch(state) {
		case 0:  // wait for network to start

			if (getSendQ() != NULL) {
				state = 1;
			}
			break;

		case 1:
			// connect to db
			state = 2;
			timer = 200;
			break;

		case 2:   // choose server
			printf("IRCDDBApp: state=2 choose new 's-'-user\n");
			if (getSendQ() == NULL) {
				state = 10;
			} else {
				if (findServerUser()) {
					sendlistTableID = numberOfTables;

					state = 3; // next: send "SENDLIST"
				} else if (timer == 0) {
					state = 10;
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
				state = 10; // disconnect DB
			} else {
				sendlistTableID --;
				if (sendlistTableID < 0) {
					state = 6; // end of sendlist
				} else {
					printf("IRCDDBApp: state=3 tableID=%d\n", sendlistTableID);
					state = 4; // send "SENDLIST"
					timer = 900; // 15 minutes max for update
				}
			}
			break;

		case 4:
			if (getSendQ() == NULL) {
				state = 10; // disconnect DB
			} else {
				if (1 == sendlistTableID) {
					IRCMessage *m = new IRCMessage(currentServer, std::string("SENDLIST") + getTableIDString(sendlistTableID, true)
					                                + std::string(" ") + getLastEntryTime(sendlistTableID));

					IRCMessageQueue *q = getSendQ();
					if (q != NULL)
						q->putMessage(m);

					state = 5; // wait for answers
				} else
					state = 3; // don't send SENDLIST for this table (tableID 0), go to next table
			}
			break;

		case 5: // sendlist processing
			if (getSendQ() == NULL) {
				state = 10; // disconnect DB
			} else if (timer == 0) {
				state = 10; // disconnect DB
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
				state = 10; // disconnect DB
			} else {
				printf("IRCDDBApp: state=6 initialization completed\n");

				infoTimer = 2;

				initReady = true;
				state = 7;
			}
			break;


		case 7: // standby state after initialization
			if (getSendQ() == NULL)
				state = 10; // disconnect DB

			if (infoTimer > 0) {
				infoTimer--;

				if (infoTimer == 0) {
					moduleMapMutex.lock();

					for (auto itl = locationMap.begin(); itl != locationMap.end(); itl++) {
						std::string value = itl->second;
						IRCMessage *m = new IRCMessage(currentServer, std::string("IRCDDB RPTRQTH: ") + value);

						IRCMessageQueue * q = getSendQ();
						if (q != NULL) {
							q->putMessage(m);
						}
					}

					for (auto itu = urlMap.begin(); itu != urlMap.end(); itu++) {
						std::string value = itu->second;
						IRCMessage * m = new IRCMessage(currentServer, std::string("IRCDDB RPTRURL: ") + value);

						IRCMessageQueue * q = getSendQ();
						if (q != NULL) {
							q->putMessage(m);
						}
					}

					for(auto itm = moduleMap.begin(); itm != moduleMap.end(); itm++) {
						std::string value = itm->second;
						IRCMessage * m = new IRCMessage(currentServer, std::string("IRCDDB RPTRQRG: ") + value);

						IRCMessageQueue *q = getSendQ();
						if (q != NULL) {
							q->putMessage(m);
						}
					}

					for(auto its = swMap.begin(); its != swMap.end(); its++) {
						std::string value = its->second;
						IRCMessage * m = new IRCMessage(currentServer, std::string("IRCDDB RPTRSW: ") + value);

						IRCMessageQueue *q = getSendQ();
						if (q != NULL) {
							q->putMessage(m);
						}
					}

					moduleMapMutex.unlock();
				}
			}

			if (wdTimer > 0) {
				wdTimer--;
				if (wdTimer <= 0) {
					wdTimer = 900;  // 15 minutes

					IRCMessage *m = new IRCMessage(currentServer, std::string("IRCDDB WATCHDOG: ") +
							getCurrentTime() + std::string(" ") + wdInfo + std::string(" 1"));

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
			state = 0;
			timer = 0;
			initReady = false;
			break;

		}

		sleep(1);

	} // while

	return;
} // Entry()
