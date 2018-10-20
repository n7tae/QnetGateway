#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>

#include "IRCClient.h"
#include "IRCutils.h"

#include <fcntl.h>
#include <errno.h>

IRCClient::IRCClient(IRCApplication *app, const std::string &update_channel, const std::string &hostName, unsigned int port, const std::string &callsign, const std::string &password, const std::string &versionInfo, const std::string &localAddr)
{
	safeStringCopy(host_name, hostName.c_str(), sizeof host_name);


	this->callsign = callsign;
	ToLower(this->callsign);
	this->port = port;
	this->password = password;

	this->app = app;

	if (localAddr.empty())
		safeStringCopy(local_addr, "0.0.0.0", sizeof local_addr);
	else
		safeStringCopy(local_addr, localAddr.c_str(), sizeof local_addr);

	proto = new IRCProtocol(app, this->callsign, password, update_channel, versionInfo);

	recvQ = NULL;
	sendQ = NULL;

	recv = NULL;
}

IRCClient::~IRCClient()
{
	delete proto;
}

bool IRCClient::startWork()
{

	terminateThread = false;
	client_thread = std::async(std::launch::async, &IRCClient::Entry, this);
	return true;
}

void IRCClient::stopWork()
{
	terminateThread = true;
    client_thread.get();
}

#define MAXIPV4ADDR 10
void IRCClient::Entry()
{

	unsigned int numAddr;

	struct sockaddr_in addr[MAXIPV4ADDR];

	struct sockaddr_in myaddr;

	int state = 0;
	int timer = 0;
	int sock = 0;
	unsigned int currentAddr = 0;

	numAddr = 0;

	int result = getAllIPV4Addresses(local_addr, 0, &numAddr, &myaddr, 1);

	if ((result != 0) || (numAddr != 1)) {
		printf("IRCClient::Entry: local address not parseable, using 0.0.0.0\n");
		memset(&myaddr, 0x00, sizeof(struct sockaddr_in));
	}

	while (true) {

		if (timer > 0) {
			timer--;
		}

		switch (state) {
            case 0:
                if (terminateThread) {
                    printf("IRCClient::Entry: thread terminated at state=%d\n", state);
                    return;
                }

                if (timer == 0) {
                    timer = 30;

                    if (getAllIPV4Addresses(host_name, port, &numAddr, addr, MAXIPV4ADDR) == 0) {
                        //printf("IRCClient::Entry: number of DNS entries %d\n", numAddr);
                        if (numAddr > 0) {
                            currentAddr = 0;
                            state = 1;
                            timer = 0;
                        }
                    }
                }
                break;

            case 1:
                if (terminateThread) {
                    printf("IRCClient::Entry: thread terminated at state=%d\n", state);
                    return;
                }

                if (timer == 0) {
                    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

                    if (sock < 0) {
                        printf("IRCClient::Entry: could not create socket!\n");
                        timer = 30;
                        state = 0;
                    } else {
                        if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
                            printf("IRCClient::Entry: fcntl error\n");
                            close(sock);
                            timer = 30;
                            state = 0;
                        }
                        else {
                            unsigned char *h = (unsigned char *) &(myaddr.sin_addr);
                            int res;

                            if ((h[0] != 0) || (h[1] != 0) || (h[2] != 0) || (h[3] != 0))
                                printf("IRCClient::Entry: bind: local address %d.%d.%d.%d\n", h[0], h[1], h[2], h[3]);

                            res = bind(sock, (struct sockaddr *) &myaddr, sizeof (struct sockaddr_in));

                            if (res != 0) {
                                printf("IRCClient::Entry: bind error\n");
                                close(sock);
                                state = 0;
                                timer = 30;
                                break;
                            }


                            h = (unsigned char *) &(addr[currentAddr].sin_addr);
                            //printf("IRCClient::Entry: trying to connect to %d.%d.%d.%d\n", h[0], h[1], h[2], h[3]);

                            res = connect(sock, (struct sockaddr *) (addr + currentAddr), sizeof (struct sockaddr_in));

                            if (res == 0) {
                                printf("IRCClient::Entry: connected to %d.%d.%d.%d\n", h[0], h[1], h[2], h[3]);
                                state = 4;
                            } else {
                                if (errno == EINPROGRESS) {
                                    //printf("IRCClient::Entry: connect in progress\n");
                                    state = 3;
                                    timer = 10;  // 5 second timeout
                                } else {
                                    printf("IRCClient::Entry: connect\n");
                                    close(sock);
                                    currentAddr++;
                                    if (currentAddr >= numAddr) {
                                        state = 0;
                                        timer = 30;
                                    } else {
                                        state = 1;
                                        timer = 4;
                                    }
                                }
                            }
                        } // connect
                    }
                }
                break;

            case 3: {
                struct timeval tv;
                tv.tv_sec = 0;
                tv.tv_usec = 0;
                fd_set myset;
                FD_ZERO(&myset);
                FD_SET(sock, &myset);
                int res = select(sock+1, NULL, &myset, NULL, &tv);

                if (res < 0) {
                    printf("IRCClient::Entry: select\n");
                    close(sock);
                    state = 0;
                    timer = 30;
                } else if (res > 0) { // connect is finished
                    socklen_t val_len;
                    int value;

                    val_len = sizeof value;

                    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *) &value, &val_len) < 0) {
                        printf("IRCClient::Entry: getsockopt error\n");
                        close(sock);
                        state = 0;
                        timer = 30;
                    } else {
                        if (value != 0) {
                            printf("IRCClient::Entry: SO_ERROR=%d\n", value);
                            close(sock);
                            currentAddr ++;
                            if (currentAddr >= numAddr) {
                                state = 0;
                                timer = 30;
                            } else {
                                state = 1;
                                timer = 2;
                            }
                        } else {
                            printf("IRCClient::Entry: connected2\n");
                            state = 4;
                        }
                    }

                } else if (timer == 0) {
                    // select timeout and timer timeout
                    //printf("IRCClient::Entry: connect timeout\n");
                    close(sock);
                    currentAddr++;
                    if (currentAddr >= numAddr) {
                        state = 0;
                        timer = 30;
                    } else {
                        state = 1; // open new socket
                        timer = 2;
                    }
                }

            }
            break;

            case 4: {
                recvQ = new IRCMessageQueue();
                sendQ = new IRCMessageQueue();

                recv = new IRCReceiver(sock, recvQ);
                recv->startWork();

                proto->setNetworkReady(true);
                state = 5;
                timer = 0;

            }
            break;


            case 5:
                if (terminateThread) {
                    state = 6;
                } else {

                    if (recvQ->isEOF()) {
                        timer = 0;
                        state = 6;
                    } else if (proto->processQueues(recvQ, sendQ) == false) {
                        timer = 0;
                        state = 6;
                    }

                    while ((state == 5) && sendQ->messageAvailable()) {
                        IRCMessage * m = sendQ->getMessage();

                        std::string out;

                        m->composeMessage(out);

                        char buf[200];
                        safeStringCopy(buf, out.c_str(), sizeof buf);
                        int len = strlen(buf);

                        if (buf[len - 1] == 10) { // is there a NL char at the end?
                            int r = send(sock, buf, len, 0);

                            if (r != len) {
                                printf("IRCClient::Entry: short write %d < %d\n", r, len);

                                timer = 0;
                                state = 6;
                            }
                            /*	    else
                                    {
                                      printf("write %d bytes (%s)\n", len, out.c_str());
                                    } */
                        } else {
                            printf("IRCClient::Entry: no NL at end, len=%d\n", len);

                            timer = 0;
                            state = 6;
                        }

                        delete m;
                    }
                }
                break;

            case 6: {
                if (app != NULL) {
                    app->setSendQ(NULL);
                    app->userListReset();
                }

                proto->setNetworkReady(false);
                recv->stopWork();

                sleep(2);

                delete recv;
                delete recvQ;
                delete sendQ;

                close(sock);

                if (terminateThread) { // request to end the thread
                    printf("IRCClient::Entry: thread terminated at state=%d\n", state);
                    return;
                }

                timer = 30;
                state = 0;  // reconnect to IRC server
            }
            break;
		}   // switch
		usleep(500000);

	}
	return;
}
