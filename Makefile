# Copyright (c) 2018 by Thomas A. Early N7TAE
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# locations for the executibles and other files are set here
# NOTE: IF YOU CHANGE THESE, YOU WILL NEED TO UPDATE THE service.* FILES AND
# if you change these locations, make sure the sgs.service file is updated!
BINDIR=/usr/local/bin
CFGDIR=/usr/local/etc

# use this if you want debugging help in the case of a crash
#CPPFLAGS=-g -ggdb -W -Wall -std=c++11 -DCFG_DIR=\"$(CFGDIR)\"

# or, you can choose this for a much smaller executable without debugging help
CPPFLAGS=-W -Wall -std=c++11

LDFLAGS=-L/usr/lib -lconfig++ -lrt

DSTROBJS = dstar_dv.o golay23.o
IRCOBJS = IRCDDB.o IRCClient.o IRCReceiver.o IRCMessageQueue.o IRCProtocol.o IRCMessage.o IRCDDBApp.o IRCutils.o $(DSTROBJS)
SRCS = $(wildcard *.cpp)
OBJS = $(SRCS:.cpp=.o)
DEPS = $(SRCS:.cpp=.d)
PROGRAMS=qngateway qnlink qnrelay qndvap qndvrptr qnlinktest qnlinktestaudio

all : $(PROGRAMS)

qngateway : $(IRCOBJS) QnetGateway.o aprs.o
	g++ $(CPPFLAGS) -o qngateway QnetGateway.o aprs.o $(IRCOBJS) $(LDFLAGS) -pthread

qnlink : QnetLink.o
	g++ $(CPPFLAGS) -o qnlink QnetLink.o $(LDFLAGS) -pthread

qnrelay : QnetRelay.o
	g++ $(CPPFLAGS) -o qnrelay QnetRelay.o $(LDFLAGS)

qndvap : QnetDVAP.o DVAPDongle.o $(DSTROBJS)
	g++ $(CPPFLAGS) -o qndvap QnetDVAP.o DVAPDongle.o $(DSTROBJS) $(LDFLAGS) -pthread

qndvrptr : QnetDVRPTR.o $(DSTROBJS)
	g++ $(CPPFLAGS) -o qndvrptr QnetDVRPTR.o $(DSTROBJS) $(LDFLAGS)

qnlinktest : QnetLinkTest.o
	g++ $(CPPFLAGS) -o qnlinktest QnetLinkTest.o  -lrt

qnlinktestaudio : QnetLinkTestAudio.o
	g++ $(CPPFLAGS) -o qnlinktestaudio QnetLinkTestAudio.o  -lrt

%.o : %.cpp
	g++ $(CPPFLAGS) -MMD -MD -c $< -o $@

.PHONY: clean

clean:
	$(RM) $(OBJS) $(DEPS) $(PROGRAMS)

-include $(DEPS)

install : qngateway qnlink qnrelay
	######### QnetGateway #########
	/bin/cp -f qngateway $(BINDIR)
	/bin/cp -f qn.cfg $(CFGDIR)
	/bin/cp -f service.qngateway /lib/systemd/system/qngateway.service
	systemctl enable qngateway.service
	systemctl daemon-reload
	systemctl start qngateway.service
	######### QnetLink #########
	/bin/cp -f qnlink $(BINDIR)
	/bin/cp -f announce/*.dat $(CFGDIR)
	/bin/cp -f gwys.txt $(CFGDIR)
	/bin/cp -f exec_?.sh $(CFGDIR)
	/bin/cp -f service.qnlink /lib/systemd/system/qnlink.service
	systemctl enable qnlink.service
	systemctl daemon-reload
	systemctl start qnlink.service
	######### QnetRelay #########
	/bin/cp -f qnrelay $(BINDIR)
	/bin/cp -f service.qnrelay /lib/systemd/system/qnrelay.service
	systemctl enable qnrelay.service
	systemctl daemon-reload
	systemctl start qnrelay.service

installdvap : qngateway qnlink qndvap
	######### QnetGateway #########
	/bin/cp -f qngateway $(BINDIR)
	/bin/cp -f qn.cfg $(CFGDIR)
	/bin/cp -f service.qngateway /lib/systemd/system/qngateway.service
	systemctl enable qngateway.service
	systemctl daemon-reload
	systemctl start qngateway.service
	######### QnetLink #########
	/bin/cp -f qnlib $(BINDIR)
	/bin/cp -f announce/*.dat $(CFGDIR)
	/bin/cp -f gwys.txt $(CFGDIR)
	/bin/cp -f exec_?.sh $(CFGDIR)
	/bin/cp -f service.qnlink /lib/systemd/system/qnlink.service
	systemctl enable qnlink.service
	systemctl daemon-reload
	systemctl start qnlink.service
	######### QnetDVAP #########
	/bin/cp -f qndvap $(BINDIR)
	/bin/cp -f qndvap.sh $(BINDIR)
	/bin/cp -f service.qndvap /lib/systemd/system/qndvap.service
	systemctl enable qnlink.service
	systemctl daemon-reload
	systemctl start qnlink.service

installdvrptr : qngateway qnlink qndvrptr
	######### QnetGateway #########
	/bin/cp -f qngateway $(BINDIR)
	/bin/cp -f qn.cfg $(CFGDIR)
	/bin/cp -f service.qngateway /lib/systemd/system/qngateway.service
	systemctl enable qngateway.service
	systemctl daemon-reload
	systemctl start qngateway.service
	######### QnetLink #########
	/bin/cp -f qnlib $(BINDIR)
	/bin/cp -f announce/*.dat $(CFGDIR)
	/bin/cp -f gwys.txt $(CFGDIR)
	/bin/cp -f exec_?.sh $(CFGDIR)
	/bin/cp -f service.qnlink /lib/systemd/system/qnlink.service
	systemctl enable qnlink.service
	systemctl daemon-reload
	systemctl start qnlink.service
	######### QnetDVRPTR #########
	/bin/cp -f qndvrptr $(BINDIR)
	/bin/cp -f qndvrptr.sh $(BINDIR)
	/bin/cp -f service.qndvrptr /lib/systemd/system/qndvrptr.service
	systemctl enable qndvrptr.service
	systemctl daemon-reload
	systemctl start qndvrptr.service

installdtmfs : qnlinktest
	/bin/cp -f qnlinktest $(BINDIR)
	/bin/cp -f proc_qnlinktest $(BINDIR)
	/bin/cp -f service.qnlinktest /lib/systemd/system/qnlinktest.service
	systemctl enable qnlinktest.service
	systemctl daemon-reload
	systemctl start qnlinktest.service

uninstalldtmfs:
	systemctl stop qnlinktest.service
	systemctl disable qnlinktest.service
	/bin/rm -f /lib/systemd/system/qnlinktest.service
	systemctl daemon-reload
	/bin/rm -f $(BINDIR)/qnlinktest
	/bin/rm -f $(BINDIR)/proc_qnlinktest

uninstall :
	######### QnetGateway #########
	systemctl stop qngateway.service
	systemctl disable qngateway.service
	/bin/rm -f /lib/systemd/system/qngateway.service
	/bin/rm -f $(BINDIR)/qngateway
	/bin/rm -f $(CFGDIR)/qn.cfg
	######### QnetLink #########
	systemctl stop qnlink.service
	systemctl disable qnlink.service
	/bin/rm -f /lib/systemd/system/qnlink.service
	/bin/rm -f $(BINDIR)/qnlink
	/bin/rm -f $(CFGDIR)/already_linked.dat
	/bin/rm -f $(CFGDIR)/already_unlinked.dat
	/bin/rm -f $(CFGDIR)/failed_linked.dat
	/bin/rm -f $(CFGDIR)/id.dat
	/bin/rm -f $(CFGDIR)/linked.dat
	/bin/rm -f $(CFGDIR)/unlinked.dat
	/bin/rm -f $(CFGDIR)/RPT_STATUS.txt
	/bin/rm -f $(CFGDIR)/gwys.txt
	/bin/rm -f $(CFGDIR)/exec_?.sh
	######### QnetRelay #########
	systemctl stop qnrelay.service
	systemctl disable qnrelay.service
	/bin/rm -f /lib/systemd/system/qnrelay.service
	/bin/rm -f $(BINDIR)/qnrelay

uninstalldvap :
	######### QnetGateway #########
	systemctl stop qngateway.service
	systemctl disable qngateway.service
	/bin/rm -f /lib/systemd/system/qngateway.service
	/bin/rm -f $(BINDIR)/qngateway
	/bin/rm -f $(CFGDIR)/qn.cfg
	######### QnetLink #########
	systemctl stop qnlink.service
	systemctl disable qnlink.service
	/bin/rm -f /lib/systemd/system/qnlink.service
	/bin/rm -f $(BINDIR)/qnlink
	/bin/rm -f $(CFGDIR)/already_linked.dat
	/bin/rm -f $(CFGDIR)/already_unlinked.dat
	/bin/rm -f $(CFGDIR)/failed_linked.dat
	/bin/rm -f $(CFGDIR)/id.dat
	/bin/rm -f $(CFGDIR)/linked.dat
	/bin/rm -f $(CFGDIR)/unlinked.dat
	/bin/rm -f $(CFGDIR)/RPT_STATUS.txt
	/bin/rm -f $(CFGDIR)/gwys.txt
	/bin/rm -f $(CFGDIR)/exec_?.sh
	######### QnetDVAP #########
	systemctl stop qndvap.service
	systemctl disable qndvap.service
	/bin/rm -f /lib/systemd/system/qndvap.service
	/bin/rm -f $(BINDIR)/qndvap
	/bin/rm -f $(BINDIR)/qndvap.sh

uninstalldvrptr :
	######### QnetGateway #########
	systemctl stop qngateway.service
	systemctl disable qngateway.service
	/bin/rm -f /lib/systemd/system/qngateway.service
	/bin/rm -f $(BINDIR)/qngateway
	/bin/rm -f $(CFGDIR)/qn.cfg
	######### QnetLink #########
	systemctl stop qnlink.service
	systemctl disable qnlink.service
	/bin/rm -f /lib/systemd/system/qnlink.service
	/bin/rm -f $(BINDIR)/qnlink
	/bin/rm -f $(CFGDIR)/already_linked.dat
	/bin/rm -f $(CFGDIR)/already_unlinked.dat
	/bin/rm -f $(CFGDIR)/failed_linked.dat
	/bin/rm -f $(CFGDIR)/id.dat
	/bin/rm -f $(CFGDIR)/linked.dat
	/bin/rm -f $(CFGDIR)/unlinked.dat
	/bin/rm -f $(CFGDIR)/RPT_STATUS.txt
	/bin/rm -f $(CFGDIR)/gwys.txt
	/bin/rm -f $(CFGDIR)/exec_?.sh
	######### QnetDVRPTR #########
	systemctl stop qndvrptr.service
	systemctl disable qndvrptr.service
	/bin/rm -f /lib/systemd/system/qndvrptr.service
	/bin/rm -f $(BINDIR)/qndvrptr
	/bin/rm -f $(BINDIR)/qndvrptr.sh
