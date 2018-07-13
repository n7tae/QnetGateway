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
MMPATH=../MMDVMHost
SYSDIR=/lib/systemd/system
IRC=ircddb

# use this if you want debugging help in the case of a crash
#CPPFLAGS=-g -ggdb -W -Wall -std=c++11 -Iircddb -DCFG_DIR=\"$(CFGDIR)\"

# or, you can choose this for a much smaller executable without debugging help
CPPFLAGS=-W -Wall -std=c++11 -Iircddb -DCFG_DIR=\"$(CFGDIR)\"

LDFLAGS=-L/usr/lib -lconfig++ -lrt

DSTROBJS = $(IRC)/dstar_dv.o $(IRC)/golay23.o
IRCOBJS = $(IRC)/IRCDDB.o $(IRC)/IRCClient.o $(IRC)/IRCReceiver.o $(IRC)/IRCMessageQueue.o $(IRC)/IRCProtocol.o $(IRC)/IRCMessage.o $(IRC)/IRCDDBApp.o $(IRC)/IRCutils.o $(DSTROBJS)
SRCS = $(wildcard *.cpp) $(wildcard $(IRC)/*.cpp)
OBJS = $(SRCS:.cpp=.o)
DEPS = $(SRCS:.cpp=.d)

ALL_PROGRAMS=qngateway qnlink qnremote qnvoice qnrelay qndvap qndvrptr
MDV_PROGRAMS=qngateway qnlink qnremote qnvoice qnrelay
DVP_PROGRAMS=qngateway qnlink qnremote qnvoice qndvap
DVR_PROGRAMS=qngateway qnlink qnremote qnvoice qndvrptr
ICM_PROGRAMS=qngateway qnlink qnremote qnvoice

all    : $(ALL_PROGRAMS)
mmdvm  : $(MDV_PROGRAMS)
dvap   : $(DVP_PROGRAMS)
dvrptr : $(DVR_PROGRAMS)
icom   : $(ICM_PROGRAMS)

qngateway : $(IRCOBJS) QnetGateway.o aprs.o
	g++ $(CPPFLAGS) -o qngateway QnetGateway.o aprs.o $(IRCOBJS) $(LDFLAGS) -pthread

qnlink : QnetLink.o Random.o
	g++ $(CPPFLAGS) -o qnlink QnetLink.o Random.o $(LDFLAGS) -pthread

qnrelay : QnetRelay.o
	g++ $(CPPFLAGS) -o qnrelay QnetRelay.o $(LDFLAGS)

qndvap : QnetDVAP.o DVAPDongle.o Random.o $(DSTROBJS)
	g++ $(CPPFLAGS) -o qndvap QnetDVAP.o DVAPDongle.o Random.o $(DSTROBJS) $(LDFLAGS) -pthread

qndvrptr : QnetDVRPTR.o $(DSTROBJS) Random.o
	g++ $(CPPFLAGS) -o qndvrptr QnetDVRPTR.o Random.o $(DSTROBJS) $(LDFLAGS)

qnremote : QnetRemote.o Random.o
	g++ $(CPPFLAGS) -o qnremote QnetRemote.o Random.o $(LDFLAGS)

qnvoice : QnetVoice.o Random.o
	g++ $(CPPFLAGS) -o qnvoice QnetVoice.o Random.o $(LDFLAGS)

%.o : %.cpp
	g++ $(CPPFLAGS) -MMD -MD -c $< -o $@

.PHONY: clean

clean:
	$(RM) $(OBJS) $(DEPS) $(ALL_PROGRAMS)

-include $(DEPS)

install : $(MDV_PROGRAMS) gwys.txt qn.cfg
	######### QnetGateway #########
	/bin/cp -f qngateway $(BINDIR)
	/bin/cp -f qnremote qnvoice $(BINDIR)
	/bin/ln -s $(shell pwd)/qn.cfg $(CFGDIR)
	/bin/cp -f system/qngateway.service $(SYSDIR)
	systemctl enable qngateway.service
	systemctl daemon-reload
	systemctl start qngateway.service
	######### QnetLink #########
	/bin/cp -f qnlink $(BINDIR)
	/bin/cp -f announce/*.dat $(CFGDIR)
	/bin/ln -s $(shell pwd)/gwys.txt $(CFGDIR)
	/bin/cp -f exec_?.sh $(CFGDIR)
	/bin/cp -f system/qnlink.service $(SYSDIR)
	systemctl enable qnlink.service
	systemctl daemon-reload
	systemctl start qnlink.service
	######### QnetRelay #########
	/bin/cp -f qnrelay $(BINDIR)
	/bin/cp -f system/qnrelay.service $(SYSDIR)
	systemctl enable qnrelay.service
	systemctl daemon-reload
	systemctl start qnrelay.service

installicom : $(ICM_PROGRAMS) gwys.txt qn.cfg
	######### QnetGateway #########
	/bin/cp -f qngateway $(BINDIR)
	/bin/cp -f qnremote qnvoice $(BINDIR)
	/bin/ln -s $(shell pwd)/qn.cfg $(CFGDIR)
	/bin/cp -f system/qngateway.service $(SYSDIR)
	systemctl enable qngateway.service
	systemctl daemon-reload
	systemctl start qngateway.service
	######### QnetLink #########
	/bin/cp -f qnlink $(BINDIR)
	/bin/cp -f announce/*.dat $(CFGDIR)
	/bin/ln -s $(shell pwd)/gwys.txt $(CFGDIR)
	/bin/cp -f exec_?.sh $(CFGDIR)
	/bin/cp -f system/qnlink.service $(SYSDIR)
	systemctl enable qnlink.service
	systemctl daemon-reload
	systemctl start qnlink.service

installdvap : $(DVP_PROGRAMS) gwys.txt qn.cfg
	######### QnetGateway #########
	/bin/cp -f qngateway $(BINDIR)
	/bin/cp -f qnremote qnvoice $(BINDIR)
	/bin/ln -s $(shell pwd)/qn.cfg $(CFGDIR)
	/bin/cp -f system/qngateway.service $(SYSDIR)
	systemctl enable qngateway.service
	systemctl daemon-reload
	systemctl start qngateway.service
	######### QnetLink #########
	/bin/cp -f qnlink $(BINDIR)
	/bin/cp -f announce/*.dat $(CFGDIR)
	/bin/ln -s $(shell pwd)/gwys.txt $(CFGDIR)
	/bin/cp -f exec_?.sh $(CFGDIR)
	/bin/cp -f system/qnlink.service $(SYSDIR)
	systemctl enable qnlink.service
	systemctl daemon-reload
	systemctl start qnlink.service
	######### QnetDVAP #########
	/bin/cp -f qndvap $(BINDIR)
	/bin/cp -f system/qndvap.service $(SYSDIR)
	systemctl enable qndvap.service
	systemctl daemon-reload
	systemctl start qndvap.service

installdvrptr : $(DVR_PROGRAMS) gwys.txt qn.cfg
	######### QnetGateway #########
	/bin/cp -f qngateway $(BINDIR)
	/bin/cp -f qnremote qnvoice $(BINDIR)
	/bin/ln -s $(shell pwd)/qn.cfg $(CFGDIR)
	/bin/cp -f system/qngateway.service $(SYSDIR)
	systemctl enable qngateway.service
	systemctl daemon-reload
	systemctl start qngateway.service
	######### QnetLink #########
	/bin/cp -f qnlink $(BINDIR)
	/bin/cp -f announce/*.dat $(CFGDIR)
	/bin/ln -s $(shell pwd)/gwys.txt $(CFGDIR)
	/bin/cp -f exec_?.sh $(CFGDIR)
	/bin/cp -f system/qnlink.service $(SYSDIR)
	systemctl enable qnlink.service
	systemctl daemon-reload
	systemctl start qnlink.service
	######### QnetDVRPTR #########
	/bin/cp -f qndvrptr $(BINDIR)
	/bin/cp -f system/qndvrptr.service $(SYSDIR)
	systemctl enable qndvrptr.service
	systemctl daemon-reload
	systemctl start qndvrptr.service

installdtmf : qndtmf
	/bin/ln -s $(shell pwd)/qndtmf $(BINDIR)
	/bin/cp -f system/qndtmf.service $(SYSDIR)
	systemctl enable qndtmf.service
	systemctl daemon-reload
	systemctl start qndtmf.service

installmmdvm : $(MMPATH)/MMDVMHost $(MMPATH)/MMDVM.qn
	/bin/cp -f $(MMPATH)/MMDVMHost $(BINDIR)
	/bin/ln -s $(shell pwd)/$(MMPATH)/MMDVM.qn $(CFGDIR)
	/bin/cp -f system/mmdvm.service $(SYSDIR)
	/bin/cp -f system/mmdvm.timer $(SYSDIR)
	systemctl enable mmdvm.timer
	systemctl daemon-reload
	systemctl start mmdvm.service

uninstallmmdvm :
	systemctl stop mmdvm.service
	systemctl disable mmdvm.timer
	/bin/rm -f $(SYSDIR)/mmdvm.service
	/bin/rm -f $(SYSDIR)/mmdvm.timer
	/bin/rm -f $(BINDIR)/MMDVMHost
	/bin/rm -f $(CFGDIR)/MMDVM.qn
	sudo systemctl daemon-reload

uninstall :
	######### QnetGateway #########
	systemctl stop qngateway.service
	systemctl disable qngateway.service
	/bin/rm -f $(SYSDIR)/qngateway.service
	/bin/rm -f $(BINDIR)/qngateway
	/bin/rm -f $(BINDIR)/qnremote
	/bin/rm -f $(BINDIR)/qnvoice
	/bin/rm -f $(CFGDIR)/qn.cfg
	######### QnetLink #########
	systemctl stop qnlink.service
	systemctl disable qnlink.service
	/bin/rm -f $(SYSDIR)/qnlink.service
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
	/bin/rm -f $(SYSDIR)/qnrelay.service
	/bin/rm -f $(BINDIR)/qnrelay
	systemctl daemon-reload

uninstallicom :
	######### QnetGateway #########
	systemctl stop qngateway.service
	systemctl disable qngateway.service
	/bin/rm -f $(SYSDIR)/qngateway.service
	/bin/rm -f $(BINDIR)/qngateway
	/bin/rm -f $(BINDIR)/qnremote
	/bin/rm -f $(BINDIR)/qnvoice
	/bin/rm -f $(CFGDIR)/qn.cfg
	######### QnetLink #########
	systemctl stop qnlink.service
	systemctl disable qnlink.service
	/bin/rm -f $(SYSDIR)/qnlink.service
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

uninstalldvap :
	######### QnetGateway #########
	systemctl stop qngateway.service
	systemctl disable qngateway.service
	/bin/rm -f $(SYSDIR)/qngateway.service
	/bin/rm -f $(BINDIR)/qngateway
	/bin/rm -f $(BINDIR)/qnremote
	/bin/rm -f $(BINDIR)/qnvoice
	/bin/rm -f $(CFGDIR)/qn.cfg
	######### QnetLink #########
	systemctl stop qnlink.service
	systemctl disable qnlink.service
	/bin/rm -f $(SYSDIR)/qnlink.service
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
	/bin/rm -f $(SYSDIR)/qndvap.service
	/bin/rm -f $(BINDIR)/qndvap
	systemctl daemon-reload

uninstalldvrptr :
	######### QnetGateway #########
	systemctl stop qngateway.service
	systemctl disable qngateway.service
	/bin/rm -f $(SYSDIR)/qngateway.service
	/bin/rm -f $(BINDIR)/qngateway
	/bin/rm -f $(BINDIR)/qnremote
	/bin/rm -f $(BINDIR)/qnvoice
	/bin/rm -f $(CFGDIR)/qn.cfg
	######### QnetLink #########
	systemctl stop qnlink.service
	systemctl disable qnlink.service
	/bin/rm -f $(SYSDIR)/qnlink.service
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
	/bin/rm -f $(SYSDIR)/qndvrptr.service
	/bin/rm -f $(BINDIR)/qndvrptr
	systemctl daemon-reload

uninstalldtmf :
	systemctl stop qndtmf.service
	systemctl disable qndtmf.service
	/bin/rm -f $(SYSDIR)/qndtmf.service
	systemctl daemon-reload
	/bin/rm -f $(BINDIR)/qndtmf
