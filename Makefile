# Copyright (c) 2018-2019 by Thomas A. Early N7TAE
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
CRONDIR=/etc/cron.d

# use this if you want debugging help in the case of a crash
#CPPFLAGS=-g -ggdb -W -Wall -std=c++11 -Iircddb -DCFG_DIR=\"$(CFGDIR)\"

# or, you can choose this for a much smaller executable without debugging help
CPPFLAGS=-W -Wall -std=c++11 -Iircddb -DCFG_DIR=\"$(CFGDIR)\"

LDFLAGS=-L/usr/lib -lrt

DSTROBJS = $(IRC)/dstar_dv.o $(IRC)/golay23.o
IRCOBJS = $(IRC)/IRCDDB.o $(IRC)/IRCClient.o $(IRC)/IRCReceiver.o $(IRC)/IRCMessageQueue.o $(IRC)/IRCProtocol.o $(IRC)/IRCMessage.o $(IRC)/IRCDDBApp.o $(IRC)/IRCutils.o $(DSTROBJS)
SRCS = $(wildcard *.cpp) $(wildcard $(IRC)/*.cpp)
OBJS = $(SRCS:.cpp=.o)
DEPS = $(SRCS:.cpp=.d)

ALL_PROGRAMS=qngateway qnlink qnremote qnvoice qnrelay qndvap qndvrptr qnitap qnmodem
BASE_PROGRAMS=qngateway qnlink qnremote qnvoice

all    : $(ALL_PROGRAMS)
base   : $(BASE_PROGRAMS)
relay  : qnrelay
dvap   : qndvap
dvrptr : qndvrptr
itap   : qnitap
modem  : qnmodem

qngateway : QnetGateway.o aprs.o UnixDgramSocket.o TCPReaderWriterClient.o QnetConfigure.o $(IRCOBJS)
	g++ $(CPPFLAGS) -o $@ $^ $(LDFLAGS) -pthread

qnlink : QnetLink.o DPlusAuthenticator.o TCPReaderWriterClient.o UnixDgramSocket.o QnetConfigure.o
	g++ $(CPPFLAGS) -o $@ $^ $(LDFLAGS) -pthread

qnrelay : QnetRelay.o UnixDgramSocket.o QnetConfigure.o
	g++ $(CPPFLAGS) -o $@ $^ $(LDFLAGS)

qnitap : QnetITAP.o UnixDgramSocket.o QnetConfigure.o
	g++ $(CPPFLAGS) -o $@ $^ $(LDFLAGS)

qnmodem : QnetModem.o UnixDgramSocket.o QnetConfigure.o
		g++ $(CPPFLAGS) -o $@ $^ $(LDFLAGS)

qndvap : QnetDVAP.o DVAPDongle.o UnixDgramSocket.o QnetConfigure.o $(DSTROBJS)
	g++ $(CPPFLAGS) -o $@ $^ $(LDFLAGS) -pthread

qndvrptr : QnetDVRPTR.o UnixDgramSocket.o QnetConfigure.o $(DSTROBJS)
	g++ $(CPPFLAGS) -o $@ $^ $(LDFLAGS)

qnremote : QnetRemote.o UnixDgramSocket.o QnetConfigure.o
	g++ $(CPPFLAGS) -o $@ $^ $(LDFLAGS)

qnvoice : QnetVoice.o QnetConfigure.o
	g++ $(CPPFLAGS) -o $@ $^ $(LDFLAGS)

%.o : %.cpp
	g++ $(CPPFLAGS) -MMD -MD -c $< -o $@

.PHONY: clean

clean:
	$(RM) $(OBJS) $(DEPS) $(ALL_PROGRAMS) *.gch

-include $(DEPS)

aliases : bash_aliases
	/bin/cp -f bash_aliases ~/.bash_aliases
	# aliases have been installed in ~/.bash_alises
	# You can do 'source bash_aliases' to use them now

installbase : $(BASE_PROGRAMS) gwys.txt qn.cfg
	######### QnetGateway #########
	/bin/cp -f qngateway $(BINDIR)
	/bin/cp -f qnremote qnvoice $(BINDIR)
	/bin/ln -s $(shell pwd)/qn.cfg $(CFGDIR)
	/bin/cp -f defaults $(CFGDIR)
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

installrelay : qnrelay
	######### QnetRelay #########
	/bin/ln -f qnrelay $(BINDIR)/qnrelay$(MODULE)
	sed -e "s/XXX/qnrelay$(MODULE)/" system/qnrelay.service > $(SYSDIR)/qnrelay$(MODULE).service
	systemctl enable qnrelay$(MODULE).service
	systemctl daemon-reload
	systemctl start qnrelay$(MODULE).service

installmmdvm : $(MMPATH)/MMDVMHost $(MMPATH)/MMDVM$(MODULE).qn
	######### MMDVMHost #########
	/bin/ln -f $(MMPATH)/MMDVMHost $(BINDIR)/MMDVMHost$(MODULE)
	/bin/ln -s $(shell pwd)/$(MMPATH)/MMDVM$(MODULE).qn $(CFGDIR)
	sed -e "s/XXX/MMDVMHost$(MODULE)/" -e "s/YYY/MMDVM$(MODULE)/" system/mmdvm.service > $(SYSDIR)/mmdvm$(MODULE).service
	/bin/cp -f system/mmdvm.timer $(SYSDIR)/mmdvm$(MODULE).timer
	systemctl enable mmdvm$(MODULE).timer
	systemctl daemon-reload
	systemctl start mmdvm$(MODULE).service

installitap : qnitap
	######### QnetITAP #########
	/bin/ln -f qnitap $(BINDIR)/qnitap$(MODULE)
	sed -e "s/XXX/qnitap$(MODULE)/" system/qnitap.service > $(SYSDIR)/qnitap$(MODULE).service
	systemctl enable qnitap$(MODULE).service
	systemctl daemon-reload
	systemctl start qnitap$(MODULE).service

installmodem : qnmodem
	######### QnetModem #########
	/bin/ln -f qnmodem $(BINDIR)/qnmodem$(MODULE)
	sed -e "s/XXX/qnmodem$(MODULE)/" system/qnmodem.service > $(SYSDIR)/qnmodem$(MODULE).service
	systemctl enable qnmodem$(MODULE).service
	systemctl daemon-reload
	systemctl start qnmodem$(MODULE).service

installdvap : qndvap
	######### QnetDVAP #########
	/bin/ln -f qndvap $(BINDIR)/qndvap$(MODULE)
	sed -e "s/XXX/qndvap$(MODULE)/" system/qndvap.service > $(SYSDIR)/qndvap$(MODULE).service
	systemctl enable qndvap$(MODULE).service
	systemctl daemon-reload
	systemctl start qndvap$(MODULE).service

installdvrptr : qndvrptr
	######### QnetDVRPTR #########
	/bin/ln -f qndvrptr $(BINDIR)/qndvrptr$(MODULE)
	sed -e "s/XXX/qndvrptr$(MODULE)/" system/qndvrptr.service > $(SYSDIR)/qndvrptr$(MODULE).service
	systemctl enable qndvrptr$(MODULE).service
	systemctl daemon-reload
	systemctl start qndvrptr$(MODULE).service

installdtmf : qndtmf
	/bin/ln -s $(shell pwd)/qndtmf $(BINDIR)
	/bin/cp -f system/qndtmf.service $(SYSDIR)
	systemctl enable qndtmf.service
	systemctl daemon-reload
	systemctl start qndtmf.service

installdash :
	/usr/bin/apt-get -y install python3-pip
	/usr/bin/pip3 install libconf
	/bin/cp -f dash/qng-info.py $(BINDIR)
	/bin/cp -f dash/qngdash $(CRONDIR)
	/bin/sh /usr/bin/python3 $(BINDIR)/qng-info.py &

uninstallbase :
	######### QnetGateway #########
	systemctl stop qngateway.service
	systemctl disable qngateway.service
	/bin/rm -f $(SYSDIR)/qngateway.service
	/bin/rm -f $(BINDIR)/qngateway
	/bin/rm -f $(BINDIR)/qnremote
	/bin/rm -f $(BINDIR)/qnvoice
	/bin/rm -f $(CFGDIR)/qn.cfg
	/bin/rm -f $(CFGDIR)/defaults
	######### QnetLink #########
	systemctl stop qnlink.service
	systemctl disable qnlink.service
	/bin/rm -f $(SYSDIR)/qnlink.service
	/bin/rm -f $(BINDIR)/qnlink
	/bin/rm -f $(CFGDIR)/*.dat
	/bin/rm -f $(CFGDIR)/RPT_STATUS.txt
	/bin/rm -f $(CFGDIR)/gwys.txt
	/bin/rm -f $(CFGDIR)/exec_?.sh

uninstallrelay :
	######### QnetRelay #########
	systemctl stop qnrelay$(MODULE).service
	systemctl disable qnrelay$(MODULE).service
	/bin/rm -f $(SYSDIR)/qnrelay$(MODULE).service
	/bin/rm -f $(BINDIR)/qnrelay$(MODULE)
	systemctl daemon-reload

uninstallmmdvm :
	######### MMDVMHost ##########
	systemctl stop mmdvm$(MODULE).service
	systemctl disable mmdvm$(MODULE).timer
	/bin/rm -f $(SYSDIR)/mmdvm$(MODULE).service
	/bin/rm -f $(SYSDIR)/mmdvm$(MODULE).timer
	/bin/rm -f $(BINDIR)/MMDVMHost$(MODULE)
	/bin/rm -f $(CFGDIR)/MMDVM$(MODULE).qn
	sudo systemctl daemon-reload

uninstallmodem :
	######### QnetModem #########
	systemctl stop qnmodem$(MODULE).service
	systemctl disable qnmodem$(MODULE).service
	/bin/rm -f $(SYSDIR)/qnmodem$(MODULE).service
	/bin/rm -f $(BINDIR)/qnmodem$(MODULE)
	systemctl daemon-reload

uninstallitap :
	######### QnetITAP #########
	systemctl stop qnitap$(MODULE).service
	systemctl disable qnitap$(MODULE).service
	/bin/rm -f $(SYSDIR)/qnitap$(MODULE).service
	/bin/rm -f $(BINDIR)/qnitap$(MODULE)
	systemctl daemon-reload

uninstalldvap :
	######### QnetDVAP #########
	systemctl stop qndvap$(MODULE).service
	systemctl disable qndvap$(MODULE).service
	/bin/rm -f $(SYSDIR)/qndvap$(MODULE).service
	/bin/rm -f $(BINDIR)/qndvap$(MODULE)
	systemctl daemon-reload

uninstalldvrptr :
	######### QnetDVRPTR #########
	systemctl stop qndvrptr$(MODULE).service
	systemctl disable qndvrptr$(MODULE).service
	/bin/rm -f $(SYSDIR)/qndvrptr$(MODULE).service
	/bin/rm -f $(BINDIR)/qndvrptr$(MODULE)
	systemctl daemon-reload

uninstalldtmf :
	systemctl stop qndtmf.service
	systemctl disable qndtmf.service
	/bin/rm -f $(SYSDIR)/qndtmf.service
	systemctl daemon-reload
	/bin/rm -f $(BINDIR)/qndtmf

uninstalldash :
	/bin/rm -f $(SYSDIR)/qng-info.py
	/bin/rm -f $(CRONDIR)/qngdash
	/usr/bin/pkill python3
