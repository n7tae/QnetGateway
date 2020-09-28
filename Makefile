# Copyright (c) 2018-2020 by Thomas A. Early N7TAE
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
# you will also break hard coded paths in the dashboard file, index.php.

BINDIR=/usr/local/bin
CFGDIR=/usr/local/etc
WWWDIR=/usr/local/www
MMPATH=../MMDVMHost
DMRPATH=../DMRGateway
YSFPATH=../YSFClients/YSFGateway
APRSPATH=../APRSGateway
SYSDIR=/lib/systemd/system
IRC=ircddb

# use this if you want debugging help in the case of a crash
#CPPFLAGS=-ggdb -W -std=c++11 -Iircddb -DCFG_DIR=\"$(CFGDIR)\" -DBIN_DIR=\"$(BINDIR)\"

# or, you can choose this for a much smaller executable without debugging help
CPPFLAGS=-W -std=c++11 -Iircddb -DCFG_DIR=\"$(CFGDIR)\" -DBIN_DIR=\"$(BINDIR)\"

LDFLAGS=-L/usr/lib -lrt

IRCOBJS = $(IRC)/IRCDDB.o $(IRC)/IRCClient.o $(IRC)/IRCReceiver.o $(IRC)/IRCMessageQueue.o $(IRC)/IRCProtocol.o $(IRC)/IRCMessage.o $(IRC)/IRCDDBApp.o $(IRC)/IRCutils.o
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

qngateway : QnetGateway.o KRBase.o aprs.o UnixDgramSocket.o UnixPacketSock.o TCPReaderWriterClient.o QnetConfigure.o QnetDB.o CacheManager.o DStarDecode.o Location.o $(IRCOBJS)
	g++ -o $@ $^ $(LDFLAGS) -l sqlite3 -pthread

qnlink : QnetLink.o KRBase.o DPlusAuthenticator.o TCPReaderWriterClient.o UnixPacketSock.o UDPSocket.o QnetConfigure.o QnetDB.o
	g++ -o $@ $^ $(LDFLAGS) -l sqlite3 -pthread

qnrelay : QnetRelay.o KRBase.o UnixPacketSock.o QnetConfigure.o
	g++ -o $@ $^ $(LDFLAGS)

qnitap : QnetITAP.o KRBase.o UnixPacketSock.o QnetConfigure.o
	g++ -o $@ $^ $(LDFLAGS)

qnmodem : QnetModem.o KRBase.o UnixPacketSock.o QnetConfigure.o
	g++ -o $@ $^ $(LDFLAGS)

qndvap : QnetDVAP.o KRBase.o DVAPDongle.o UnixPacketSock.o QnetConfigure.o DStarDecode.o
	g++ -o $@ $^ $(LDFLAGS) -pthread

qndvrptr : QnetDVRPTR.o KRBase.o UnixPacketSock.o QnetConfigure.o DStarDecode.o
	g++ -o $@ $^ $(LDFLAGS)

qnremote : QnetRemote.o UnixDgramSocket.o QnetConfigure.o
	g++ -o $@ $^ $(LDFLAGS)

qnvoice : QnetVoice.o QnetConfigure.o
	g++ -o $@ $^ $(LDFLAGS)

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
	/bin/ln -f -s $(shell pwd)/qn.cfg $(CFGDIR)
	/bin/ln -f -s $(shell pwd)/index.php $(WWWDIR)
	/bin/ln -f -s $(shell pwd)/dashboardV2 $(WWWDIR)
	/bin/cp -f defaults $(CFGDIR)
	/bin/cp -f system/qngateway.service $(SYSDIR)
	systemctl enable qngateway.service
	systemctl daemon-reload
	systemctl start qngateway.service
	######### QnetLink #########
	/bin/cp -f qnlink $(BINDIR)
	/bin/cp -f announce/*.dat $(CFGDIR)
	/bin/ln -f -s $(shell pwd)/gwys.txt $(CFGDIR)
	/bin/cp -f exec_?.sh $(BINDIR)
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
	/bin/ln -f -s $(shell pwd)/$(MMPATH)/MMDVM$(MODULE).qn $(CFGDIR)
	sed -e "s/XXX/MMDVMHost$(MODULE)/" -e "s/YYY/MMDVM$(MODULE)/" system/mmdvm.service > $(SYSDIR)/mmdvm$(MODULE).service
	/bin/cp -f system/mmdvm.timer $(SYSDIR)/mmdvm$(MODULE).timer
	systemctl enable mmdvm$(MODULE).timer
	systemctl daemon-reload
	systemctl start mmdvm$(MODULE).service

installdmr : $(DMRPATH)/DMRGateway $(DMRPATH)/DMRGateway$(MODULE).qn
	######### DMRGateway #########
	/bin/ln -f $(DMRPATH)/DMRGateway $(BINDIR)/DMRGateway$(MODULE)
	/bin/ln -f -s $(shell pwd)/$(DMRPATH)/DMRGateway$(MODULE).qn $(CFGDIR)
	sed -e "s/XXX/DMRGateway$(MODULE)/" -e "s/YYY/DMRGateway$(MODULE)/" system/mmdvm.service > $(SYSDIR)/dmrgateway$(MODULE).service
	/bin/cp -f system/gateway.timer $(SYSDIR)/dmrgateway$(MODULE).timer
	systemctl enable dmrgateway$(MODULE).timer
	systemctl daemon-reload
	systemctl start dmrgateway$(MODULE).service

installysf : $(YSFPATH)/YSFGateway $(YSFPATH)/YSFGateway$(MODULE).qn
	######### YSFGateway #########
	/bin/ln -f $(YSFPATH)/YSFGateway $(BINDIR)/YSFGateway$(MODULE)
	/bin/ln -f -s $(shell pwd)/$(YSFPATH)/YSFGateway$(MODULE).qn $(CFGDIR)
	sed -e "s/XXX/YSFGateway$(MODULE)/" -e "s/YYY/YSFGateway$(MODULE)/" system/mmdvm.service > $(SYSDIR)/ysfgateway$(MODULE).service
	/bin/cp -f system/gateway.timer $(SYSDIR)/ysfgateway$(MODULE).timer
	systemctl enable ysfgateway$(MODULE).timer
	systemctl daemon-reload
	systemctl start ysfgateway$(MODULE).service

installaprs : $(APRSPATH)/APRSGateway $(APRSPATH)/APRSGateway.qn
	######### APRSGateway #########
	/bin/cp -f $(APRSPATH)/APRSGateway $(BINDIR)
	/bin/ln -f -s $(shell pwd)/$(APRSPATH)/APRSGateway.qn $(CFGDIR)
	sed -e "s/XXX/APRSGateway/" -e "s/YYY/APRSGateway/" system/mmdvm.service > $(SYSDIR)/aprsgateway.service
	/bin/cp -f system/gateway.timer $(SYSDIR)/aprsgateway.timer
	systemctl enable aprsgateway.timer
	systemctl daemon-reload
	systemctl start aprsgateway.service

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
	/bin/ln -f -s $(shell pwd)/qndtmf $(BINDIR)
	/bin/cp -f system/qndtmf.service $(SYSDIR)
	systemctl enable qndtmf.service
	systemctl daemon-reload
	systemctl start qndtmf.service

installdash : index.php
	/usr/bin/apt update
	/usr/bin/apt install -y php-common php-fpm sqlite3 php-sqlite3
	mkdir -p $(WWWDIR)
	mkdir -p dashboardV2/jsonData
	/bin/ln -f -s $(shell pwd)/index.php $(WWWDIR)
	/bin/ln -f -s $(shell pwd)/dashboardV2 $(WWWDIR)
	/bin/cp -f system/qndash.service $(SYSDIR)
	systemctl enable qndash.service
	systemctl daemon-reload
	systemctl start qndash.service

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
	/bin/rm -f $(CFGDIR)/qn.db
	/bin/rm -f $(CFGDIR)/gwys.txt
	/bin/rm -f $(BINDIR)/exec_?.sh

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

uninstalldmr :
	######### DMRGateway ##########
	systemctl stop dmrgateway$(MODULE).service
	systemctl disable dmrgateway$(MODULE).timer
	/bin/rm -f $(SYSDIR)/dmrgateway$(MODULE).service
	/bin/rm -f $(SYSDIR)/dmrgateway$(MODULE).timer
	/bin/rm -f $(BINDIR)/DMRGateway$(MODULE)
	/bin/rm -f $(CFGDIR)/DMRGateway$(MODULE).qn
	sudo systemctl daemon-reload

uninstallysf :
	######### YSFGateway ##########
	systemctl stop ysfgateway$(MODULE).service
	systemctl disable ysfgateway$(MODULE).timer
	/bin/rm -f $(SYSDIR)/ysfgateway$(MODULE).service
	/bin/rm -f $(SYSDIR)/ysfgateway$(MODULE).timer
	/bin/rm -f $(BINDIR)/YSFGateway$(MODULE)
	/bin/rm -f $(CFGDIR)/YSFGateway$(MODULE).qn
	sudo systemctl daemon-reload

uninstallaprs :
	######### APRSGateway ##########
	systemctl stop aprsgateway.service
	systemctl disable aprsgateway.timer
	/bin/rm -f $(SYSDIR)/aprsgateway.service
	/bin/rm -f $(SYSDIR)/aprsgateway.timer
	/bin/rm -f $(BINDIR)/APRSGateway
	/bin/rm -f $(CFGDIR)/APRSGateway.qn
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
	systemctl stop qndash.service
	systemctl disable qndash.service
	/bin/rm -f $(SYSDIR)/qndash.service
	systemctl daemon-reload
	/bin/rm -f $(WWWDIR)/index.php
	/bin/rm -f $(WWWDIR)/dashboardV2
	/bin/rm -f $(CFGDIR)/qn.db
	/bin/rm -rf dashboardV2/jsonData
