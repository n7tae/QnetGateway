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
PROGRAMS=g2_ircddb g2_link dvap_rptr dvrptr g2link_test g2link_test_audio mmdvm_modem

all : $(PROGRAMS)

g2_ircddb : $(IRCOBJS) g2_ircddb.o aprs.o
	g++ $(CPPFLAGS) -o g2_ircddb g2_ircddb.o aprs.o $(IRCOBJS) $(LDFLAGS) -pthread

g2_link : g2_link.o
	g++ $(CPPFLAGS) -o g2_link g2_link.o $(LDFLAGS) -pthread

mmdvm_modem : mmdvm_modem.o UDPSocket.o
	g++ $(CPPFLAGS) -o mmdvm_modem mmdvm_modem.o UDPSocket.o $(LDFLAGS)

dvap_rptr : dvap_rptr.o DVAPDongle.o $(DSTROBJS)
	g++ $(CPPFLAGS) -o dvap_rptr dvap_rptr.o DVAPDongle.o $(DSTROBJS) $(LDFLAGS) -pthread

dvrptr : dvrptr.o $(DSTROBJS)
	g++ $(CPPFLAGS) -o dvrptr dvrptr.o $(DSTROBJS) $(LDFLAGS)

g2link_test : g2link_test.o
	g++ $(CPPFLAGS) -o g2link_test g2link_test.o  -lrt

g2link_test_audio : g2link_test_audio.o
	g++ $(CPPFLAGS) -o g2link_test_audio g2link_test_audio.o  -lrt

%.o : %.cpp
	g++ $(CPPFLAGS) -MMD -MD -c $< -o $@

.PHONY: clean

clean:
	$(RM) $(OBJS) $(DEPS) $(PROGRAMS)

-include $(DEPS)

installdvap : dvap_rptr g2_link g2_ircddb
	######### g2_ircddb #########
	/bin/cp -f g2_ircddb $(BINDIR)
	/bin/cp -f g2.cfg $(CFGDIR)
	/bin/cp -f service.g2_ircddb /etc/init.d/g2_ircddb
#	/usr/sbin/update-rc.d g2_ircddb defaults
#	/usr/sbin/update-rc.d g2_ircddb enable
	######### g2_link #########
	/bin/cp -f g2_link $(BINDIR)
	/bin/cp -f announce/*.dat $(CFGDIR)
	/bin/cp -f gwys.txt $(CFGDIR)
	/bin/cp -f exec_?.sh $(CFGDIR)
	/bin/cp -f service.g2_link /etc/init.d/g2_link
#	/usr/sbin/update-rc.d g2_link defaults
#	/usr/sbin/update-rc.d g2_link enable
	######### dvap_rptr #########
	/bin/cp -f dvap_rptr $(BINDIR)
	/bin/cp -f dvap_rptr.sh $(BINDIR)
	/bin/cp -f service.dvap_rptr /etc/init.d/dvap_rptr
#	/usr/sbin/update-rc.d dvap_rptr defaults
#	/usr/sbin/update-rc.d dvap_rptr enable

installdvrptr : dvrptr g2_link g2_ircddb
	######### g2_ircddb #########
	/bin/cp -f g2_ircddb $(BINDIR)
	/bin/cp -f g2.cfg $(CFGDIR)
	/bin/cp -f service.g2_ircddb /etc/init.d/g2_ircddb
#	/usr/sbin/update-rc.d g2_ircddb defaults
#	/usr/sbin/update-rc.d g2_ircddb enable
	######### g2_link #########
	/bin/cp -f g2_link $(BINDIR)
	/bin/cp -f announce/*.dat $(CFGDIR)
	/bin/cp -f gwys.txt $(CFGDIR)
	/bin/cp -f exec_?.sh $(CFGDIR)
	/bin/cp -f service.g2_link /etc/init.d/g2_link
#	/usr/sbin/update-rc.d g2_link defaults
#	/usr/sbin/update-rc.d g2_link enable
	######### dvrptr ##########
	/bin/cp -f dvrptr $(BINDIR)
	/bin/cp -f dvrptr.sh $(BINDIR)
	/bin/cp -f service.dvrptr /etc/init.d/dvrptr
#	/usr/sbin/update-rc.d dvrptr defaults
#	/usr/sbin/update-rc.d dvrptr enable

installdtmfs : g2link_test
	/bin/cp -f g2link_test $(BINDIR)
	/bin/cp -f proc_g2_ircddb_dtmfs.sh $(BINDIR)
	/bin/cp -f service.proc_g2_ircddb_dtmfs /etc/init.d/proc_g2_ircddb_dtmfs
#	/usr/sbin/update-rc.d proc_g2_ircddb_dtmfs defaults
#	/usr/sbin/update-rc.d proc_g2_ircddb_dtmfs enable

uninstalldtmfs:
#	/usr/sbin/service proc_g2_ircddb_dtmfs stop
#	/bin/rm -f /etc/init.d/proc_g2_ircddb_dtmfs
#	/usr/sbin/update-rc.d proc_g2_ircddb_dtmfs remove
	/bin/rm -f $(BINDIR)/proc_g2_ircddb_dtmfs.sh
	/bin/rm -f $(BINDIR)/g2link_test

uninstalldvap :
	######### g2_ircddb #########
#	/usr/sbin/service g2_ircddb stop
#	/bin/rm -f /etc/init.d/g2_ircddb
#	/usr/sbin/update-rc.d g2_ircddb remove
	/bin/rm -f $(BINDIR)/g2_ircddb
	/bin/rm -f $(CFGDIR)/g2.cfg
	######### g2_link #########
#	/usr/sbin/service g2_link stop
#	/bin/rm -f /etc/init.d/g2_link
#	/usr/sbin/update-rc.d g2_link remove
	/bin/rm -f $(BINDIR)/g2_link
	/bin/rm -f $(CFGDIR)/already_linked.dat
	/bin/rm -f $(CFGDIR)/already_unlinked.dat
	/bin/rm -f $(CFGDIR)/failed_linked.dat
	/bin/rm -f $(CFGDIR)/id.dat
	/bin/rm -f $(CFGDIR)/linked.dat
	/bin/rm -f $(CFGDIR)/unlinked.dat
	/bin/rm -f $(CFGDIR)/RPT_STATUS.txt
	/bin/rm -f $(CFGDIR)/gwys.txt
	/bin/rm -f $(CFGDIR)/exec_?.sh
	/bin/rm -f /var/log/g2_link.log
	######### dvap_rptr #########
#	/usr/sbin/service dvap_rptr stop
#	/bin/rm -f /etc/init.d/dvap_rptr
#	/usr/sbin/update-rc.d dvap_rptr remove
#	/bin/rm -f $(BINDIR)/dvap_rptr
#	/bin/rm -f $(BINDIR)/dvap_rptr.sh

uninstalldvrptr:
	######### g2_ircddb #########
#	/usr/sbin/service g2_ircddb stop
#	/bin/rm -f /etc/init.d/g2_ircddb
#	/usr/sbin/update-rc.d g2_ircddb remove
#	/bin/rm -f $(BINDIR)/g2_ircddb
#	/bin/rm -f $(CFGDIR)/g2.cfg
	######### g2_link #########
#	/usr/sbin/service g2_link stop
#	/bin/rm -f /etc/init.d/g2_link
#	/usr/sbin/update-rc.d g2_link remove
	/bin/rm -f $(BINDIR)/g2_link
	/bin/rm -f $(CFGDIR)/already_linked.dat
	/bin/rm -f $(CFGDIR)/already_unlinked.dat
	/bin/rm -f $(CFGDIR)/failed_linked.dat
	/bin/rm -f $(CFGDIR)/id.dat
	/bin/rm -f $(CFGDIR)/linked.dat
	/bin/rm -f $(CFGDIR)/unlinked.dat
	/bin/rm -f $(CFGDIR)/RPT_STATUS.txt
	/bin/rm -f $(CFGDIR)/gwys.txt
	/bin/rm -f $(CFGDIR)/exec_?.sh
	/bin/rm -f /var/log/g2_link.log
	######### dvrptr ##########
#	/usr/sbin/service dvrptr stop
#	/bin/rm -f /etc/init.d/dvrptr
#	/usr/sbin/update-rc.d dvrtpr remove
	/bin/rm -f $(BINDIR)/dvrptr
	/bin/rm -f $(BINDIR)/dvrptr.sh
