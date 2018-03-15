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
#

# locations for the executibles and other files are set here
# NOTE: IF YOU CHANGE THESE, YOU WILL NEED TO UPDATE THE service.* FILES AND
# SOME OF THE *.sh FILES TOO!
BINDIR=/usr/local/bin
CFGDIR=/usr/local/etc
LOGDIR=/var/log

CPPFLAGS=-W -Wall -I/usr/include -std=c++11
LDFLAGS=-L/usr/lib -lconfig++

PROGRAMS=g2_ircddb g2_link dvap_rptr dvrptr g2link_test g2link_test_audio

IRCDDBOBJS = IRCDDB.o IRCClient.o IRCReceiver.o IRCMessageQueue.o IRCProtocol.o IRCMessage.o IRCDDBApp.o IRCutils.o golay23.o dstar_dv.o aprs.o

all : $(PROGRAMS)

g2_ircddb : g2_ircddb.cpp $(IRCDDBOBJS) aprs.h g2_typedefs.h versions.h g2_ircddb.h
	g++ $(CPPFLAGS) -o g2_ircddb g2_ircddb.cpp $(IRCDDBOBJS) $(LDFLAGS) -pthread

g2_link : g2_link.cpp versions.h
	g++ $(CPPFLAGS) -o g2_link g2_link.cpp -lrt -lconfig++ -pthread

dvap_rptr : dvap_rptr.cpp DVAPDongle.o dstar_dv.o golay23.o DVAPDongle.h g2_typedefs.h versions.h
	g++ $(CPPFLAGS) -o dvap_rptr  dvap_rptr.cpp  DVAPDongle.o golay23.o dstar_dv.o -I/usr/include -L/usr/lib -lrt -lconfig++ -pthread

dvrptr : dvrptr.cpp dstar_dv.o golay23.o
	g++ $(CPPFLAGS) -o dvrptr  dvrptr.cpp golay23.o dstar_dv.o  -I/usr/include -L/usr/lib -lconfig++ -lrt

IRCutils.o : IRCutils.cpp IRCutils.h
	g++ -c $(CPPFLAGS) IRCutils.cpp

IRCDDB.o : IRCDDB.cpp IRCDDB.h IRCutils.h
	g++ -c $(CPPFLAGS) IRCDDB.cpp

IRCClient.o : IRCClient.cpp IRCClient.h IRCutils.h
	g++ -c $(CPPFLAGS) IRCClient.cpp

IRCReceiver.o : IRCReceiver.cpp IRCReceiver.h IRCMessageQueue.h IRCutils.h
	g++ -c $(CPPFLAGS) IRCReceiver.cpp

IRCMessageQueue.o : IRCMessageQueue.cpp IRCMessageQueue.h IRCMessage.h
	g++ -c $(CPPFLAGS) IRCMessageQueue.cpp

IRCProtocol.o : IRCProtocol.cpp IRCProtocol.h IRCutils.h
	g++ -c $(CPPFLAGS) IRCProtocol.cpp

IRCMessage.o : IRCMessage.cpp IRCMessage.h
	g++ -c $(CPPFLAGS) IRCMessage.cpp

IRCDDBApp.o : IRCDDBApp.cpp IRCDDBApp.h IRCutils.h
	g++ -c $(CPPFLAGS) IRCDDBApp.cpp

aprs.o : aprs.cpp aprs.h
	g++ -c $(CPPFLAGS) aprs.cpp

DVAPDongle.o : DVAPDongle.cpp DVAPDongle.h
	g++ -c $(CPPFLAGS) DVAPDongle.cpp

golay23.o : golay23.cpp golay23.h
	g++ -c $(CPPFLAGS) golay23.cpp

dstar_dv.o : dstar_dv.cpp dstar_dv.h golay23.h
	g++ -c $(CPPFLAGS) dstar_dv.cpp

g2link_test : g2link_test.cpp
	g++ $(CPPFLAGS) -o g2link_test g2link_test.cpp  -lrt

g2link_test_audio : g2link_test_audio.cpp
	g++ $(CPPFLAGS) -o g2link_test_audio g2link_test_audio.cpp  -lrt

IRCApplication.h : IRCMessageQueue.h
IRCClient.h : IRCReceiver.h IRCMessageQueue.h IRCProtocol.h IRCApplication.h
IRCDDBApp.h : IRCDDB.h IRCApplication.h
IRCMessageQueue.h : IRCMessage.h
IRCProtocol.h : IRCMessageQueue.h IRCApplication.h
IRCReceiver.h : IRCMessageQueue.h

clean :
	/bin/rm -f *.o

realclean :
	/bin/rm -f *.o $(PROGRAMS)

installdvap : dvap_rptr g2_link g2_ircddb
	######### g2_ircddb #########
	/bin/cp -f g2_ircddb $(BINDIR)
	/bin/cp -f g2.cfg $(CFGDIR)
	/bin/cp -f service.g2_ircddb /etc/init.d/g2_ircddb
	/usr/sbin/update-rc.d g2_ircddb defaults
	/usr/sbin/update-rc.d g2_ircddb enable
	######### g2_link #########
	/bin/cp -f g2_link $(BINDIR)
	/bin/cp -f announce/*.dat $(CFGDIR)
	/bin/cp -f gwys.txt $(CFGDIR)
	/bin/cp -f exec_?.sh $(CFGDIR)
	/bin/cp -f service.g2_link /etc/init.d/g2_link
	/usr/sbin/update-rc.d g2_link defaults
	/usr/sbin/update-rc.d g2_link enable
	######### dvap_rptr #########
	/bin/cp -f dvap_rptr $(BINDIR)
	/bin/cp -f dvap_rptr.sh $(BINDIR)
	/bin/cp -f service.dvap_rptr /etc/init.d/dvap_rptr
	/usr/sbin/update-rc.d dvap_rptr defaults
	/usr/sbin/update-rc.d dvap_rptr enable

installdvrptr : dvrptr g2_link g2_ircddb
	######### g2_ircddb #########
	/bin/cp -f g2_ircddb $(BINDIR)
	/bin/cp -f g2.cfg $(CFGDIR)
	/bin/cp -f service.g2_ircddb /etc/init.d/g2_ircddb
	/usr/sbin/update-rc.d g2_ircddb defaults
	/usr/sbin/update-rc.d g2_ircddb enable
	######### g2_link #########
	/bin/cp -f g2_link $(BINDIR)
	/bin/cp -f announce/*.dat $(CFGDIR)
	/bin/cp -f gwys.txt $(CFGDIR)
	/bin/cp -f exec_?.sh $(CFGDIR)
	/bin/cp -f service.g2_link /etc/init.d/g2_link
	/usr/sbin/update-rc.d g2_link defaults
	/usr/sbin/update-rc.d g2_link enable
	######### dvrptr ##########
	/bin/cp -f dvrptr $(BINDIR)
	/bin/cp -f dvrptr.sh $(BINDIR)
	/bin/cp -f service.dvrptr /etc/init.d/dvrptr
	/usr/sbin/update-rc.d dvrptr defaults
	/usr/sbin/update-rc.d dvrptr enable

installdtmfs : g2link_test
	/bin/cp -f g2link_test $(BINDIR)
	/bin/cp -f proc_g2_ircddb_dtmfs.sh $(BINDIR)
	/bin/cp -f service.proc_g2_ircddb_dtmfs /etc/init.d/proc_g2_ircddb_dtmfs
	/usr/sbin/update-rc.d proc_g2_ircddb_dtmfs defaults
	/usr/sbin/update-rc.d proc_g2_ircddb_dtmfs enable

uninstalldtmfs:
	/usr/sbin/service proc_g2_ircddb_dtmfs stop
	/bin/rm -f /etc/init.d/proc_g2_ircddb_dtmfs
	/usr/sbin/update-rc.d proc_g2_ircddb_dtmfs remove
	/bin/rm -f $(BINDIR)/proc_g2_ircddb_dtmfs.sh
	/bin/rm -f $(BINDIR)/g2link_test

uninstalldvap :
	######### g2_ircddb #########
	/usr/sbin/service g2_ircddb stop
	/bin/rm -f /etc/init.d/g2_ircddb
	/usr/sbin/update-rc.d g2_ircddb remove
	/bin/rm -f $(BINDIR)/g2_ircddb
	/bin/rm -f $(CFGDIR)/g2.cfg
	######### g2_link #########
	/usr/sbin/service g2_link stop
	/bin/rm -f /etc/init.d/g2_link
	/usr/sbin/update-rc.d g2_link remove
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
	/usr/sbin/service dvap_rptr stop
	/bin/rm -f /etc/init.d/dvap_rptr
	/usr/sbin/update-rc.d dvap_rptr remove
	/bin/rm -f $(BINDIR)/dvap_rptr
	/bin/rm -f $(BINDIR)/dvap_rptr.sh

uninstalldvrptr:
	######### g2_ircddb #########
	/usr/sbin/service g2_ircddb stop
	/bin/rm -f /etc/init.d/g2_ircddb
	/usr/sbin/update-rc.d g2_ircddb remove
	/bin/rm -f $(BINDIR)/g2_ircddb
	/bin/rm -f $(CFGDIR)/g2.cfg
	######### g2_link #########
	/usr/sbin/service g2_link stop
	/bin/rm -f /etc/init.d/g2_link
	/usr/sbin/update-rc.d g2_link remove
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
	/usr/sbin/service dvrptr stop
	/bin/rm -f /etc/init.d/dvrptr
	/usr/sbin/update-rc.d dvrtpr remove
	/bin/rm -f $(BINDIR)/dvrptr
	/bin/rm -f $(BINDIR)/dvrptr.sh
