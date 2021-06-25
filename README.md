QnetGateway
===========

The QnetGateway is an D-Star IRCDDB gateway application that supports MMDVMHost (and all of its supported repeater modems) as well as the DVAP Dongle, the DVRPTR_V1. It is *incredibly easy* to build and install the system.

QnetGateway now includes a dashboard with a last heard section. The lastheard section uses SQLite3, a light-weight database, so you will need a package to compile the gateway:

```bash
sudo apt install libsqlite3-dev
```

QnetGateway is dual-stack capable. This means it can simultaneously connect to ircv4.openquad.net, which is IPv4 based (using 32-bit internet addresses) and to ircv6.openquad.net which is IPv6 based (using 128-bit internet address). If your hot-spot/reapeater has IPv6 access you can enable dual-stack operation (it's IPv4-only by default) and then take advantage of direct world-routable address. The potential benefit of IPv6 to routing is significant.

The QnetGateway program includes support for Icom's Terminal Mode and Access Point mode. For more information, Terminal Mode turns off the RF portion of you radio and just uses the AMBE vocoder to convert between audio and AMBE data and then sends and receives that data through a USB serial cable. Access Point mode turns your Icom radio into a high power, simplex hot-spot.

QnetGateway supports MMDVM modems directly, without the need for MMDVMHost. This is for hams that want to use their MMDVM devices and create a hot-spot for D-Star mode only. (You still can talk to your friends on other modes by gathering at multi-mode reflectors, like the QuadNet Array!)

For building a QnetGateway + MMDVMHost system, see the MMDVM.README file. To build QnetGateway that uses a DVAP Dongle or DVRPTR V1, see the CONFIG+INSTALL file. To build QnetGateway for an Icom Repeater Stack, I have another repo at QnetIcomGateway. Detailed information is available there.

To get started with an MMDVM-modem, DVAP, DVRPTR or Icom Terminal and/or Access Point system, clone this software to your Linux device:

```bash
git clone git://github.com/n7tae/QnetGateway.git
```

Then look to the MMDVM.README or the CONFIG+INSTALL file for more information.

QnetGateway includes a "remote control" program, called `qnremote`. After you build and install the system, type `qnremote` for a prompt on how to use it. Using this and cron, it's possible to setup schedules where you system will automatically link up to a reflector, or subscribe to a Routing Group. For More information, see DTMF+REMOTE.README.

For other details of interesting things QnetGatway can do, see the OPERATING file. For example, with QnetGateway, you can execute up to 36 different Linux scripts from you radio. Two scripts are include:

```text
YourCall = "      HX"   will halt your system.
YourCall = "      RX"   will reboot your system.
YourCall - "      GX"   will restart QnetGateway
```

QnetGateway is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation. QnetGateway is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the LICENSE file for more details.

Many thanks go to **Colby W1BSB**, **Will W4WWM** and **Carty KA2Y** for recent help, suggestions, discussion and criticisms of the Qnet*/MMDVMHost phase of this long-term project! Also thanks to Jonathan G4KLX for MMDVMHost. It gave QnetGateway access to a large number of D-Star compatible modems!

Finally, QnetGateway is brought to you by the folks at **QuadNet2 USA IRC Network**, but it should work on *any* IRCDDB network.

73

Tom

N7TAE (at) arrl (dot) net
