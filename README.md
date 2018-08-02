QnetGateway
===========

The QnetGateway is an D-Star IRCDDB gateway application that supports MMDVMHost (and all of its supported repeater modems) as well as the DVAP Dongle, the DVRPTR_V1 and now the Icom repeater. It is *incredibly easy* to build and install the system.

The Qnet Gateway program now includes support for Icom's new Terminal mode. Access Point mode is still having some performance issues and we will be working on this. For more information, please read the ITAP.README file.

For building a QnetGateway + MMDVMHost system, see the MMDVM.README file. To build QnetGateway that uses a DVAP Dongle or DVRPTR V1, see the BUILDING file.

To get started, clone the software to your Linux device:

```
git clone git://github.com/n7tae/QnetGateway.git
```

Then look to the MMDVM.README or the BUILDING file for more information.

QnetGateway includes a "remote control" program, called `qnremote`. After you build and install the system, type `qnremote` for a prompt on how to use it. Using this and cron, it's possible to setup schedules where you system will automatically link up to a reflector, or subscribe to a Routing Group. For More information, see DTMF+REMOTE.README.

For other details of interesting things QnetGatway can do, see the CONFIGURING file. For example, with QnetGateway, you can execute up to 36 different Linux scripts from you radio. Two scripts are include:

```
YourCall = "      HX"   will halt your system.
YourCall = "      RX"   will reboot your system.
```

QnetGateway is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation. QnetGateway is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the LICENSE file for more details.

Many thanks go to **Colby W1BSB**, **Will W4WWM** and **Carty KA2Y** for recent help, suggestions, discussion and criticisms of the Qnet*/MMDVMHost phase of this long-term project! Also thanks to Jonathan G4KLX for MMDVMHost. It gave QnetGateway access to a large number of D-Star compatible modems!

Finally, QnetGateway is brought to you by the folks at **QuadNet2 USA IRC Network**, but it should work on *any* IRCDDB network.

73

Tom

N7TAE (at) arrl (dot) net
