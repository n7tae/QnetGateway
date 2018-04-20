QnetGateway
===========

The QnetGateway is an D-Star IRCDDB gateway application that supports MMDVMHost (and all of its supported repeater modems) as well as the DVAP Dongle and the DVRPTR_V1. It is *incredibly easy* to build and install the system.

For building a QnetGateway + MMDVMHost system, see the MMDVM.README file. To build QnetGateway that uses a DVAP Dongle or DVRPTR V1, see the BUILDING file.

To get started, clone the software to your Linux device:

```
git clone git://github.com/n7tae/QnetGateway.git
```

Then look to the MMDVM.README or the BUILDING file for more information.

For details of interesting things QnetGatway can do, see the CONFIGURING file. For example, with QnetGateway, you can execute up to 36 different Linux scripts from you radio. Two scripts are include:

```
YourField = _ _ _ _ _ _ H X   will halt your system.
YourField = _ _ _ _ _ _ R X   will reboot your system.
```

QnetGateway is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation. QnetGateway is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the LICENSE file for more details.

Many thanks go to **Colby W1BSB**, **Will W4WWM** and **Carty KA2Y** for recent help, suggestions, discussion and criticisms of the Qnet*/MMDVMHost phase of this long-term project! Also thanks to Jonathan G4KLX for MMDVMHost. It gave QnetGateway access to a large number of D-Star compatible modems!

Finally, QnetGateway is brought to you by the folks at **QuadNet2 USA IRC Network**, but it should work on *any* IRCDDB network.

73

Tom

N7TAE (at) arrl (dot) net
