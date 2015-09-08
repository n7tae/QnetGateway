g2_ircddb
=========

NEW! Software configuration is SIGNIFICANTLY easier because most parameters now have default values. Most hams will only need to define a few things.

PRETTY NEW: g2_ircddb has come up to current practices when it comes to ":IRCDDB" irc commands. This means irc hosts like rr.openquad.net can list your repeater frequency, offset, location and URL automatically if you want.

This package is for making a ircddb gateway based on Scott Lawson KI4LKF g2_ircddb gateway software.

Two repeater devices are supported so far: the DVAP dongle (http://www.dvapdongle.com) and the dvrptr V1 (http://www.dvrptr.net).

Creating a portable ircddb hotspot based on a Raspberry Pi or a BeagleBone Black that can connect to DStar reflectors, XREF reflectors and DCS reflectors based on this software is easy.

As configured, this software requires a Debian or Debian-based Linux OS and works very well on a Raspberry Pi (http://raspberrypi.org) on Raspbian Liunx or a BeagleBone Black (http://beagleboard.org) running Debian Linux. Depending on your knowledge with your choice of OS, you can probably get this to work on others as well. The closer you are to a Debian base, the easier it will be.

Start with a Raspberry Pi with the latest Raspbian image (see http://raspberrypi.org) or a BeagleBone Black with the latest Debian image (see http://www.armhf.com). This software will EASILY fit on the 2gb on-board memory of the older Rev. B of the BBB, but you will still need a uSD card to install the armhf.com Debian image to the on-board memory. If you are using Raspbian on a RasPi, be sure to configure Raspbian with the `sudo raspi-config` command. If you are using Debian on a BBB, be sure to look over the notes on expanding the uSD memory on the www.armhf.com website.

You can also use the new Debian images on BeagleBone.org. New BBBs (with the 4gb on-board memory) are now shipping with Debian instead of Angstrom and g2_ircddb will compile and install just fine on this Debian image. However, right now (late June 2014) there are still some minor bugs in this package, e.g., `halt` in a ssh shell will hang the shell. Hopefully, `sudo apt-get upgrade` will eventually fix this.

You will need several packages to build software. The RasPi will probably have most of these but it still doesn't hurt to be sure:

```
sudo apt-get update
sudo apt-get upgrade
sudo apt-get install make g++ unzip git libconfig++-dev
```

and maybe a few more of your favorite packages. Here is one of my favorites: `sudo apt-get install avahi-daemon`. Then you can `ssh user@hostname.local` instead of `ssh user@ip_address`.

After you install all the required packages, the g2_ircddb gateway installation can begin. Go to your login home directory and (without root privileges) type:
```
git clone git://github.com/ac2ie/g2_ircddb.git
```
Then cd into the new g2_ircddb directory and review the `BUILDING` and `CONFIGURING` file for further instructions, here is an outline:
```
Build the wxWidgets library.
Make the g2 modules.
Edit the configuration file, g2.cfg.
Download the latest gateway list, gwys.txt.
Install g2.
Reboot and enjoy!
```

73

Tom

AC2IE (at) arrl (dot) net
