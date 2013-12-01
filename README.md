g2_ircddb
=========

g2_ircddb source package with easy to use Makefile based on KI4LKF open source software. Needs Debian-based OS.

Here is the short and sweet to get a DVAP hotspot up and running.

./build_wxBase          # build and install wxBase, needed for g2_ircddb

make                    # build g2_ircddb, g2_link and dvap_rptr

vi *.cfg                # edit the all the configuration files
                        # any text editor will work
sudo make install       # installs everything

sudo reboot             # the three services should be up and running after reboot
                        # running logs are in /var/log

For much more details, see CONFIGURING and BUILDING.

Tom Early, ac2ie@arrl.net
