#!/bin/sh
qnvoice ${2} rebooting.dat 'System Reboot'
sleep 5
shutdown -r now
