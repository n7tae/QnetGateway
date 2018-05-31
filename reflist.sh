#!/bin/bash

wget ftp://dschost1.w6kd.com/DExtra_Hosts.txt || wget ftp://dschost2.w6kd.com/DExtra_Hosts.txt
wget ftp://dschost1.w6kd.com/DPlus_Hosts.txt || wget ftp://dschost2.w6kd.com/DPlus_Hosts.txt
wget ftp://dschost1.w6kd.com/DCS_Hosts.txt || wget ftp://dschost2.w6kd.com/DCS_Hosts.txt

/bin/rm -f gwys.txt

echo "# Downloaded from dschost1.w6kd.com `date`" > gwys.txt
awk '$1 ~ /^REF/ { printf "%s %s 20001\n", $1, $2 }' DPlus_Hosts.txt >> gwys.txt
awk '$1 ~ /^XRF/ { printf "%s %s 30001\n", $1, $2 }' DExtra_Hosts.txt >> gwys.txt
awk '$1 ~ /^DCS/ { printf "%s %s 30051\n", $1, $2 }' DCS_Hosts.txt >> gwys.txt

/bin/rm -f D{Extra,Plus,CS}_Hosts.txt
