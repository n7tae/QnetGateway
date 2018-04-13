#!/bin/bash
# from the PiStar servers...
wget http://www.pistar.uk/downloads/DPlus_Hosts.txt
wget http://www.pistar.uk/downloads/DExtra_Hosts.txt
wget http://www.pistar.uk/downloads/DCS_Hosts.txt
/bin/rm -f gwys.txt

echo "# Downloaded from www.pistar.uk `date`" > gwys.txt
awk '$1 ~ /^REF/ { printf "%s %s 20001\n", $1, $2 }' DPlus_Hosts.txt >> gwys.txt
awk '$1 ~ /^XRF/ { printf "%s %s 30001\n", $1, $2 }' DExtra_Hosts.txt >> gwys.txt
awk '$1 ~ /^DCS/ { printf "%s %s 30051\n", $1, $2 }' DCS_Hosts.txt >> gwys.txt

/bin/rm -f D{Extra,Plus,DCS}_Hosts.txt
