#/bin/bash
# Get the big list from Ramesh (VA3UV) and extract the DCS, DStar and XReflectors only.
# Put XREF reflectors on port 20001 so no ports have to be forwarded on your home router!
#
# 73
#
# Tom, ac2ie@arrl.net

if [ -e gwys.txt ]; then
	mv -f gwys.txt gwys.txt.orig
fi

rm -f gwys.va2uv.txt

wget -nv -O gwys.va3uv.txt http://www.va3uv.com/gwys.txt

if [ -e gwys.va3uv.txt ]; then
	# Move DPlus and DExtra to port 20001
	awk '$1~/^REF|XRF/{print $1, $2, 20001}' gwys.va3uv.txt > gwys.txt
	# Get the DCS reflectors too
	awk '$1~/^DCS/{print $1, $2, $3}' gwys.va3uv.txt >> gwys.txt
else
        echo "Could not get gateways list from www.va3uv.com!"
	if [ -e gwys.txt.orig ]; then
        	mv -f gwys.txt.orig gwys.txt
	fi
fi

