#/bin/bash
# Get the big list from Ramesh (VA3UV) and extract the DStar and XReflectors only.
# Put everything on port 20001 so no ports have to be opened!
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
	awk '$1~/^REF|XRF/&&$2~/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/{printf "%s\t%s\t20001\n", $1, $2}' gwys.va3uv.txt > gwys.txt
else
        echo "Could not get gateways list from www.va3uv.com!"
	if [ -e gwys.txt.orig ]; then
        	mv -f gwys.txt.orig gwys.txt
	fi
fi

