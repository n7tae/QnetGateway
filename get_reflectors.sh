#/bin/bash

# Get the big list from Ramesh (VA3UV) and extract the DCS, DStar and XReflectors only.
# Put XREF reflectors on port 20001 so they will use DPlus linking!
#
# 73
#
# Tom, n7tae (at) arrl (dot) net

if [ -e gwys.txt ]; then
	mv -f gwys.txt gwys.txt.orig
fi

rm -f gwys.va2uv.txt

wget -nv -O gwys.va3uv.txt http://www.va3uv.com/gwys.txt

if [ -e gwys.va3uv.txt ]; then
	echo "# from www.va3uv.com on `date`" > gwys.txt
	echo "Got `awk '$1~/^REF/{print $1, $2, $3}' gwys.va3uv.txt | tee -a gwys.txt | wc -l` REF reflectors"
	# Move DPlus and DExtra to port 20001
	echo "Got `awk '$1~/^XRF/{print $1, $2, 20001}' gwys.va3uv.txt | tee -a gwys.txt | wc -l` XRF reflectors"
	echo "Got `awk '$1~/^DCS/{print $1, $2, $3}' gwys.va3uv.txt | tee -a gwys.txt | wc -l` DCS reflectors"
else
	echo "Could not get gateways list from www.va3uv.com!"
	if [ -e gwys.txt.orig ]; then
		mv -f gwys.txt.orig gwys.txt
	fi
fi

