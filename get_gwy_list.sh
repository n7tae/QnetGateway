#/bin/bash

/bin/cp ./gwys.txt ./gwys.txt.bak
/bin/rm -rf ./gwys.txt

wget http://www.va3uv.com/gwys.txt

#/sbin/service g2_link restart

exit 0
