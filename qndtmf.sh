#!/bin/bash

# Copyright (C) 2011 by Scott Lawson KI4LKF
# Copyright (C) 2018 by Thomas A. Early N7TAE
#
# This script finds files in the /tmp  directory
#    The files have a name like x_mod_DTMF_NOTIFY, where x is one of A B or C, the local module
#    The contents of these files can be as follows:

# Example:  #        will unlink local module, "       U"
# Example:  B75703   will link local module to XRF757 C
# Example:  D00617   will link local module to DCS006 Q
# Example:  *00103   will link local module to REF001 C
# Example:  0 or 00  will report status of the link, "       I"
# Example:  ##08     will execute the exec_H.sh script (shutdown the system)
# Please note that scripts exec_[0-9].sh are not accessible from DTMF.

# We set this to spaces, it will be set later

GetLetter () {
	local i
	if [[ $1 == +([0-9]) ]]; then
		i=`expr $1 - 1`
		if [ $i -ge 0 ] && [ $i -lt 26 ]; then
			LETTER=${LETTERS[$i]}
			return
		fi
	fi
	LETTER=$BAD
}

LUSER="        "
LETTERS=( {A..Z} )
BAD='bad'

cd /tmp
echo started at `date`

while [[ 1 ]]
do
	for i in `ls ?_mod_DTMF_NOTIFY 2>/dev/null`
	do
		echo found file $i at `date`
		LOCAL_BAND=${i:0:1}
		if [[ "$LOCAL_BAND" == 'A' ]] || [[ "$LOCAL_BAND" == 'B' ]] || [[ "$LOCAL_BAND" == 'C' ]]; then
			CMD=`head -n 1 $i 2>/dev/null`
			LUSER=`tail -n 1 $i 2>/dev/null`
			echo "... with these contents: " $CMD " " $LUSER
			if [[ "$CMD" == '#' ]]; then
				echo Unlinking local band $LOCAL_BAND requested by $LUSER
				qnremote ${LOCAL_BAND} "$LUSER"  U  >/dev/null 2>&1
				echo
			elif [[ "$CMD" == '0' ]] || [[ "$CMD" == '00' ]]; then
				echo Link Status on local band $LOCAL_BAND requested by $LUSER
				qnremote ${LOCAL_BAND} "$LUSER"  I  >/dev/null 2>&1
				echo
			elif [[ "$CMD" == '**' ]]; then
				echo Load Hosts on local band  $LOCAL_BAND requested by $LUSER
				qnremote ${LOCAL_BAND} "$LUSER"  F  >/dev/null 2>&1
			else
				if [ ${#CMD} -eq 4 ] && [[ ${CMD:0:2} == '##' ]]; then
					GetLetter ${CMD:2:2}
					if [[ "$LETTER" == "$BAD" ]]; then
						echo "bad script letter index: '${CMD:2:2}'"
						qnvoice $LOCAL_BAND baddtmfcmd.dat "Bad DTMF CMD"
					else
						qnremote $LOCAL_BAND $LUSER ${LETTER}X >/dev/null 2>&1
					fi
				elif [ ${#CMD} -eq 6 ]; then

					PFX=${CMD:0:1}
					if [[ "$PFX" = 'B' ]]; then
						RMT=XRF
					elif [[ "$PFX" = 'D' ]]; then
						RMT=DCS
					elif [[ "$PFX" = '*' ]]; then
						RMT=REF
					else
						RMT=$BAD
					fi

					REMOTE_NODE=${CMD:1:3}
					if [[ $REMOTE_NODE != +([0-9]) ]]; then
						REMOTE_NODE=$BAD
					fi

					GetLetter ${CMD:4:2}
					REMOTE_BAND=$LETTER

					if [[ "$RMT" == "$BAD" ]] || [[ "$REMOTE_NODE" == "$BAD" ]] || [[ "$REMOTE_BAND" == "$BAD" ]]; then
						echo "Bad link command: '$CMD'"
						qnvoice $LOCAL_BAND baddtmfcmd.dat "Bad Link CMD"
					else
						echo linking local band $LOCAL_BAND to remote node ${RMT}${REMOTE_NODE} $REMOTE_BAND requested by $LUSER
						qnremote ${LOCAL_BAND} "$LUSER"  ${RMT}${REMOTE_NODE}${REMOTE_BAND}L  >/dev/null 2>&1
						echo
					fi
				else
					echo "Bad command: '$CMD'"
					qnvoice $LOCAL_BAND baddtmfcmd.dat "Bad CMD"
				fi
			fi
		else
			echo "Local band '${LOCAL_BAND}' is bad"
		fi
		rm -f $i
	done
	sleep 2
done

exit 0
