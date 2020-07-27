<?php

header('Content-Type: application/json');

# Load functions and read config file
include '../init.php';

# Only proccess if defined in show list
if( in_array("LH", $showlist) ) {
     $jsonArray = [];
     $dbname = $cfgdir.'/qn.db';
     $db = new SQLite3($dbname, SQLITE3_OPEN_READONLY);
     $ss = 'SELECT callsign,sfx,message,module,reflector,maidenhead,latitude,longitude,strftime("%s","now")-lasttime as lastTime FROM LHEARD ORDER BY lastTime LIMIT '.GetCFGValue('dash_lastheard_count').' ';
     if ($stmnt = $db->prepare($ss)) {
          if ($result = $stmnt->execute()) {
               while ($row = $result->FetchArray(SQLITE3_ASSOC)) {
                    //transform the lastTimeHeard to a printable string
                    $row['lastTime'] = SecToString($row['lastTime']);
                    $row['maidenheadProcessed'] = Maidenhead($row['maidenhead'], $row['latitude'], $row['longitude']);
                    $row['callsignProcessed'] = MyAndSfxToQrz($row['callsign'], $row['sfx']);
                    $jsonArray[] = $row;
               }
               $result->finalize();
          }
          $stmnt->close();
     }
     $db->Close();
     echo json_encode($jsonArray);
} else { echo "Section disabled"; }

?>
