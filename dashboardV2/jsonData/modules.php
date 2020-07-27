<?php

header('Content-Type: application/json');

#Load functions and read config file
include '../init.php';

# Only proccess if defined in show list
if( in_array("MO", $showlist) ) {
     $jsonArray = [];
     $dbname = $cfgdir.'/qn.db';
     $db = new SQLite3($dbname, SQLITE3_OPEN_READONLY);
     foreach (array('a', 'b', 'c') as $mod) {
          $linkstatus = 'Unlinked';
          $address = '';
          $ctime = '';
          $module = 'module_'.$mod;
          if (array_key_exists($module, $cfg)) {
               $freq = 0.0;
               if (array_key_exists($module.'_tx_frequency', $cfg)) {
                    $freq = $cfg[$module.'_tx_frequency'];
               }
               else if (array_key_exists($module.'_frequency', $cfg)) {
                    $freq = $cfg[$module.'_frequency'];
               }
               $ss = 'SELECT ip_address,to_callsign,to_mod,strftime("%s","now")-linked_time as linkedTime FROM LINKSTATUS WHERE from_mod=' . "'" . strtoupper($mod) . "';";
               if ($stmnt = $db->prepare($ss)) {
                    if ($result = $stmnt->execute()) {
                         if ($row = $result->FetchArray(SQLITE3_ASSOC)) {
                              $row['linkedTime'] = SecToString(intval($row['linkedTime']));
                              $row['module'] = strtoupper($mod);
                              $row['modem'] = $cfg[$module];
                              $row['freq'] = $freq;
                              $row['link'] = $row['to_callsign']." ".$row['to_mod'];
                              $jsonArray[] = $row;
                         } else {
                              $jsonArray[] = array('linkedTime' => '',
                                                   'module' =>strtoupper($mod),
                                                   'modem' => $cfg[$module],
                                                   'freq' => $freq,
                                                   'link' => 'Unlinked',
                                                   'ip_address' => '',
                                                   'to_callsign' => '',
                                                   'to_mod' => '');
                         }
                         $result->finalize();
                    }
                    $stmnt->close();
               }
          }
     }
     $db->close();
     echo json_encode($jsonArray); 
} else { echo "Section disabled"; } 

?>
