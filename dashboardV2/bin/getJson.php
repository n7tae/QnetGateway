<?php

# Load functions and read config file
include '../init.php';

$lastRunFile = "/tmp/lastJsonGen.tmp";
$lastRunTime = filemtime($lastRunFile);
$now = time();

# Only Generage jSon Data if it hasnt been generated in the last 8 seconds
if( ($now-$lastRunTime) > 8 )
{
     # OpenDatabase
     $dbname = $cfgdir.'/qn.db';
     $db = new SQLite3($dbname, SQLITE3_OPEN_READONLY);
     
     # Only proccess if defined in show list
     if( in_array("LH", $showlist) ) {
          $jsonArray = [];
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
     
          # Write the lastHeard JSON file
          $lhJsonFile = fopen("../jsonData/lastHeard.json", "w");
          fwrite($lhJsonFile, json_encode($jsonArray));
          fclose($lhJsonFile);
     } else { echo "Section disabled"; 
          $lhJsonFile = fopen("../jsonData/lastHeard.json", "w");
          fwrite($lhJsonFile, "{ }\n");
          fclose($lhJsonFile);
     }
     
     
     # Only proccess if defined in show list
     if( in_array("MO", $showlist) ) {
          $jsonArray = [];
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
          $modJsonFile = fopen("../jsonData/modules.json", "w");
          fwrite($modJsonFile, json_encode($jsonArray));
          fclose($modJsonFile);
     } else { 
          $modJsonFile = fopen("../jsonData/modules.json", "w");
          fwrite($modJsonFile, "{ }\n");
          fclose($modJsonFile);
     } 
     
     # Close database it is not needed anymore
     $db->Close();
     
     
     # Only proccess if defined in show list
     if( in_array("PS", $showlist) ) {
          $jsonArray = [];
          $lines = explode("\n", `ps -eo user,pid,pcpu,size,cmd | grep -e qngateway -e qnlink -e qndtmf -e qndvap -e qnitap -e qnrelay -e qndvrptr -e qnmodem -e MMDVMHost | grep -v grep`);
          foreach ($lines as $line) {
               $items = preg_split ('/\s+/', $line, 5);
               if( isset( $items[1] ) ) {
                    $jsonArray[] = array('user' => $items[0],
                                        'pid'  => $items[1],
                                        'pcpu' => $items[2],
                                        'size' => $items[3],
                                        'cmd'  => $items[4]);
               }
          }
          $psJsonFile = fopen("../jsonData/ps.json", "w");
          if ($jsonArray) {
               fwrite($psJsonFile, json_encode($jsonArray));
          } else {
               fwrite($psJsonFile, "{ }\n");
          }
          fclose($psJsonFile);
     } else { 
          # Section is disabled, replace with blank JSON file
          $psJsonFile = fopen("../jsonData/ps.json", "w");
          fwrite($psJsonFile, "{ }\n");
          fclose($psJsonFile);
     }

     # Update last run time
     `touch $lastRunFile`;
}

# If the jsonFile is in the URL lets get the file
if( isset($_GET['jsonFile']) )
{
     if( $_GET['jsonFile'] == "lastHeard" )
          readfile("../jsonData/lastHeard.json");
     else if( $_GET['jsonFile'] == "modules" )
          readfile("../jsonData/modules.json");
     else if( $_GET['jsonFile'] == "ps" )
          readfile("../jsonData/ps.json");
}
?>

