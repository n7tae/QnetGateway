<?php
header('Content-Type: application/json');

# Load functions and read config file
include '../init.php';

# Only proccess if defined in show list
if( in_array("PS", $showlist) ) {
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
     if ($jsonArray) {
          echo json_encode($jsonArray); 
     } else { echo '{ }'; }
} else { echo "Section disabled"; }
?>
