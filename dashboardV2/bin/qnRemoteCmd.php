<!DOCTYPE html>
<?php

# Load functions and read config file
include '../init.php';

# Only proccess if defined in show list
if( in_array("UR", $showlist) ) {
     if ( isset($_POST['URCall']) && isset($_POST['mod'])) {
          $urcall = str_replace(' ', '_', trim(preg_replace('/[^0-9a-z_ ]/', '', strtolower($_POST['URCall']))));
          if (strlen($urcall)>0 && strlen($_POST['mod'])>0) {
               $command = 'qnremote '.strtolower($_POST['mod']).' '.strtolower($cfg['ircddb_login']).' '.$urcall;
               $unused = `$command`;
               
               # Return the command sent for the front-end display
               echo $command;
          }
     }
} else {
     echo "Section disabled";
}
?>
