<!DOCTYPE html>
<?php
#    If visiting this page by /dashboardV2  (no / suffix) it causes issues referring to CSS / JS 
#    So we check to see the URL and redirect to /dashboardV2/ if we need to
     function endsWith($string, $test) {
          $strlen = strlen($string);
          $testlen = strlen($test);
          if ($testlen > $strlen) return false;
          return substr_compare($string, $test, $strlen - $testlen, $testlen) === 0;
     }

      if ( !( endsWith($_SERVER['REQUEST_URI'], "/index.php") || (endsWith($_SERVER['REQUEST_URI'], "/") ) ) )
      {
	header("Location: dashboardV2/");
      }

     # Load functions and read config file
     include 'init.php';
?>
<html lang="en">
<head>
     <title>QnetGateway Dashboard V2</title>
     <meta name="viewport" content="width=device-width, initial-scale=1.0">
     <meta charset="utf-8">
     <!-- Bootstrap -->
     <link href="css/bootstrap.min.css" rel="stylesheet" media="screen">
     <link href="css/bootstrap-table.min.css" rel="stylesheet"> 
</head>
<body>

     <!-- Include jQuery and Bootstrap-->
     <script src="js/jquery.min.js"></script>
     <script src="js/bootstrap.min.js"></script>

     <!-- Header - maybe turn this into a Nav Bar in the future -->
     <nav class="navbar navbar-light bg-light">
          <div class="navbar-header  navbar-default">
               <a class="navbar-brand" href="#">QnetGateway <?php echo GetCFGValue('ircddb_login'); ?> Dashboard</a>
          </div>
     </nav>
     <br>

     <!-- Large fixed width container for our layout -->
     <div class="container-lg">


<?php if( in_array("LH", $showlist) ) { 
      # Only show this section if LH is in the show list 
?>

     <div class="row"> <!-- R1 Start -->
          <div class="col-md-12"> <!-- R1C1  Start-->
               <div class="card border-dark mb-3"> <!-- Start of LH Card -->
                    <div class="card-body text-dark">
                         <h5 class="card-title">Last Heard</h5>
                         <table class="table table-sm" 
                                id="lhTable" 
                                data-auto-refresh="true"
                                data-auto-refresh-interval="<?php echo GetCFGValue('dash_refresh'); ?>"
                                data-pagination="false"
                                data-url="bin/getJson.php?jsonFile=lastHeard"
                                data-check-on-init="true">
                              <thead>
                              <tr class="d-flex">
                                   <th data-field="callsignProcessed" data-sortable="false">CallSign/Suffix</th>
                                   <th scope="col" data-field="message" data-sortable="false" class="d-none d-md-table-cell">Message</th>
                                   <th scope="col" data-field="maidenheadProcessed" data-sortable="false" class="d-none d-md-table-cell">Maidenhead</th>
                                   <th scope="col" data-field="module" data-sortable="false" class="d-none d-sm-table-cell">Module</th>
                                   <th data-field="reflector" data-sortable="false">Via</th>
                                   <th data-field="lastTime" data-sortable="false">Time</th>
                              </tr>
                              </thead>
                         </table>
                    </div>
               </div> <!-- End of LH Card -->
         </div> <!-- R1C1 End  -->
     </div> <!-- R1 End -->

<?php } ?>
     <div class="row"> <!-- R2 Start -->
          <div class="col-md-6"> <!-- R2C1 Start -->

<?php if( in_array("UR", $showlist) ) { 
      # If UR is in show list - dispaly QnRemote card
?>
               <div class="card border-dark mb-3"> <!-- Start of UR Card -->
                    <div class="card-body text-dark">
                         <h5 class="card-title">QnRemote Control</h5>
                         <div id="last_cmd_sent"> </div> <!-- Area for Last Command dispaly -->
                         <form name="URCall_form">
                              <fieldset>
                                   <div class="input-group">
                                        <div class="input-group-prepend">  <!-- Module button group -->
                                             <div class="btn-group btn-group-toggle" data-toggle="buttons">
<?php
     # Code to determine which module buttons are going to be disabled
     # or enabled.   If they are in the config, enable them for use, otherwise
     # keep them disabled
     $somethingChecked = false;
     foreach (array('a', 'b', 'c') as $mod) {
          $module = 'module_'.$mod;
          $modUpper = strtoupper($mod);
          #
          # If module is configured, make the button active
          if (array_key_exists($module, $cfg)) {
               echo '<label class="btn btn-primary active" >';
               echo '<input type="radio" name="moduleSelection" id="mod'.$modUpper.'opt" value="'.$modUpper.'" ';
               if( ! $somethingChecked ) { 
                   echo 'checked';
                   $somethingChecked = true;
               }
               echo '/>'.$modUpper;
               echo '</label>';
          } else { 
               #if the button is not configured, make the button disabled
               echo '<label class="btn btn-outline-primary disabled" >';
               echo '<input type="radio" name="moduleSelection" id="mod'.$modUpper.'opt" value="'.$modUpper.'" />'.$modUpper;
               echo '</label>';
          }
     }
?>
                                             </div>
                                        </div>
                                        <!-- URCall data input Field -->
                                        <input type="text" class="form-control" placeholder="URCall data" id="URCall_field" maxlength="8" />
                                        <div class="input-group-append">  <!-- Submit button -->
                                             <input class="btn btn-primary button" type="submit" value="Submit" id="URCall_SubmitBtn" />
                                        </div>
                                   </div>
                              </fieldset>
                         </form>
                    </div>
               </div> <!-- End of UR card -->

<?php } if( in_array("MO", $showlist) ) { 
     # Show card if MO is in the show list
?>
               <div class="card border-dark mb-3"> <!-- Start of MO Card -->
                    <div class="card-body text-dark">
                         <h5 class="card-title">Configured Modules</h5>
                         <table class="table table-sm"
                                id="modulesTable"
                                data-auto-refresh="true"
                                data-auto-refresh-interval="<?php echo GetCFGValue('dash_refresh'); ?>"
                                data-pagination="false"
                                data-card-view="true"
                                data-url="bin/getJson.php?jsonFile=modules">
                              <thead>
                              <tr class="d-flex">
                                   <th data-field="module" data-sortable="false">Module</th>
                                   <th data-field="modem" data-sortable="false">Modem</th>
                                   <th data-field="freq" data-sortable="false">Frequency</th>
                                   <th data-field="link" data-sortable="false">Link</th>
                                   <th data-field="linkedTime" data-sortable="false">Linked Time</th>
                                   <th data-field="ip_address" data-sortable="false">Link IP</th>
                              </tr>
                              </thead>
                         </table>
                    </div>
               </div> <!-- End of MO card -->

<?php } ?>
          </div> <!-- R2C1 End -->
          <div class="col-xs-12 col-md-6"> <!-- R2C2 Start -->
<?php if( in_array("SY", $showlist) ) { 
    # Only show this card if the SY was listed in the show list 
?>
               <div class="card border-dark mb-3"> <!-- SY Card Start -->
                    <div class="card-body text-dark">
                         <h5 class="card-title">System Information</h5>
                         <table class="table table-sm table-hover" cellpadding="1" style="font-family: monospace">

<?php
     # Code to Generate the System Information for the SY card
     $hn = trim(`uname -n`);
     $kn = trim(`uname -rmo`);
     $osinfo = file('/etc/os-release', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
     foreach ($osinfo as $line) {
          list( $key, $value ) = explode('=', $line);
          if ($key == 'PRETTY_NAME') {
              $os = trim($value, '"');
          }
     }
     $cu = trim(`cat /proc/cpuinfo | grep Model`);
     if (0 == strlen($cu))
          $cu = trim(`cat /proc/cpuinfo | grep "model name"`);
     $culist = explode("\n", $cu);
     $mnlist = explode(':', $culist[0]);
     $cu = trim($mnlist[1]);
     if (count($culist) > 1)
          $cu .= ' ' . count($culist) . ' Threads';
     if (file_exists('/opt/vc/bin/vcgencmd'))
          $cu .= ' ' . str_replace("'", '&deg;', trim(`/opt/vc/bin/vcgencmd measure_temp`));
?>
                              <tr>
                                   <th scope="row" style="text-align:right">CPU</th>
                                   <td><?php echo $cu; ?></td>
                              </tr>
                              <tr>
                                   <th scope="row" style="text-align:right">Kernel</th>
                                   <td><?php echo $kn; ?></td>
                              </tr>
                              <tr>
                                   <th scope="row" style="text-align:right">OS</th>
                                   <td><?php echo $os; ?></td>
                              </tr>
                              <tr>
                                   <th scope="row" style="text-align:right">Hostname</th>
                                   <td><?php echo $hn; ?></td>
                              </tr>
                              <tr>
                                   <th scope="row" style="text-align:right">Internal IP</th>
                                   <td><?php echo GetIP('internal'); ?></td>
                              </tr>
                              <tr>
                                   <th scope="row" style="text-align:right">IPV4</th>
                                   <td><?php echo GetIP('ipv4'); ?></td>
                              </tr>
                              <tr>
                                   <th scope="row" style="text-align:right">IPV6</th>
                                   <td><?php echo GetIP('ipv6'); ?></td>
                              </tr>
                         </table>
                    </div>
               </div> <!-- End of SY Card -->
<?php } ?>
          </div> <!-- R2C2 End  -->
     </div> <!-- R2 End -->

<?php if( in_array("PS", $showlist) ) { 
     # Only show 3rd row if PS is in show list
?>

     <div class="row"> <!-- R3 Start -->
          <div class="col-12"> <!-- R3C1 Start -->
               <div class="card border-dark mb-3"> <!-- PS Card Start -->
                    <div class="card-body text-dark">
                         <h5 class="card-title">Processes</h5>
                         <table class="table table-sm"
                                id="procTable"
                                data-auto-refresh="true"
                                data-auto-refresh-interval="<?php echo GetCFGValue('dash_refresh'); ?>"
                                data-pagination="false"
                                data-url="bin/getJson.php?jsonFile=ps">
                              <thead>
                              <tr class="d-flex">
                                   <th scope="col" data-field="user" data-sortable="false" class="d-none d-sm-table-cell">User</th>
                                   <th data-field="pid" data-sortable="false">PID</th>
                                   <th scope="col" data-field="pcpu" data-sortable="false" class="d-none d-md-table-cell">CPU</th>
                                   <th scope="col" data-field="size" data-sortable="false" class="d-none d-md-table-cell">Mem</th>
                                   <th data-field="cmd" data-sortable="false">Command</th>
                              </tr>
                              </thead>
                         </table>
                    </div>
               </div> <!-- End of PS card -->
          </div> <!-- End of R3C1 -->
     </div> <!-- End of R3 -->
<?php } ?>
</div> <!-- End of Container -->

<!-- Bootstrap table Javascript -->
<script src="js/bootstrap-table.min.js"></script>
<script src="js/bootstrap-table-auto-refresh.min.js"></script> 

<!-- Enable Bootstrap tables and jQuery AJAX for QnRemote Control -->
<script>
     $(function() {
          $('#lhTable').bootstrapTable()
          $('#modulesTable').bootstrapTable()
          $('#procTable').bootstrapTable()
          
          $(".button").click(function() {
               var processMod = $("input[type='radio'][name='moduleSelection']:checked").val();
               var processURCall = $("input#URCall_field").val();
               var dataString = 'mod='+ processMod + '&URCall=' + processURCall;
               $.ajax({
                    type: "POST",
                    url: "bin/qnRemoteCmd.php",
                    data: dataString,
                    success: function( returnData ) {
                         $('#last_cmd_sent').html("<div class=\"pb-2\" id=\"message\"></div>");
                         $('#message').html("Last command sent: <kbd>" + returnData + "</kbd><br>")
                         .hide()
                         .fadeIn( 1500 );
                         $("input#URCall_field").val("");
                    }
               });
               return false; //Dont actually submit the form, let the above JS do the work
          });
     });
</script> 
</body>
</html>
