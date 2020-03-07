<!DOCTYPE html>
<html>
<head>
<title>QnetGateway Dashboard</title>
<meta http-equiv="refresh" content="20">
</head>
<body>
<?php
	$cfg = array();
	$defaults = array();
	$fmodule = $furcall = '';
	$cfgdir = '/usr/local/etc';

	function ParseKVFile(string $filename, &$kvarray)
	{
		if ($lines = file($filename, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)) {
			foreach ($lines as $line) {
				$line = trim($line);
				if ($line[0] == '#') continue;
				if (! strpos($line, '=')) continue;
				list( $key, $value ) = explode('=', $line);
				if ("'" == $value[0])
					list ( $value ) = explode("'", substr($value, 1));
				else
					list ( $value ) = explode(' ', $value);
				$value = trim($value);
				$kvarray[$key] = $value;
			}
		}
	}

	function GetCFGValue(string $key)
	{
		global $cfg, $defaults;
		if (array_key_exists($key, $cfg))
			return $cfg[$key];
		if ('module_' == substr($key, 0, 7)) {
			$mod = substr($key, 0, 8);
			if (array_key_exists($mod, $cfg)) {
				$key = $cfg[$mod].substr($key, 8);
				if (array_key_exists($key, $defaults))
					return $defaults[$key];
			}
		} else {
			if (array_key_exists($key.'_d', $defaults))
				return $defaults[$key.'_d'];
		}
		return '';
	}

	function GetIP(string $type)
	{
		if ('internal' == $type) {
			$iplist = explode(' ', `hostname -I`);
			foreach ($iplist as $ip) {
				if (strpos($ip, '.')) break;
			}
		} else if ('ipv6' == $type)
			$ip = trim(`curl --silent -6 icanhazip.com`);
		else if ('ipv4' == $type)
			$ip = trim(`curl --silent -4 icanhazip.com`);
		else
			$ip = '';
		return $ip;
	}

	function GetStatus(string $mod, array &$kv)
	{
		$mod = strtoupper(substr($mod, 0, 1));
		if (array_key_exists('file_status', $kv))
			$file = $kv['file_status'];
		else
			$file = '/usr/local/etc/rptr_status';
		if ($lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)) {
			foreach ($lines as $line) {
				$words = explode(',', $line);
				if ($words[0] == $mod)
					return $words;
			}
		}
		return explode(',', ',,,,,');
	}
	function SecToString(int $secs) {
		$days = $secs / 86400;
		if ($days >= 1.0)
			return sprintf("%0.2f days", $days);
		$hrs = intdiv($secs, 3600);
		$sec %= 3600;
		$min = intdiv($sec, 3600);
		$sec %= 60;
		if ($hrs > 9)
			return sprintf("%d hr %2d min %2d sec", $hrs, $min, $sec);
		if ($hrs)
			return sprintf("%2d min $2 sec", $min, $sec);
		if ($min > 9)
			return sprintf("%d min %2d sec", $min, $sec);
		if ($sec > 9)
			return sprintf("%d sec", $sec);
		return sprintf("%2d sec", $sec);
	}

	function LastHeardPage()
	{
		echo 'Last Heard:<br><code>', "\n";
		$rstr = 'MyCall/Sfx    URCall   Module   Gateway  Last Time<br>';
		echo str_replace(' ', '&nbsp;', $rstr), "\n";
		echo '</code><br>', "\n";
		$dbname = GetCFGValue('dashboard_sql_filename');
		$db = new SQLite3($dbname, SQLITE3_OPEN_READONLY);
		$ss = 'SELECT mycall,sfx,urcall,module,gateway,strftime("%s","now")-lasttime FROM LHEARD ORDER BY 6 LIMIT '.GetCFGValue('dashboard_lastheard_count').' ';
		if ($stmnt = $db->prepare($ss)) {
			if ($result = $stmnt->execute()) {
				while ($row = $result->FetchArray(SQLITE3_NUM)) {
					$cs = str_pad(trim($row[0]).'/'.trim($row[1]), 13);
					$rstr = $cs.' '.$row[2].' '.$row[3].' '.$row[4].'  '.SecToString(intval($row[5])).'<br>';
					echo str_replace(' ', '&nbsp;', $rstr), "\n";
				}
				$result->finalize();
			}
			$stmnt->close();
		}
		$db->Close();
		echo '</code><br>', "\n";
	}

	ParseKVFile($cfgdir.'/qn.cfg', $cfg);
	ParseKVFile($cfgdir.'/defaults', $defaults);
?>
<h2>QnetGateway <?php echo GetCFGValue('ircddb_login'); ?> Dashboard</h2>
<?php
if (`ps -aux | grep -e qn -e MMDVMHost | wc -l` > 2) {
	echo 'Processes:<br><code>', "\n";
	echo str_replace(' ', '&nbsp;', 'USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND<br>'), "\n";
	$lines = explode("\n", `ps -aux | grep -e qngateway -e qnlink -e qndtmf -e qndvap -e qnitap -e qnrelay -e qndvrptr -e qnmodem -e MMDVMHost | grep -v grep`);
	foreach ($lines as $line) {
		echo str_replace(' ', '&nbsp;', $line), "<br>\n";
	}
	echo '</code>', "\n";
}

if ('true' == GetCFGValue('dashboard_enable_lastheard'))
	LastHeardPage();
?>
IP Addresses:<br>
<table cellpadding='1' border='1' style='font-family: monospace'>
<tr><td style="text-align:center">Internal</td><td style="text-align:center">IPV4</td><td style="text-align:center">IPV6</td></tr>
<tr><td><?php echo GetIP('internal');?></td><td><?php echo GetIP('ipv4');?></td><td><?php echo GetIP('ipv6');?></td></tr>
</table><br>
Modules:<br>
<table cellpadding='1' border='1' style='font-family: monospace'>
<tr><td style="text-align:center">Module</td><td style="text-align:center">Modem</td><td style="text-align:center">Frequency</td><td style="text-align:center">Repeater</td><td style="text-align:center">Repeater IP</td></tr>
<?php
foreach (array('a', 'b', 'c') as $mod) {
	$module = 'module_'.$mod;
	if (array_key_exists($module, $cfg)) {
		$configured[] = strtoupper($mod);
		$freq = 0.0;
		if (array_key_exists($module.'_tx_frequency', $cfg))
			$freq = $cfg[$module.'_tx_frequency'];
		else if (array_key_exists($module.'_frequency', $cfg))
			$freq = $cfg[$module.'_frequency'];
		$stat = GetStatus($mod, $cfg);
		if (8==strlen($stat[1]) && 1==strlen($stat[2]))
			$linkstatus = substr($stat[1], 0, 7).$stat[2];
		else
			$linkstatus = 'Unlinked';
		echo '<tr><td style="text-align:center">',strtoupper($mod),'</td><td style="text-align:center">',$cfg[$module],'</td><td style="text-align:center">',$freq,'</td><td style="text-align:center">',$linkstatus,'</td><td style="text-align:center">',$stat[3],'</td></tr>',"\n";
	}
}
?>
</table><br>
Send URCall:<br>
<form method="post">
<?php
	if (count($configured) > 1) {
		echo 'Module: ', "\n";
		foreach ($configured as $mod) {
			echo '<input type="radio" name="fmodule"', (isset($fmodule) && $fmodule==$mod) ? '"checked"' : '', ' value="$mod">', $mod, '<br>', "\n";
		}
	} else
		$fmodule = $configured[0];
?>
URCall: <input type="text" name='furcall' value="<?php echo $furcall;?>">
<input type="submit" name="sendurcall" value="Send URCall"><br>
</form>

<?php
	if (isset($_POST['sendurcall'])) {
		$furcall = $_POST['furcall'];

		if (empty($_POST['fmodule'])) {
			if (1==count($configured)) {
				$fmodule = $configured[0];
			}
		} else {
		  $fmodule = $_POST['fmodule'];
		}
	  }
	  $furcall = str_replace(' ', '_', trim(preg_replace('/[^0-9a-z ]/', '', strtolower($furcall))));

	  if (strlen($furcall)>0 && strlen($fmodule)>0) {
		  $command = 'qnremote '.strtolower($fmodule).' '.strtolower($cfg['ircddb_login']).' '.$furcall;
		  echo $command, "<br>\n";
		  $unused = `$command`;
	  }
?>
</body>
</html>
