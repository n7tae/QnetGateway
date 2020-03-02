<!DOCTYPE html>
<html>
<head>
<title>QnetGateway Dashboard</title>
<meta http-equiv="refresh" content="15">
</head>
<body>
<?php
	$fmodule = $furcall = '';

	function parse(string $filename)
	{
		$ret = array();
		if ($lines = file($filename, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)) {
			foreach ($lines as $line) {
				$line = trim($line);
				if ($line[0] == '#') continue;
				if (! strpos($line, '=')) continue;
				list( $key, $value ) = explode('=', $line);
				$value = trim($value, "'");
				$ret[$key] = $value;
			}
		}
		return $ret;
	}

	function getip(string $type)
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

	function getstatus(string $mod, array &$kv)
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

	$cfg = parse("/usr/local/etc/qn.cfg");
?>
<h2>QnetGateway <?php echo $cfg['ircddb_login']; ?> Dashboard</h2>
<?php
if (`ps -aux | grep -e qn -e MMDVMHost | wc -l` > 2) {
	echo 'Process:<br><code>', "\n";
	echo str_replace(' ', '&nbsp;', 'USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND<br>'), "\n";
	$lines = explode("\n", `ps -aux | grep -e qngateway -e qnlink -e qndtmf -e qndvap -e qnitap -e qnrelay -e qndvrptr -e qnmodem -e MMDVMHost | grep -v grep`);
	foreach ($lines as $line) {
		echo str_replace(' ', '&nbsp;', $line), "<br>\n";
	}
	echo '</code>', "\n";
}
?>
IP Addresses:<br>
<table cellpadding='1' border='1' style='font-family: monospace'>
<tr><td style="text-align:center">Internal</td><td style="text-align:center">IPV4</td><td style="text-align:center">IPV6</td></tr>
<tr><td><?php echo getip('internal');?></td><td><?php echo getip('ipv4');?></td><td><?php echo getip('ipv6');?></td></tr>
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
		$stat = getstatus($mod, $cfg);
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
		  $lastline = system($command);
	  }
?>
</body>
</html>
