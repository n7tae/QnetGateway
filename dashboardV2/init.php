<?php
$cfg = array();
$defaults = array();
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
          $ip = trim(`dig @resolver1.ipv6-sandbox.opendns.com AAAA myip.opendns.com +short -6`);
     else if ('ipv4' == $type)
          $ip = trim(`dig @resolver4.opendns.com myip.opendns.com +short -4`);
     else
          $ip = '';
     return $ip;
}


function SecToString(int $sec) {
     if ($sec >= 86400)
          return sprintf("%0.2f days", $sec/86400);
     $hrs = intdiv($sec, 3600);
     $sec %= 3600;
     $min = intdiv($sec, 60);
     $sec %= 60;
     if ($hrs) return sprintf("%2d hr  %2d min", $hrs, $min);
     if ($min) return sprintf("%2d min %2d sec", $min, $sec);
     return sprintf("%2d sec", $sec);
}

function MyAndSfxToQrz(string $my, string $sfx)
{
     $my = trim($my);
     $sfx = trim($sfx);
     if (0 == strlen($my)) {
          $my = 'Empty MYCall ';
     } else {
          if (strpos($my, ' '))
               $link = strstr($my, ' ', true);
          else
               $link = $my;
          if (strlen($sfx))
               $my .= '/'.$sfx;
          $len = strlen($my);
          $my = '<a target="_blank" href="https://www.qrz.com/db/'.$link.'">'.$my.'</a>';
          while ($len < 13) {
               $my .= ' ';
               $len += 1;
          }
     }
     return $my;
}

function Maidenhead(string $maid, float $lat, float $lon)
{
     $str = trim($maid);
     if (6 > strlen($str))
          return $maid;
     if ($lat >= 0.0)
          $slat = '+'.$lat;
     else
          $slat = $lat;
     if ($lon >= 0.0)
          $slon = '+'.$lon;
     else
          $slon = $lon;
     $str = '<a target="_blank" href="https://www.google.com/maps?q='.$slat.','.$slon.'">'.$maid.'</a>';
     return $str;
}


ParseKVFile($cfgdir.'/qn.cfg', $cfg);
ParseKVFile($cfgdir.'/defaults', $defaults);

$showorder = GetCFGValue('dash_show_order');
$showlist = explode(',', trim($showorder));

?>
