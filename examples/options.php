<?php
require_once('../PhpSIP.class.php');

/* Sends Anonymous OPTIONS to eu.sip.ssl7.net */

$bindIP = '192.168.5.65'; // <-- change this to your own IP

try
{
  $api = new PhpSIP($bindIP);
  $api->setDebug(true);
  $api->setMethod('OPTIONS');
  $api->setFrom('sip:anonymous@localhost');
  $api->setUri('sip:test@eu.sip.ssl7.net');
  $res = $api->send();

  echo "response: $res\n";
  
} catch (Exception $e) {
  
  echo $e;
}

?>
