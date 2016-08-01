<?php
require_once('PhpSIP.class.php');

/* Sends NOTIFY to reset Linksys phone */

try
{
  $api = new PhpSIP();
  $api->setUsername('10000'); // authentication username
  $api->setPassword('secret'); // authentication password
  // $api->setProxy('some_ip_here'); 
  $api->addHeader('Event: resync');
  $api->setMethod('NOTIFY');
  $api->setFrom('sip:10000@sip.domain.com');
  $api->setUri('sip:10000@sip.domain.com');
  $res = $api->send();

  echo "response: $res\n";
  
} catch (Exception $e) {
  
  echo $e;
}

?>
