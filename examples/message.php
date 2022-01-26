<?php
require_once('../PhpSIP.class.php');

try
{
  $api = new PhpSIP('127.0.0.1', 5060);
  $api->setMethod('MESSAGE');
  $api->setFrom('sip:10000@127.0.0.1');
  $api->setUri('sip:10000@192.168.5.65:5061'); // <- CHANGE IP address here
  $api->setBody('Hello world');
  $res = $api->send();

  echo "response: $res\n";
  
} catch (Exception $e) {
  
  echo $e;
}

?>
