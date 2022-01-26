<?php
require_once('../PhpSIP.class.php');

/* Listens for incoming SIP message */

try
{
  $api = new PhpSIP('192.168.5.65', 5061); // <-- CHANGE IP address here
  $api->setDebug(true);
  $api->setServerMode(true);
  $api->listen(['MESSAGE']);

  echo "MESSAGE received\n";

  $api->reply(200,'OK');
  
} catch (Exception $e) {
  
  echo $e;
}

?>
