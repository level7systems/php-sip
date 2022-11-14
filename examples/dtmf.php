<?php
require_once('../PhpSIP.class.php');

try
{
  $api = new PhpSIP();
  $api->setDebug(true);
  $api->setUsername('ua1');
  $api->setPassword('xxxxxxxx');
  $api->setProxy('192.168.1.1');
  $api->setMethod('INVITE');
  $api->setFrom('sip:ua1@192.168.1.1');
  $api->setUri('sip:ua2@192.168.1.1');
  $res = $api->send();
  echo "response: $res\n";

  usleep(100000);

  $api->setMethod('INFO');
  $api->setContentType('application/dtmf-relay');
  $api->setBody('Signal=*'."\r\n".'Duration=160');
  $res = $api->send();
  echo "response: $res\n";

  usleep(100000);

  $api->setMethod('INFO');
  $api->setContentType('application/dtmf-relay');
  $api->setBody('Signal=0'."\r\n".'Duration=160');
  $res = $api->send();
  echo "response: $res\n";

  usleep(100000);

  $api->setMethod('BYE');
  $res = $api->send();
  echo "response: $res\n";

} catch (Exception $e) {

  echo $e;

}

?>
