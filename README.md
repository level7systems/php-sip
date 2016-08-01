
# PHP SIP User Agent class

## Introduction

This is a PHP implementation of a simple [SIP](http://en.wikipedia.org/wiki/Session_Initiation_Protocol) user agent (UAS / UAC). PHP SIP is not a VoIP phone. It is not possible to make "voip calls" with this tool - only SIP signalling is supported - no audio available.

Usage examples:

* "click to call" in a web page - see Tutorial
* send SIMPLE instant messages
* send Message Waiting Indication NOTIFY
* send messages to any SIP destination
* SIP functional testing
* more...

## Features

* symmetric signalling
* send/receive SIP message concurrently
* add any header to the request
* interpret and react to the response
* Linux and Windows compatible

## Known Bugs/Limitations

* only UDP transport
* not fully RFC compliant
* probably more... please help improve this project and report any issues [here](https://github.com/level7systems/php-sip/issues)

## Code examples
Instant MESSAGE

```php

try {
  $api = new PhpSIP('172.30.30.1'); // IP we will bind to $api->setMethod('MESSAGE');  
  $api->setFrom('sip:john@sip.domain.com');
  $api->setUri('sip:anna@sip.domain.com');
  $api->setBody('Hi, can we meet at 5pm   today?');
  
  $res = $api->send(); echo "res1: $res\n";

} catch (Exception $e) {

  echo $e->getMessage()."\n";
}

?> 
```

Send NOTIFY to resync Linksys phone

```php
try {
  $api = new PhpSIP('172.30.30.1'); // IP we will bind to
  $api->setUsername('10000'); // authentication username
  $api->setPassword('secret'); // authentication password //
  $api->setProxy('some_ip_here');
  $api->addHeader('Event: resync');
  $api->setMethod('NOTIFY');
  $api->setFrom('sip:10000@sip.domain.com');
  $api->setUri('sip:10000@sip.domain.com');
  $res = $api->send();
  
  echo "res1: $res\n";

} catch (Exception $e) {

  echo $e->getMessage()."\n"; }

?>
```
