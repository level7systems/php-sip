<?php
/**
 * (c) 2007-2016 Chris Maciejewski
 * 
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files 
 * (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software, 
 * and to permit persons to whom the Software is furnished to do so, 
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included 
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
 * DEALINGS IN THE SOFTWARE.
 * 
 */

/**
 * PHP SIP UAC class
 * 
 * @ingroup  API
 * @author Chris Maciejewski <chris@level7systems.co.uk>
 * 
 */
require_once 'PhpSIP.Exception.php';

class PhpSIP
{
  private $debug = false;
  
  /**
   * Min port
   */
  private $min_port = 5065;
  
  /**
   * Max port
   */
  private $max_port = 5265;
  
  /**
   * Final Response timer (in ms)
   */
  private $fr_timer = 10000;
  
  /**
   * Lock file
   */
  private $lock_file = '/dev/shm/cache/PhpSIP.lock';
  
  /**
   * Persistent Lock file 
   */
  private $persistent_lock_file = true;
  
  /**
   * Allowed methods array
   */
  private $allowed_methods = array(
    "CANCEL","NOTIFY", "INVITE","BYE","REFER","OPTIONS","SUBSCRIBE","MESSAGE", "PUBLISH", "REGISTER"
  );
  
  private $server_mode = false;
  
  /**
   * Dialog established
   */
  private $dialog = false;
  
  /**
   * The opened socket we listen for incoming SIP messages
   */
  private $socket;
  
  /**
   * Source IP address
   */
  private $src_ip;
  
  /**
   * Source IP address
   */
  private $user_agent = 'PHP SIP';
  
  /**
   * CSeq
   */
  private $cseq = 20;
  
  /**
   * Source port
   */
  private $src_port;
  
  /**
   * Call ID
   */
  private $call_id;
  
  /**
   * Contact
   */
  private $contact;
  
  /**
   * Request URI
   */
  private $uri;
  
  /**
   * Request host
   */
  private $host;
  
  /**
   * Request port
   */
  private $port = 5060;
  
  /**
   * Outboud SIP proxy
   */
  private $proxy;
  
  /**
   * Method
   */
  private $method;
  
  /**
   * Auth username
   */
  private $username;
  
  /**
   * Auth password
   */
  private $password;
  
  /**
   * To
   */
  private $to;
  
  /**
   * To tag
   */
  private $to_tag;
  
  /**
   * From
   */
  private $from;
  
  /**
   * From User
   */
  private $from_user;

  /**
   * From tag
   */
  private $from_tag;
  
  /**
   * Via tag
   */
  private $via;
  
  /**
   * Content type
   */
  private $content_type;
  
  /**
   * Body
   */
  private $body;
  
  /**
   * Received SIP message
   */
  private $rx_msg;
  
  /**
   * Received Response
   */
  private $res_code;
  private $res_contact;
  private $res_cseq_method;
  private $res_cseq_number;

  /**
   * Received Request
   */
  private $req_method;
  private $req_cseq_method;
  private $req_cseq_number;
  private $req_contact;
  private $req_from;
  private $req_from_tag;
  private $req_to;
  private $req_to_tag;
  
  /**
   * Authentication
   */
  private $auth;
  
  /**
   * Routes
   */
  private $routes = array();
  
  /**
   * Record-route
   */
  private $record_route = array();
  
  /**
   * Request vias
   */
  private $request_via = array();
  
  /**
   * Additional headers
   */
  private $extra_headers = array();
  
  /**
   * Constructor
   * 
   * @param $src_ip Ip address to bind (optional)
   */
  public function __construct($src_ip = null, $src_port = null, $fr_timer = null)
  {
    if (!function_exists('socket_create'))
    {
      throw new PhpSIPException("socket_create() function missing.");
    }
    
    if ($src_ip)
    {
      if (!preg_match('/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/', $src_ip))
      {
        throw new PhpSIPException("Invalid src_ip $src_ip");
      }
    }
    else
    {
      // running in a web server
      if (isset($_SERVER['SERVER_ADDR']))
      {
        $src_ip = $_SERVER['SERVER_ADDR'];
      }
      // running from command line
      else
      {
        $addr = gethostbynamel(php_uname('n'));
        
        if (!is_array($addr) || !isset($addr[0]) || substr($addr[0],0,3) == '127')
        {
          throw new PhpSIPException("Failed to obtain IP address to bind. Please set bind address manualy.");
        }
      
        $src_ip = $addr[0];
      }
    }
    
    $this->src_ip = $src_ip;
    
    if ($src_port)
    {
      if (!preg_match('/^[0-9]+$/',$src_port))
      {
        throw new PhpSIPException("Invalid src_port $src_port");
      }
      
      $this->src_port = $src_port;
      $this->lock_file = null;
    }
    
    if ($fr_timer)
    {
      if (!preg_match('/^[0-9]+$/',$fr_timer))
      {
        throw new PhpSIPException("Invalid fr_timer $fr_timer");
      }
      
      $this->fr_timer = $fr_timer;
    }
    
    $this->createSocket();
  }
  
  /**
   * Destructor
   */
  public function __destruct()
  {
    $this->closeSocket();
  }
  
  /**
   * Sets debuggin ON/OFF
   * 
   * @param bool $status
   */
  public function setDebug($status = false)
  {
    $this->debug = $status;
  }
  
  /**
   * Gets src IP
   * 
   * @return string
   */
  public function getSrcIp()
  {
    return $this->src_ip;
  }
  
  /**
   * Gets port number to bind
   */
  private function getPort()
  {
    if ($this->src_port)
    {
      return true;
    }
    
    if ($this->min_port > $this->max_port)
    {
      throw new PhpSIPException ("Min port is bigger than max port.");
    }
    
    $fp = @fopen($this->lock_file, 'a+');
    
    if (!$fp)
    {
      throw new PhpSIPException ("Failed to open lock file ".$this->lock_file);
    }
    
    $canWrite = flock($fp, LOCK_EX);
    
    if (!$canWrite)
    {
      throw new PhpSIPException ("Failed to lock a file in 1000 ms.");
    }
    
    //file was locked
    clearstatcache();
    $size = filesize($this->lock_file);
    
    if ($size)
    {
      $contents = fread($fp, $size);
      
      $ports = explode(",",$contents);
    }
    else
    {
      $ports = false;
    }
    
    ftruncate($fp, 0);
    rewind($fp);
    
    // we are the first one to run, initialize "PID" => "port number" array
    if (!$ports)
    {
      if (!fwrite($fp, $this->min_port))
      {
        throw new PhpSIPException("Fail to write data to a lock file.");
      }
      
      $this->src_port =  $this->min_port;
    }
    // there are other programs running now
    else
    {
      $src_port = null;
      
      for ($i = $this->min_port; $i <= $this->max_port; $i++)
      {
        if (!in_array($i,$ports))
        {
          $src_port = $i;
          break;
        }
      }
      
      if (!$src_port)
      {
        throw new PhpSIPException("No more ports left to bind.");
      }
      
      $ports[] = $src_port;
      
      if (!fwrite($fp, implode(",",$ports)))
      {
        throw new PhpSIPException("Failed to write data to lock file.");
      }
      
      $this->src_port = $src_port;
    }
    
    if (!fclose($fp))
    {
      throw new PhpSIPException("Failed to close lock_file");
    }
    
  }
  
  /**
   * Releases port
   */
  private function releasePort()
  {
    if ($this->lock_file === null)
    {
      return true;
    }
    
    $fp = fopen($this->lock_file, 'r+');
    
    if (!$fp)
    {
      throw new PhpSIPException("Can't open lock file.");
    }
    
    $canWrite = flock($fp, LOCK_EX);
    
    if (!$canWrite)
    {
      throw new PhpSIPException("Failed to lock a file in 1000 ms.");
    }
    
    clearstatcache();
    
    $size = filesize($this->lock_file);
    $content = fread($fp,$size);
    
    //file was locked
    $ports = explode(",",$content);
    
    $key = array_search($this->src_port,$ports);
    
    unset($ports[$key]);
    
    if (!$this->persistent_lock_file && count($ports) === 0)
    {
      if (!fclose($fp))
      {
        throw new PhpSIPException("Failed to close lock_file");
      }
      
      if (!unlink($this->lock_file))
      {
        throw new PhpSIPException("Failed to delete lock_file.");
      }
    }
    else
    {
      ftruncate($fp, 0);
      rewind($fp);
      
      if ($ports && !fwrite($fp, implode(",",$ports)))
      {
        throw new PhpSIPException("Failed to save data in lock_file");
      }
      
      flock($fp, LOCK_UN);
      
      if (!fclose($fp))
      {
        throw new PhpSIPException("Failed to close lock_file");
      }
    }
  }
  
  /**
   * Adds aditional header
   * 
   * @param string $header
   */
  public function addHeader($header)
  {
    $this->extra_headers[] = $header;
  }
  
  /**
   * Sets From header
   * 
   * @param string $from
   */
  public function setFrom($from)
  {
    if (preg_match('/<.*>$/',$from))
    {
      $this->from = $from;
    }
    else
    {
      $this->from = '<'.$from.'>';
    }
    
    $m = array();
    if (!preg_match('/sip:(.*)@/i',$this->from,$m))
    {
      throw new PhpSIPException('Failed to parse From username.');
    }
    
    $this->from_user = $m[1];
  }
  
  /**
   * Sets To header
   * 
   * @param string $to
   */
  public function setTo($to)
  {
    if (preg_match('/<.*>$/',$to))
    {
      $this->to = $to;
    }
    else
    {
      $this->to = '<'.$to.'>';
    }
  }
  
  /**
   * Sets method
   * 
   * @param string $method
   */
  public function setMethod($method)
  {
    if (!in_array($method,$this->allowed_methods))
    {
      throw new PhpSIPException('Invalid method.');
    }
    
    $this->method = $method;
    
    if ($method == 'INVITE')
    {
      $body = "v=0\r\n";
      $body.= "o=click2dial 0 0 IN IP4 ".$this->src_ip."\r\n";
      $body.= "s=click2dial call\r\n";
      $body.= "c=IN IP4 ".$this->src_ip."\r\n";
      $body.= "t=0 0\r\n";
      $body.= "m=audio 8000 RTP/AVP 0 8 18 3 4 97 98\r\n";
      $body.= "a=rtpmap:0 PCMU/8000\r\n";
      $body.= "a=rtpmap:18 G729/8000\r\n";
      $body.= "a=rtpmap:97 ilbc/8000\r\n";
      $body.= "a=rtpmap:98 speex/8000\r\n";
      
      $this->body = $body;
      
      $this->setContentType(null);
    }
    
    if ($method == 'REFER')
    {
      $this->setBody('');
    }
    
    if ($method == 'CANCEL')
    {
      $this->setBody('');
      $this->setContentType(null);
    }
    
    if ($method == 'MESSAGE' && !$this->content_type)
    {
      $this->setContentType(null);
    }
  }
  
  /**
   * Sets SIP Proxy
   * 
   * @param $proxy
   */
  public function setProxy($proxy)
  {
    $this->proxy = $proxy;
    
    if (strpos($this->proxy,':'))
    {
      $temp = explode(":",$this->proxy);
      
      if (!preg_match('/^[0-9]+$/',$temp[1]))
      {
        throw new PhpSIPException("Invalid port number ".$temp[1]);
      }
      
      $this->host = $temp[0];
      $this->port = $temp[1];
    }
    else
    {
      $this->host = $this->proxy;
    }
  }
  
  /**
   * Sets Contact header
   * 
   * @param $v
   */
  public function setContact($v)
  {
    $this->contact = $v;
  }
  
  /**
   * Sets request URI
   *
   * @param string $uri
   */
  public function setUri($uri)
  {
    if (strpos($uri,'sip:') === false)
    {
      throw new PhpSIPException("Only sip: URI supported.");
    }
    
    if (!$this->proxy && strpos($uri,'transport=tcp') !== false)
    {
      throw new PhpSIPException("Only UDP transport supported.");
    }
    
    $this->uri = $uri;
    
    if (!$this->to)
    {
      $this->to = '<'.$uri.'>';
    }
    
    if ($this->proxy)
    {
      if (strpos($this->proxy,':'))
      {
        $temp = explode(":",$this->proxy);
        
        $this->host = $temp[0];
        $this->port = $temp[1];
      }
      else
      {
        $this->host = $this->proxy;
      }
    }
    else
    {
      $uri = ($t_pos = strpos($uri,";")) ? substr($uri,0,$t_pos) : $uri;
      
      $url = str_replace("sip:","sip://",$uri);
      
      if (!$url = @parse_url($url))
      {
        throw new PhpSIPException("Failed to parse URI '$url'.");
      }
      
      $this->host = $url['host'];
      
      if (isset($url['port']))
      {
        $this->port = $url['port'];
      }
    }
  }
  
  /**
   * Sets username
   *
   * @param string $username
   */
  public function setUsername($username)
  {
    $this->username = $username;
  }
  
  /**
   * Sets User Agent
   *
   * @param string $user_agent
   */
  public function setUserAgent($user_agent)
  {
    $this->user_agent = $user_agent;
  }
  
  /**
   * Sets password
   *
   * @param string $password
   */
  public function setPassword($password)
  {
    $this->password = $password;
  }
  
  /**
   * Sends SIP Request
   * 
   * @return string Reply 
   */
  public function send()
  {
    if (!$this->from)
    {
      throw new PhpSIPException('Missing From.');
    }
    
    if (!$this->method)
    {
      throw new PhpSIPException('Missing Method.');
    }
    
    if (!$this->uri)
    {
      throw new PhpSIPException('Missing URI.');
    }
    
    $data = $this->formatRequest();
    
    $this->sendData($data);
    
    $this->readMessage();
    
    if ($this->method == 'CANCEL' && $this->res_code == '200')
    {
      $i = 0;
      while (substr($this->res_code,0,1) != '4' && $i < 2)
      {
        $this->readMessage();
        $i++;
      }
    }
    
    if ($this->res_code == '407')
    {
      $this->cseq++;
      
      $this->auth();
      
      $data = $this->formatRequest();
      
      $this->sendData($data);
      
      $this->readMessage();
    }
    
    if ($this->res_code == '401')
    {
      $this->cseq++;
      
      $this->authWWW();
      
      $data = $this->formatRequest();
      
      $this->sendData($data);
      
      $this->readMessage();
    }
    
    if (substr($this->res_code,0,1) == '1')
    {
      $i = 0;
      while (substr($this->res_code,0,1) == '1' && $i < 4)
      {
        $this->readMessage();
        $i++;
      }
    }
    
    $this->extra_headers = array();
    $this->cseq++;
    
    return $this->res_code;
  }
  
  /**
   * Sends data
   */
  private function sendData($data)
  {
    if (!$this->host)
    {
      throw new PhpSIPException("Can't send data, host undefined");
    }
    
    if (!$this->port)
    {
      throw new PhpSIPException("Can't send data, host undefined");
    }
    
    if (!$data)
    {
      throw new PhpSIPException("Can't send - empty data");
    }
    
    if (preg_match('/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/', $this->host))
    {
      $ip_address = $this->host;
    }
    else
    {
      $ip_address = gethostbyname($this->host);
      
      if ($ip_address == $this->host)
      {
        throw new PhpSIPException("DNS resolution of ".$this->host." failed");
      }
    }
    
    if (!@socket_sendto($this->socket, $data, strlen($data), 0, $ip_address, $this->port))
    {
      $err_no = socket_last_error($this->socket);
      throw new PhpSIPException("Failed to send data to ".$ip_address.":".$this->port.". Source IP ".$this->src_ip.", source port: ".$this->src_port.". ".socket_strerror($err_no));
    }
    
    if ($this->debug)
    {
      $temp = explode("\r\n",$data);
      
      echo "--> ".$temp[0]."\n";
    }
  }
  
  /**
   * Listen for request
   * 
   * @param mixed $method string or array
   */
  public function listen($methods)
  { 
    if (!is_array($methods))
    {
      $methods = array($methods);
    }
    
    if ($this->debug)
    {
      echo "Listenning for ".implode(", ",$methods)."\n";
    }
    
    if ($this->server_mode)
    {
      while (!in_array($this->req_method, $methods))
      {
        $this->readMessage(); 
        
        if ($this->rx_msg && !in_array($this->req_method, $methods))
        {
          $this->reply(200,'OK');
        }
      }
    }
    else
    {
      $i = 0;
      $this->req_method = null;
    
      while (!in_array($this->req_method, $methods))
      {
        $this->readMessage(); 
        
        $i++;
        
        if ($i > 5)
        {
          throw new PhpSIPException("Unexpected request ".$this->req_method." received.");
        }
      }
    }
  }
  
  /**
   * Sets server mode
   * 
   * @param bool $status
   */
  public function setServerMode($v)
  {
    if (!@socket_set_option($this->socket, SOL_SOCKET, SO_RCVTIMEO, array("sec"=>0,"usec"=>0)))
    {
      $err_no = socket_last_error($this->socket);
      throw new PhpSIPException (socket_strerror($err_no));
    }
    
    $this->server_mode = $v;
  }
  
  /**
   * Reads incoming SIP message
   */
  private function readMessage()
  {
    $from = "";
    $port = 0;
    $this->rx_msg = null;
    
    if (!@socket_recvfrom($this->socket, $this->rx_msg, 10000, 0, $from, $port))
    {
      $this->res_code = "No final response in ".round($this->fr_timer/1000,3)." seconds. (".socket_last_error($this->socket).")";
      return $this->res_code;
    }
    
    if ($this->debug)
    {
      $temp = explode("\r\n",$this->rx_msg);
      
      echo "<-- ".$temp[0]."\n";
    }
    
    // Response
    $m = array();
    if (preg_match('/^SIP\/2\.0 ([0-9]{3})/', $this->rx_msg, $m))
    {
      $this->res_code = trim($m[1]);
      
      $this->parseResponse();
    }
    // Request
    else
    {
      $this->parseRequest();
    }
    
    // is diablog establised?
    if (in_array(substr($this->res_code,0,1),array("1","2")) && $this->from_tag && $this->to_tag && $this->call_id)
    {
      if ($this->debug && !$this->dialog)
      {
        echo "  New dialog: ".$this->from_tag.'.'.$this->to_tag.'.'.$this->call_id."\n";
      }
      
      $this->dialog = $this->from_tag.'.'.$this->to_tag.'.'.$this->call_id;
    }
  }
  
  /**
   * Parse Response
   */
  private function parseResponse()
  {
    // Request via
    $m = array();
    $this->req_via = array();
    
    if (preg_match_all('/^Via: (.*)$/im', $this->rx_msg, $m))
    {
      foreach ($m[1] as $via)
      {
        $this->req_via[] = trim($via);
      }
    }

    // Routes
    $this->parseRecordRoute();
    
    // To tag
    $m = array();
    if (preg_match('/^To: .*;tag=(.*)$/im', $this->rx_msg, $m))
    {
      $this->to_tag = trim($m[1]);
    }
    
    // Response contact
    $this->res_contact = $this->parseContact();
    
    // Response CSeq method
    $this->res_cseq_method = $this->parseCSeqMethod();
    
    // ACK 2XX-6XX - only invites - RFC3261 17.1.2.1
    if ($this->res_cseq_method == 'INVITE' && in_array(substr($this->res_code,0,1),array('2','3','4','5','6')))
    {
      $this->ack();
    }
    
    return $this->res_code;
  }
  
  /**
   * Parse Request
   */
  private function parseRequest()
  {
    $temp = explode("\r\n",$this->rx_msg);
    $temp = explode(" ",$temp[0]);
    
    $this->req_method = trim($temp[0]);
    
    // Routes
    $this->parseRecordRoute();
    
    // Request via
    $m = array();
    $this->req_via = array();
    if (preg_match_all('/^Via: (.*)$/im',$this->rx_msg,$m))
    {
      if ($this->server_mode)
      {
        // set $this->host to top most via
        $m2 = array();
        if (preg_match('/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/',$m[1][0],$m2))
        {
          $this->host = $m2[0];
        }
      }
      
      foreach ($m[1] as $via)
      {
        $this->req_via[] = trim($via);
      }
    }
    
    // Request contact
    $this->req_contact = $this->parseContact();
    
    // Request CSeq method
    $this->req_cseq_method = $this->parseCSeqMethod();

    // Request CSeq number
    $m = array();
    
    if (preg_match('/^CSeq: ([0-9]+)/im', $this->rx_msg, $m))
    {
      $this->req_cseq_number = trim($m[1]);
    }

    // Request From
    $m = array();
    if (preg_match('/^From: (.*)/im', $this->rx_msg, $m))
    {
      $this->req_from = (strpos($m[1],';')) ? substr($m[1],0,strpos($m[1],';')) : $m[1];
    }
    
    // Request From tag
    $m = array();
    if (preg_match('/^From:.*;tag=(.*)$/im', $this->rx_msg, $m))
    {
      $this->req_from_tag = trim($m[1]);
    }
    
    // Request To
    $m = array();
    if (preg_match('/^To: (.*)/im', $this->rx_msg, $m))
    {
      $this->req_to = (strpos($m[1],';')) ? substr($m[1],0,strpos($m[1],';')) : $m[1];
    }
    
    // Request To tag
    $m = array();
    if (preg_match('/^To:.*;tag=(.*)$/im', $this->rx_msg, $m))
    {
      $this->req_to_tag = trim($m[1]);
    }
    else
    {
      $this->req_to_tag = rand(10000,99999);
    }
    
    // Call-id
    if (!$this->call_id)
    {
      $m = array();
      if (preg_match('/^Call-ID:(.*)$/im', $this->rx_msg, $m))
      {
        $this->call_id = trim($m[1]);
      }
    }
  }
  
  /**
   * Send Response
   * 
   * @param int $code     Response code
   * @param string $text  Response text
   */
  public function reply($code, $text)
  {
    $r = 'SIP/2.0 '.$code.' '.$text."\r\n";
    
    // Via
    foreach ($this->req_via as $via)
    {
      $r.= 'Via: '.$via."\r\n";
    }
    
    // Record-route
    foreach ($this->record_route as $record_route)
    {
      $r.= 'Record-Route: '.$record_route."\r\n";
    }
    
    // From
    $r.= 'From: '.$this->req_from.';tag='.$this->req_from_tag."\r\n";
    
    // To
    $r.= 'To: '.$this->req_to.';tag='.$this->req_to_tag."\r\n";
    
    // Call-ID
    $r.= 'Call-ID: '.$this->call_id."\r\n";
    
    //CSeq
    $r.= 'CSeq: '.$this->req_cseq_number.' '.$this->req_cseq_method."\r\n";
    
    // Max-Forwards
    $r.= 'Max-Forwards: 70'."\r\n";
    
    // User-Agent
    $r.= 'User-Agent: '.$this->user_agent."\r\n";
    
    // Content-Length
    $r.= 'Content-Length: 0'."\r\n";
    $r.= "\r\n";
    
    $this->sendData($r);
  }
  
  /**
   * ACK
   */
  private function ack()
  {
    if ($this->res_cseq_method == 'INVITE' && $this->res_code == '200')
    {
      $a = 'ACK '.$this->res_contact.' SIP/2.0'."\r\n";
    }
    else
    {
      $a = 'ACK '.$this->uri.' SIP/2.0'."\r\n";
    }
    
    // Via
    $a.= 'Via: '.$this->via."\r\n";
    
    // Route
    if ($this->routes)
    {
      $a.= 'Route: '.implode(",",array_reverse($this->routes))."\r\n";
    }
    
    // From 
    if (!$this->from_tag)
    {
      $this->from_tag = rand(10000,99999);
    }
    
    $a.= 'From: '.$this->from.';tag='.$this->from_tag."\r\n";
    
    // To
    if ($this->to_tag)
    {
      $a.= 'To: '.$this->to.';tag='.$this->to_tag."\r\n";
    }
    else
    {
      $a.= 'To: '.$this->to."\r\n";
    }
    
    // Call-ID
    if (!$this->call_id)
    {
      $this->setCallId();
    }
    
    $a.= 'Call-ID: '.$this->call_id."\r\n";
    
    //CSeq
    $a.= 'CSeq: '.$this->cseq.' ACK'."\r\n";
    
    // Authentication
    if ($this->res_code == '200' && $this->auth)
    {
      $a.= 'Proxy-Authorization: '.$this->auth."\r\n";
    }
    
    // Max-Forwards
    $a.= 'Max-Forwards: 70'."\r\n";
    
    // User-Agent
    $a.= 'User-Agent: '.$this->user_agent."\r\n";
    
    // Content-Length
    $a.= 'Content-Length: 0'."\r\n";
    $a.= "\r\n";
    
    $this->sendData($a);
  }
  
  /**
   * Formats SIP request
   * 
   * @return string
   */
  private function formatRequest()
  {
    if ($this->res_contact && in_array($this->method,array('BYE','REFER','SUBSCRIBE')))
    {
      $r = $this->method.' '.$this->res_contact.' SIP/2.0'."\r\n";
    }
    else
    {
      $r = $this->method.' '.$this->uri.' SIP/2.0'."\r\n";
    }
    
    // Via
    if ($this->method != 'CANCEL')
    {
      $this->setVia();
    }
    
    $r.= 'Via: '.$this->via."\r\n";
    
    // Route
    if ($this->method != 'CANCEL' && $this->routes)
    {
      $r.= 'Route: '.implode(",",array_reverse($this->routes))."\r\n";
    }
    
    // From
    if (!$this->from_tag)
    {
      $this->from_tag = rand(10000,99999);
    }
    
    $r.= 'From: '.$this->from.';tag='.$this->from_tag."\r\n";
    
    // To
    if ($this->to_tag && !in_array($this->method,array("INVITE","CANCEL","NOTIFY","REGISTER")))
    {
      $r.= 'To: '.$this->to.';tag='.$this->to_tag."\r\n";
    }
    else
    {
      $r.= 'To: '.$this->to."\r\n";
    }
    
    // Authentication
    if ($this->auth)
    {
      $r.= $this->auth."\r\n";
      $this->auth = null;
    }
    
    // Call-ID
    if (!$this->call_id)
    {
      $this->setCallId();
    }
    
    $r.= 'Call-ID: '.$this->call_id."\r\n";
    
    //CSeq
    if ($this->method == 'CANCEL')
    {
      $this->cseq--;
    }
    
    $r.= 'CSeq: '.$this->cseq.' '.$this->method."\r\n";
    
    // Contact
    if ($this->contact)
    {
      if (substr($this->contact,0,1) == "<") {
        $r.= 'Contact: '.$this->contact."\r\n";
      } else {
        $r.= 'Contact: <'.$this->contact.'>'."\r\n";
      }
    }
    else if ($this->method != 'MESSAGE')
    {
      $r.= 'Contact: <sip:'.$this->from_user.'@'.$this->src_ip.':'.$this->src_port.'>'."\r\n";
    }
    
    // Content-Type
    if ($this->content_type)
    {
      $r.= 'Content-Type: '.$this->content_type."\r\n";
    }
    
    // Max-Forwards
    $r.= 'Max-Forwards: 70'."\r\n";
    
    // User-Agent
    $r.= 'User-Agent: '.$this->user_agent."\r\n";
    
    // Additional header
    foreach ($this->extra_headers as $header)
    {
      $r.= $header."\r\n";
    }
    
    // Content-Length
    $r.= 'Content-Length: '.strlen($this->body)."\r\n";
    $r.= "\r\n";
    $r.= $this->body;
    
    return $r;
  }
  
  /**
   * Sets body
   */
  public function setBody($body)
  {
    $this->body = $body;
  }
  
  /**
   * Sets Content Type
   */
  public function setContentType($content_type = null)
  {
    if ($content_type !== null)
    {
      $this->content_type = $content_type;
    }
    else
    {
      switch ($this->method)
      {
        case 'INVITE':
          $this->content_type = 'application/sdp';
          break;
        case 'MESSAGE':
          $this->content_type = 'text/html; charset=utf-8';
          break;
        default:
          $this->content_type = null;
      }
    }
  }
  
  /**
   * Sets Via header
   */
  private function setVia()
  {
    $rand = rand(100000,999999);
    $this->via = 'SIP/2.0/UDP '.$this->src_ip.':'.$this->src_port.';rport;branch=z9hG4bK'.$rand;
  }
  
  /**
   * Sets from tag
   * 
   * @param string $v
   */
  public function setFromTag($v)
  {
    $this->from_tag = $v;
  }
  
  /**
   * Sets to tag
   * 
   * @param string $v
   */
  public function setToTag($v)
  {
    $this->to_tag = $v;
  }
  
  /**
   * Sets cseq
   * 
   * @param string $v
   */
  public function setCseq($v)
  { 
    $this->cseq = $v;
  }
  
  /**
   * Sets call id
   * 
   * @param string $v
   */
  public function setCallId($v = null)
  {
    if ($v)
    {
      $this->call_id = $v;
    }
    else
    {
      $this->call_id = md5(uniqid()).'@'.$this->src_ip;
    }
  }
  
  /**
   * Gets value of the header from the previous request
   * 
   * @param string $name Header name
   * 
   * @return string or false
   */
  public function getHeader($name)
  {
    $m = array();
    
    if (preg_match('/^'.$name.': (.*)$/im', $this->rx_msg, $m))
    {
      return trim($m[1]);
    }
    else
    {
      return false;
    }
  }
  
  /**
   * Gets body from previous request
   * 
   * @return string
   */
  public function getBody()
  {
    $temp = explode("\r\n\r\n",$this->rx_msg);
    
    if (!isset($temp[1]))
    {
      return '';
    }
    
    return $temp[1];
  }
  
  /**
   * Calculates Digest authentication response
   * 
   */
  private function auth()
  {
    if (!$this->username)
    {
      throw new PhpSIPException("Missing username");
    }
    
    if (!$this->password)
    {
      throw new PhpSIPException("Missing password");
    }
    
    // realm
    $m = array();
    if (!preg_match('/^Proxy-Authenticate: .* realm="(.*)"/imU',$this->rx_msg, $m))
    {
      throw new PhpSIPException("Can't find realm in proxy-auth");
    }
    
    $realm = $m[1];
    
    // nonce
    $m = array();
    if (!preg_match('/^Proxy-Authenticate: .* nonce="(.*)"/imU',$this->rx_msg, $m))
    {
      throw new PhpSIPException("Can't find nonce in proxy-auth");
    }
    
    $nonce = $m[1];
    
    $ha1 = md5($this->username.':'.$realm.':'.$this->password);
    $ha2 = md5($this->method.':'.$this->uri);
    
    $res = md5($ha1.':'.$nonce.':'.$ha2);
    
    $this->auth = 'Proxy-Authorization: Digest username="'.$this->username.'", realm="'.$realm.'", nonce="'.$nonce.'", uri="'.$this->uri.'", response="'.$res.'", algorithm=MD5';
  }
  
  /**
   * Calculates WWW authorization response
   * 
   */
  private function authWWW()
  {
    if (!$this->username)
    {
      throw new PhpSIPException("Missing auth username");
    }
    
    if (!$this->password)
    {
      throw new PhpSIPException("Missing auth password");
    }
    
    $qop_present = false;
    if (strpos($this->rx_msg,'qop=') !== false)
    {
      $qop_present = true;
      
      // we can only do qop="auth"
      if  (strpos($this->rx_msg,'qop="auth"') === false)
      {
        throw new PhpSIPException('Only qop="auth" digest authentication supported.');
      }
    }
    
    // realm
    $m = array();
    if (!preg_match('/^WWW-Authenticate: .* realm="(.*)"/imU',$this->rx_msg, $m))
    {
      throw new PhpSIPException("Can't find realm in www-auth");
    }
    
    $realm = $m[1];
    
    // nonce
    $m = array();
    if (!preg_match('/^WWW-Authenticate: .* nonce="(.*)"/imU',$this->rx_msg, $m))
    {
      throw new PhpSIPException("Can't find nonce in www-auth");
    }
    
    $nonce = $m[1];
    
    $ha1 = md5($this->username.':'.$realm.':'.$this->password);
    $ha2 = md5($this->method.':'.$this->uri);
    
    if ($qop_present)
    {
      $cnonce = md5(time());
      
      $res = md5($ha1.':'.$nonce.':00000001:'.$cnonce.':auth:'.$ha2);
    }
    else
    {
      $res = md5($ha1.':'.$nonce.':'.$ha2);
    }
    
    $this->auth = 'Authorization: Digest username="'.$this->username.'", realm="'.$realm.'", nonce="'.$nonce.'", uri="'.$this->uri.'", response="'.$res.'", algorithm=MD5';
    
    if ($qop_present)
    {
      $this->auth.= ', qop="auth", nc="00000001", cnonce="'.$cnonce.'"';
    }
  }
  
  /**
   * Create network socket
   *
   * @return bool True on success
   */
  private function createSocket()
  { 
    $this->getPort();
    
    if (!$this->src_ip)
    {
      throw new PhpSIPException("Source IP not defined.");
    }
    
    if (!$this->socket = @socket_create(AF_INET, SOCK_DGRAM, SOL_UDP))
    {
      $err_no = socket_last_error($this->socket);
      throw new PhpSIPException (socket_strerror($err_no));
    }
    
    if (!@socket_bind($this->socket, $this->src_ip, $this->src_port))
    {
      $err_no = socket_last_error($this->socket);
      throw new PhpSIPException ("Failed to bind ".$this->src_ip.":".$this->src_port." ".socket_strerror($err_no));
    }
    
    $microseconds = $this->fr_timer * 1000;
    
    $usec = $microseconds % 1000000;
    
    $sec = floor($microseconds / 1000000);
    
    if (!@socket_set_option($this->socket, SOL_SOCKET, SO_RCVTIMEO, array("sec"=>$sec,"usec"=>$usec)))
    {
      $err_no = socket_last_error($this->socket);
      throw new PhpSIPException (socket_strerror($err_no));
    }
    
    if (!@socket_set_option($this->socket, SOL_SOCKET, SO_SNDTIMEO, array("sec"=>5,"usec"=>0)))
    {
      $err_no = socket_last_error($this->socket);
      throw new PhpSIPException (socket_strerror($err_no));
    }
  }
  
  /**
   * Close the connection
   *
   * @return bool True on success
   */
  private function closeSocket()
  {
    socket_close($this->socket);
    
    $this->releasePort();
  }
  
  /**
   * Resets callid, to/from tags etc.
   * 
   */
  public function newCall()
  {
    $this->cseq = 20;
    $this->call_id = null;
    $this->to = null;
    $this->to_tag = null;
    $this->from = null;
    $this->from_tag = null;
    
    /**
     * Body
     */
    $this->body = null;
    
    /**
     * Received Response
     */
    $this->rx_msg = null;
    $this->res_code = null;
    $this->res_contact = null;
    $this->res_cseq_method = null;
    $this->res_cseq_number = null;

    /**
     * Received Request
     */
    $this->req_via = array();
    $this->req_method = null;
    $this->req_cseq_method = null;
    $this->req_cseq_number = null;
    $this->req_contact = null;
    $this->req_from = null;
    $this->req_from_tag = null;
    $this->req_to = null;
    $this->req_to_tag = null;
    
    $this->routes = array();
  }

  /**
   * Parses Record-Route header
   * 
   * @return array
   */
  private function parseRecordRoute()
  {
    $this->record_route = array();
    
    $m = array();
    
    if (preg_match_all('/^Record-Route: (.*)$/im', $this->rx_msg, $m))
    {
      foreach ($m[1] as $route_header)
      {
        $this->record_route[] = $route_header;
        
        foreach (explode(",",$route_header) as $route)
        {
          if (!in_array(trim($route), $this->routes))
          {
            $this->routes[] = trim($route);
          }
        }
      }
    }
  }
  
  /**
   * Parses Contact header
   * 
   * @return string ro null
   */
  private function parseContact()
  {
    $output = null;
    
    $m = array();
    
    if (preg_match('/^Contact:.*<(.*)>/im', $this->rx_msg, $m))
    {
      $output = trim($m[1]);
      
      $semicolon = strpos($output, ";");
      
      if ($semicolon !== false)
      {
        $output = substr($output, 0, $semicolon);
      }
    }
    
    return $output;
  }

  /**
   * Parse METHOD from CSeq header
   * 
   * @return string or null
   */
  private function parseCSeqMethod()
  {
    $output = null;
    
    $m = array();
    
    if (preg_match('/^CSeq: [0-9]+ (.*)$/im', $this->rx_msg, $m))
    {
      $output = trim($m[1]);
    }
    
    return $output;
  }
}

?>
