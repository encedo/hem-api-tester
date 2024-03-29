<?php

// there is a known bug related to OpenSSL and PHP
// https://github.com/php/php-src/issues/8369
// Turn off all error reporting
//error_reporting(E_ERROR| E_PARSE);


// set the default timezone to use.
date_default_timezone_set('UTC');


function init_env() {

	//get global variables
	global $cfg_domain, $cfg_epa_domain, $cfg_ppa_domain, $cfg_tester, $cfg_debug, $cfg_epa_chipid, $argv;

	//set defaults
	$cfg_domain = $cfg_ppa_domain;

	//first parse env variables
	$arg = getenv('EPA');
	if ($arg != false) {
    $cfg_domain =  "c$cfg_epa_chipid.$cfg_epa_domain";
	}

	$arg = getenv('DEBUG');
	if ( $arg != false ) {
    $cfg_debug = intval($arg);
	}
	
	$arg = getenv('TESTER');
	if (($arg != false) && (is_string($arg))) {
    $cfg_tester = $arg;
	}

	// parse env argument
	if (isset($argv[1]) && ($argv[1] == "epa")) {
    $cfg_domain =  "c$cfg_epa_chipid.$cfg_epa_domain";
	}
}

function parseHeaders( $headers )
{
    $head = array();
    foreach( $headers as $k=>$v )
    {
        $t = explode( ':', $v, 2 );
        if( isset( $t[1] ) )
            $head[ trim($t[0]) ] = trim( $t[1] );
        else
        {
            $head[] = $v;
            if( preg_match( "#HTTP/[0-9\.]+\s+([0-9]+)#",$v, $out ) )
                $head['reponse_code'] = intval($out[1]);
        }
    }
    return $head;
}

function http_transaction($protocol, $method, $domain, $path, &$ret_data = false, &$post_data = false, $token = false, $upload_file = false) {
  global $cfg_debug;

  if ($cfg_debug >= 2) echo "HTTP Transaction\n";

  if (($protocol !== "http") && ($protocol !== "https")) return false;
  if (($method !== "GET") && ($method !== "POST") && ($method !== "DELETE")) return false;

  if (($post_data !== false) && ($method == "POST")) {
    if ( is_array($post_data) ) {
      $postdata = json_encode( $post_data);
      if ($postdata == false) return false;
    } else {
      $postdata = $post_data;
    }
  }

  $url = $protocol . "://" . $domain . $path;
  if ($cfg_debug >= 2) echo "URL: $url\n";

  $opts = array(
    'http' => array(
      'method' => $method,
      'header' => "Content-Type: application/json\r\n",
      'timeout' => 12.0,
      'ignore_errors' => '1'
    ),
    'ssl' => array(
      'capture_session_meta' => TRUE,
      'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT,
      'verify_peer' => true,           //validate peer and name - in short: validates cert trust
      'verify_peer_name' => true,      //
    )
  );

  if (isset($postdata)) {
    $opts['http']['content'] = $postdata;
  }

  if (isset($token) && (strlen($token) > 0) ) {
     $opts['http']['header'] = $opts['http']['header'] . "Authorization: Bearer $token\r\n";
  }
  
  if ($upload_file != false) {
    if ($token != false) {
      $opts['http']['header'] = "Authorization: Bearer $token\r\n" . "Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"$upload_file\"\r\n";
    } else {
      $opts['http']['header'] = "Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"$upload_file\"\r\n";
    }
    $opts['http']['timeout'] = 20;
  }

  if ($cfg_debug >= 2) {echo "Opts: "; var_dump($opts);}

  $context = stream_context_create($opts);
  if ($context == false) return false;
    
  $cont = @file_get_contents($url, false, $context);
  if ($cont === false) {
    if ($cfg_debug >= 2) echo "\nHTTP Transaction error!\n";
    return false;
  }

  if (!isset($http_response_header) || ($http_response_header == false)) {
    if ($cfg_debug >= 2) echo "\nHTTP Response headers error!\n";
    return false;
  }

  $hdrs = parseHeaders($http_response_header);    
  if ($cfg_debug >= 2) {echo "Headers: "; var_dump($hdrs);}
  
  if ( (isset($hdrs["Content-Length"])) && (intval($hdrs["Content-Length"]) > 0) ) {
    $len = intval($hdrs["Content-Length"]);
    $ret_data = false;
	  if ($len > 0) {
      if (strstr($hdrs["Content-Type"], "/json")) {
        $ret_data = json_decode($cont, true);
        if ($cfg_debug >= 2) {echo "Resposne: "; var_dump($ret_data);}
      } else {
        $ret_data = $cont;
      }
	  }
  }

  return $hdrs["reponse_code"];
}


function check_tls($domain) {
  $streamContext = stream_context_create([
    'ssl' => [
      'verify_peer' => true,         //validate peer and name - in short: validates cert trust
      'verify_peer_name' => true,    //
      'capture_peer_cert' => true,
      'capture_peer_cert_chain' => true,
      'disable_compression' => true,
    ],
  ]);

  if ($streamContext == false) return false;

  $client = stream_socket_client(
    "ssl://$domain:443",
    $errorNumber,
    $errorDescription,
    40,
    STREAM_CLIENT_CONNECT,
    $streamContext
  );

  if ($client == false) return false;

  return stream_get_meta_data($client)['crypto'];  
}


// generate Encedo-specific JWT token - standard JWT header has extra 'ecdh' and sigrnature is based on ECDH secret
function ejwt_generate($body_array, $my_secret_raw, $ext_pubkey_raw) {
  $ejwt_hdr = array (
    'alg'  => "HS256",
    'typ'  => "JWT",
    'ecdh' => "x25519"
  );
  
  $hdr = rtrim( strtr( base64_encode( json_encode($ejwt_hdr) ), '+/', '-_'), '=');      //JWT header
  $bdy = rtrim( strtr( base64_encode( json_encode($body_array) ), '+/', '-_'), '=');    //JWT body

  $ejwt = $hdr . "." . $bdy;
  
  $secret = sodium_crypto_scalarmult($my_secret_raw, $ext_pubkey_raw);                      //ECDH secret
  $signature = hash_hmac("sha256", $ejwt, $secret, true);
  $sig = rtrim( strtr( base64_encode( $signature ), '+/', '-_'), '=');                  //JWT signature
  
  $ejwt = $ejwt . "." . $sig;                                                           //final JWT string
  
  return $ejwt;
}


function init_test($test_name, $test_descr, $test_subtest_cnt, $tester) {
  $_cfg = array( 
    'title' => $test_name,
    'descr' => $test_descr,
    'testername' => $tester,
    'ts' => date("c"),
    'conf' => "???",
    'hwv' => "???",
    'fwv' => "???",
    'blv' => "???",
    'result' => "FAIL"
  );
  if ( is_array($test_subtest_cnt) ) {
    $_cfg['subtests'] = $test_subtest_cnt;
  } else {
    $_cfg['subtests'] = array_fill(1, $test_subtest_cnt, '- skipped -');
  }
  return $_cfg;
}


function print_result($result_array) {
  
  $test_name    = $result_array['title'];
  $test_descr   = $result_array['descr'];
  $tester       = $result_array['testername'];
  $timestamp    = $result_array['ts'];
  $version_conf = $result_array['conf'];
  $version_hwv  = $result_array['hwv'];
  $version_fwv  = $result_array['fwv'];
  $version_blv  = $result_array['blv'];
  $subtests     = $result_array['subtests'];
  $result       = $result_array['result'];

  printf("************************************************************\n");
  printf("*** Test %-47s ***\n", $test_name);
  printf("*** %-52s ***\n", $test_descr);
  printf("***                                                      ***\n");
  printf("*** Tester: %-44s ***\n", $tester);
  printf("*** Timestamp: %-41s ***\n", $timestamp);

  printf("*** Configuration: %-37s ***\n",$version_conf);
  printf("*** Version information:                                 ***\n");
  printf("***   HWV: %-44s  ***\n", $version_hwv);
  printf("***   BLV: %-44s  ***\n", $version_blv);
  printf("***   FWV: %-44s  ***\n", $version_fwv);
  printf("***                                                      ***\n");
  printf("*** Subtest summary:                                     ***\n");
  foreach($subtests as $test_id => $test_summary) {
    printf("***    %-8s    %-37s ***\n", $test_name.'.'.$test_id.':', $test_summary);
  }
  printf("*** Test result:   %-37s ***\n", $result);
  printf("************************************************************\n");
  printf("**********************  END OF TEST  ***********************\n");  
}


function helper_checkin($cfg_domain) {
  $ret_val = false;
  $ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/checkin", $ret_val);
  if ( $ret_stat != 200 ) return false;
  if ( !isset($ret_val['check']) ) return false;
  $post_data = $ret_val;
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", "api.encedo.com", "/checkin", $ret_val, $post_data);
  if ( $ret_stat != 200 ) return false;
  if ( !isset($ret_val['checked']) ) return false;
  $post_data = $ret_val;
  $ret_val = false;
  $ret_stat = http_transaction("http", "POST", $cfg_domain, "/api/system/checkin", $ret_val, $post_data);
  if ( $ret_stat != 200 ) return false;
  if ( !isset($ret_val['status']) ) return false;

  return true;
}


function helper_authorize($cfg_domain, $password, $scope = "scope", $exp = 3600) {
  $ret_val = false;
  $ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/auth/token", $ret_val);
  if ( $ret_stat != 200 ) return false;
  $auth_challange = $ret_val;
  //generate authentication kesy based on config constants
  $salt = base64_decode( $auth_challange['eid'] );
  $user_secret = hash_pbkdf2("sha256", $password, $salt, 2048, 32, true);
  $user_public_key = sodium_crypto_box_publickey_from_secretkey($user_secret);
  //echo "USER Private key: " . base64_encode($user_secret) . "\n";
  //echo "USER Public key:  " . base64_encode($user_public_key) . "\n";
  $ext_pubkey = base64_decode($auth_challange['spk']);
  $auth_val_user = array(                                 
    'jti' => $auth_challange['jti'],
    'aud' => $auth_challange['spk'],
    'exp' => time() + $exp,
    'iat' => time(),
    'iss' => base64_encode($user_public_key),
    'scope' => $scope
    );
  unset($auth_challange);  
  //authentication USER and get token
  $auth_data_user = ejwt_generate($auth_val_user, $user_secret, $ext_pubkey);
  $post_data = json_encode( array('auth' => $auth_data_user) );
  $ret_val = false;
  $ret_stat = http_transaction("http", "POST", $cfg_domain, "/api/auth/token", $ret_val, $post_data);
  if ( $ret_stat != 200 ) return false;
  $user_auth_token = $ret_val['token'];
  //echo "  USER token: $user_auth_token\n";
  //$token_parts = explode(".", $user_auth_token);
  //$token_details = json_decode(base64_decode($token_parts[1]), true);
  //echo "    scope=" . $token_details['scope'] ." role=" . $token_details['sub'] . " expire=" . $token_details['exp'] . "\n";
  return $user_auth_token;
}


function base64url_encode($data) {
  return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}


function base64url_decode($data) {
  return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
}


function encedo_log_integrity_check($pubkey, $log_array, &$output_log){

  $output_log = "";
  $key = false;    //log entries HMAC key
  $cnt = 0;
  foreach($log_array as $line) {
    $rec = explode("|", $line);
    
    $cutoff = strrpos($line, '|') +1;
    $msg = substr($line, 0, $cutoff);
    $hmac = substr($line, $cutoff);
    
    if (($rec[2] == 0) && ($rec[3] == 0)) {
      
      if (isset($key)) $key2 = $key;
      $key = base64url_decode( $rec[4] );
      $signa = base64url_decode( $rec[5] );
      $ret = sodium_crypto_sign_verify_detached($signa, $key, $pubkey);
      if ($ret !== true) {
        echo "ERROR: Signature error on $hem at line: $cnt\n";
        return false;
      }
      $output_log = $output_log . "$line\n";
    } else {
      if ($key != false ) {
        $hmac_bin = base64url_decode( $hmac );
        $exp_hmac = hash_hmac("sha256", $msg, $key, true);
        $tst = base64url_encode($exp_hmac);
        if (strncmp($hmac_bin, $exp_hmac, 16) !== 0) {
          return false;
        }
        $cnt++;
        $output_log = $output_log . "$line\n";
      } else {
        //echo "> no key\n";
      }
    }
  }

  return true;  //all process, no errors found
}
