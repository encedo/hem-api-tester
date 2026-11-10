<?php

// there is a known bug related to OpenSSL and PHP
// https://github.com/php/php-src/issues/8369
// Turn off all error reporting
//error_reporting(E_ERROR| E_PARSE);


// set the default timezone to use.
date_default_timezone_set('UTC');

$cfg_debug_lib = 0;

function init_env() {

  //gte global variables
  global $cfg_domain, $cfg_epa_domain, $cfg_ppa_domain, $cfg_tester, $cfg_debug, $cfg_epa_chipid, $argv, $cfg_enforce_ppa_domain;

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
  if (isset($argv[1]) && (strtolower($argv[1]) == "epa")) {
    $cfg_domain =  "c$cfg_epa_chipid.$cfg_epa_domain";
    $cfg_enforce_ppa_domain = 0;
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

function http_transaction($protocol, $method, $domain, $path, &$ret_data = false, $post_data = false, $token = false, $upload_file = false) {   // DEV-502: $post_data by value (never written; by reference gave a notice for every json_encode() argument)

  global $cfg_debug_lib;

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

  $opts = array(
    'http' => array(
      'method' => $method,
      'header' => "Content-Type: application/json\r\n",
      'timeout' => 60.0,
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
    $opts['http']['timeout'] = 60;
  }

  $url = $protocol . "://" . $domain . $path;

  if ($cfg_debug_lib) {
    echo "HTTP Transaction: $method $url\n";
    var_dump($opts);
  }

  $context = stream_context_create($opts);
  if ($context == false) return false;
  $warn = array(); set_error_handler(function($no, $str) use (&$warn) { $warn[] = $str; return true; });	// DEV-473: all warnings of the request (the OpenSSL reason comes before "HTTP request failed!")
  $cont = file_get_contents($url, false, $context);
  restore_error_handler();
  if ($cont === false) {
    echo "  [http_transaction] $method $path: " . ($warn ? implode(" | ", $warn) : "no error info") . "\n";	// DEV-473
    return false;
  }


  // For PHP >= 8.4.0
  if (function_exists('http_get_last_response_headers')) {
    $http_response_header = http_get_last_response_headers();
  }

  if (!isset($http_response_header) || ($http_response_header == false)) return false;

  $hdrs = parseHeaders($http_response_header);
  if ( (isset($hdrs["Content-Length"])) && (intval($hdrs["Content-Length"]) > 0) ) {
    $len = intval($hdrs["Content-Length"]);
    $ret_data = false;
    if ($len > 0) {
      if (strstr($hdrs["Content-Type"], "/json")) {
        $ret_data = json_decode($cont, true);
      } else {
        $ret_data = $cont;
      }
    }
  }

  if ($cfg_debug_lib) {
    var_dump($hdrs);
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

  $meta = stream_get_meta_data($client);
  fclose($client);                                            // DEV-502: the probe connection was never closed
  return isset($meta['crypto']) ? $meta['crypto'] : false;    // DEV-502: no TLS session (e.g. the name resolves to another host) - was an undefined index warning and null
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

function formatDuration(int $seconds): string {
    $h = intdiv($seconds, 3600);
    $m = intdiv($seconds % 3600, 60);
    $s = $seconds % 60;

    $parts = [];
    if ($h > 0) {
        $parts[] = "{$h}h";
    }
    if ($m > 0 || $h > 0) { // pokazuj minuty tylko je�li s� lub by�a godzina
        $parts[] = "{$m}m";
    }
    $parts[] = "{$s}s";

    return implode(' ', $parts);
}


function print_result($result_array) {

  $elapsed      = formatDuration( intval($result_array['elapsed'] / 1000) );
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
  printf("*** Elapsed sec(s): %-36s ***\n", $elapsed);

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

// waits until the device is back after GET /api/system/reboot: status answers with an uptime that started after this call; max $timeout s
function helper_wait_reboot($cfg_domain, $timeout = 60) {   // DEV-502: replaces the fixed sleeps after a reboot
  $t0 = time();
  while ((time() - $t0) < $timeout) {
    sleep(1);
    $ret_val = false;
    $ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/status", $ret_val);
    if ( ($ret_stat == 200) && isset($ret_val['uptime']) && (intval($ret_val['uptime']) <= (time() - $t0)) ) return true;
  }
  return false;
}


function helper_authorize($cfg_domain, $password, $scope = "scope", $exp = 3600) {
  global $cfg_debug_lib;

  $ret_val = false;
  $ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/auth/token", $ret_val);
  if ($cfg_debug_lib) {
    var_dump($ret_stat);
    var_dump($ret_val);
  }
  if ( $ret_stat != 200 ) return false;
  $auth_challange = $ret_val;
  //generate authentication kesy based on config constants
  $salt = $auth_challange['eid'];
  $user_secret = hash_pbkdf2("sha256", $password, $salt, 600000, 32, true);
  $user_public_key = sodium_crypto_box_publickey_from_secretkey($user_secret);
  if ($cfg_debug_lib) {
    echo "USER password: \"$password \"\n";
    echo "USER Private key: " . base64_encode($user_secret) . "\n";
    echo "USER Public key:  " . base64_encode($user_public_key) . "\n";
  }
  $ext_pubkey = base64_decode($auth_challange['spk']);
  $iat = time() - 5;  //correction for time diff (just in case)
  $auth_val_user = array(
    'jti' => $auth_challange['jti'],
    'aud' => $auth_challange['spk'],
    'exp' => $iat + $exp,
    //'exp' => $auth_challange['exp'],
    'iat' => $iat,
    'iss' => base64_encode($user_public_key),
    'scope' => $scope
    );
  unset($auth_challange);
  //authentication USER and get token
  $auth_data_user = ejwt_generate($auth_val_user, $user_secret, $ext_pubkey);
  $post_data = json_encode( array('auth' => $auth_data_user) );
  $ret_val = false;
  $ret_stat = http_transaction("http", "POST", $cfg_domain, "/api/auth/token", $ret_val, $post_data);
  if ($cfg_debug_lib) {
    var_dump($ret_stat);
    var_dump($ret_val);
  }
  if ( $ret_stat != 200 ) return false;
  $user_auth_token = $ret_val['token'];
  if ($cfg_debug_lib) {
    echo "  USER token: $user_auth_token\n";
    $token_parts = explode(".", $user_auth_token);
    $token_details = json_decode(base64_decode($token_parts[1]), true);
    echo "    scope=" . $token_details['scope'] ." role=" . $token_details['sub'] . " expire=" . $token_details['exp'] . "\n";
  }
  return $user_auth_token;
}


function base64url_encode($data) {
  return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}


function base64url_decode($data) {
  return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
}


// DEV-484: ECDSA signature raw r || s -> ASN.1 DER (openssl_verify accepts DER only)
function ecdsa_rs2der($rs) {
  $der = '';
  foreach (str_split($rs, strlen($rs) / 2) as $int) {   // r, then s
    $int = ltrim($int, "\0");                           // DER INTEGER: no leading zero bytes,
    if ( ($int === '') || (ord($int[0]) >= 0x80) ) $int = "\0" . $int;   // but 0x00 in front when the top bit is set
    $der .= "\x02" . chr(strlen($int)) . $int;          // INTEGER
  }
  return "\x30" . ((strlen($der) > 0x7f) ? "\x81" : "") . chr(strlen($der)) . $der;   // SEQUENCE { r, s }; P-521 needs the long length form
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

      $key = base64url_decode( $rec[4] );
      $signa = base64url_decode( $rec[5] );
      $ret = sodium_crypto_sign_verify_detached($signa, $key, $pubkey);
      if ($ret !== true) {
        echo "ERROR: Signature error at line: $cnt\n";   // DEV-502: $hem was undefined here
        return false;
      }
      $output_log = $output_log . "$line\n";
    } else {
      if ($key != false ) {
        $hmac_bin = base64url_decode( $hmac );
        $exp_hmac = hash_hmac("sha256", $msg, $key, true);
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

  return ($cnt > 0);  //all process, no errors found; DEV-502 (V1): at least one HMAC line checked (was true with no key line)
}


// DEV-500: audit log v2 - every line signed with a per-file Ed25519 key, the key certified by the device log key (GET /api/logger/key)
// $report: version (1|2), lines, headers, rotations, lost, gaps[] ("prev->seq"), errors[]; v1 files go through encedo_log_integrity_check()
function encedo_log_verify($pubkey_dev, $log_array, &$report) {
  $report = array('version' => 0, 'lines' => 0, 'headers' => 0, 'rotations' => 0, 'lost' => 0, 'gaps' => array(), 'errors' => array());
  $pub = false;          // current per-file public key
  $rotate_pub = false;   // pub announced by the last LOGGER_KEY_ROTATE line
  $prev_seq = null;
  foreach ($log_array as $n => $line) {
    if (($line === '') || ($line[0] === '#')) continue;
    $f = explode('|', $line);
    if (count($f) != 7) { $report['errors'][] = "line $n: " . count($f) . " fields"; return false; }
    if ($report['version'] == 0) {                                     // the first line decides: v2 header or v1 key line
      $report['version'] = (($f[2] === '0') && ($f[3] === '0') && ($f[4] === 'v2')) ? 2 : 1;
      if ($report['version'] == 1) {                                   // v1: the old check wants the 7-field lines only (no '#' comment, no empty line)
        $v1 = array();
        foreach ($log_array as $l) if (count(explode('|', $l)) == 7) { $v1[] = $l; $report['lines']++; }
        if ( ($f[2] !== '0') || ($f[3] !== '0') ) { $report['errors'][] = "line $n: no key line at the top (a v2 file without its header is not a v1 file)"; return false; }   // DEV-502 (V1)
        $out = '';
        return encedo_log_integrity_check($pubkey_dev, $v1, $out);
      }
    }
    $text = substr($line, 0, strrpos($line, '|') + 1);
    $sig = base64url_decode($f[6]);
    $seq = hexdec($f[0]);
    if (($prev_seq === null) && ($seq != 0)) { $report['errors'][] = "line $n: the first line is not seq 0 (file cut at the front)"; return false; }   // DEV-502 (G7 C1): a file cut down to a rotation header verified as complete
    if (($prev_seq !== null) && ($seq != $prev_seq + 1)) $report['gaps'][] = dechex($prev_seq) . "->" . $f[0];
    $prev_seq = $seq;
    if (($f[2] === '0') && ($f[3] === '0') && ($f[4] === 'v2')) {     // header: data = pub_file (32) || Ed25519_dev(pub_file) (64)
      $cert = base64url_decode($f[5]);
      if (strlen($cert) != 96) { $report['errors'][] = "line $n: header data is not 96 B"; return false; }
      $newpub = substr($cert, 0, 32);
      if (!sodium_crypto_sign_verify_detached(substr($cert, 32), $newpub, $pubkey_dev)) { $report['errors'][] = "line $n: header key not certified by the device key"; return false; }
      if (($report['headers'] > 0) && ($rotate_pub !== $newpub)) { $report['errors'][] = "line $n: header without a LOGGER_KEY_ROTATE line for its key"; return false; }
      $pub = $newpub; $rotate_pub = false; $report['headers']++;
    }
    if ($pub === false) { $report['errors'][] = "line $n: line before the header"; return false; }
    if ((strlen($sig) != 64) || !sodium_crypto_sign_verify_detached($sig, $text, $pub)) { $report['errors'][] = "line $n: signature does not verify"; return false; }
    if ($f[2] === '32') { $rotate_pub = base64url_decode($f[5]); $report['rotations']++; }       // LOGGER_KEY_ROTATE 0x32
    if ($f[2] === '33') { $report['lost'] += unpack('V', base64url_decode($f[5]))[1]; }          // LOGGER_EVENTS_LOST 0x33
    $report['lines']++;
  }
  return ($report['version'] == 2) && ($report['lines'] > 0);
}



// raw HTTP over TLS - the request is sent exactly as given (header name case, Content-Length value),
// for checks http_transaction() cannot do: lowercase header names (DEV-430), keep-alive (two requests on
// one connection), CORS/PNA preflight and response headers (DEV-426)
function raw_https_connect($domain) {
  $context = stream_context_create([
    'ssl' => [
      'verify_peer' => true,         //validate peer and name - in short: validates cert trust
      'verify_peer_name' => true,    //
      'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT,
    ],
  ]);
  $sock = @stream_socket_client("ssl://$domain:443", $errorNumber, $errorDescription, 20, STREAM_CLIENT_CONNECT, $context);
  if ($sock == false) return false;
  stream_set_timeout($sock, 10);
  return $sock;
}

// send one raw request on an open connection; returns the HTTP status or false (connection closed / timeout)
// $hdrs gets the response headers with lowercase names (header names are case-insensitive)
function raw_https_transaction($sock, $request, &$hdrs = false, &$body = false) {
  if ($sock == false) return false;
  if (fwrite($sock, $request) === false) return false;
  $head = "";
  while (strpos($head, "\r\n\r\n") === false) {
    $chunk = fread($sock, 1);
    if (($chunk === false) || ($chunk === "")) return false;
    $head = $head . $chunk;
  }
  $lines = explode("\r\n", trim($head));
  if ( !preg_match("#^HTTP/[0-9\.]+\s+([0-9]+)#", $lines[0], $out) ) return false;
  $hdrs = array();
  foreach(array_slice($lines, 1) as $line) {
    $t = explode(':', $line, 2);
    if ( isset($t[1]) ) $hdrs[ strtolower(trim($t[0])) ] = trim($t[1]);
  }
  $body = "";
  $len = isset($hdrs['content-length']) ? intval($hdrs['content-length']) : 0;
  while (strlen($body) < $len) {
    $chunk = fread($sock, $len - strlen($body));
    if (($chunk === false) || ($chunk === "")) return false;
    $body = $body . $chunk;
  }
  return intval($out[1]);
}

// one raw request on its own connection
function raw_https_request($domain, $request, &$hdrs = false, &$body = false) {
  $sock = raw_https_connect($domain);
  if ($sock == false) return false;
  $ret = raw_https_transaction($sock, $request, $hdrs, $body);
  fclose($sock);
  return $ret;
}
