<?php

include "libs/lib.php";
include "libs/extauth.php";
include "config.php";


// test name, descr & number of subtests
$test_name = "T-15";
$test_descr = "Input validation and robustness";   // malformed input is rejected, the device keeps running (DEV-438)
$test_subtest_cnt = 14;


// initialize the execution env
init_env();
$test_cfg = init_test($test_name, $test_descr, $test_subtest_cnt, $cfg_tester);
if ( $cfg_debug ) var_dump( $cfg_domain );
$test_cfg['elapsed'] = hrtime(true);

echo "Processing...\n";

// every case: array(description, HTTP status got, HTTP status expected); prints the mismatches, returns true if all match
function check_cases($cases) {
  $ok = true;
  foreach ($cases as $c) {
    if ($c[1] != $c[2]) {
      echo "    " . $c[0] . ": HTTP " . $c[1] . ", expected " . $c[2] . "\n";
      $ok = false;
    }
  }
  return $ok;
}

// the device still answers and did not restart since the previous check (uptime keeps growing)
function check_alive(&$uptime) {
  global $cfg_domain;
  $ret_val = false;
  $ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/status", $ret_val);
  if ( ($ret_stat != 200) || !isset($ret_val['uptime']) ) {
    echo "    device does not answer\n";
    return false;
  }
  if ( intval($ret_val['uptime']) < $uptime ) {
    echo "    device restarted (uptime " . $ret_val['uptime'] . " < $uptime)\n";
    return false;
  }
  $uptime = intval($ret_val['uptime']);
  return true;
}

// auth token request as helper_authorize does, with $mod applied to the claims; returns the HTTP status
function auth_with_claims($mod) {
  global $cfg_domain, $cfg_passpharse;
  $ret_val = false;
  if ( http_transaction("http", "GET", $cfg_domain, "/api/auth/token", $ret_val) != 200 ) return 0;
  $user_secret = hash_pbkdf2("sha256", $cfg_passpharse, $ret_val['eid'], 600000, 32, true);
  $iat = time() - 5;
  $claims = array('jti' => $ret_val['jti'], 'aud' => $ret_val['spk'], 'exp' => $iat + 600, 'iat' => $iat,
                  'iss' => base64_encode(sodium_crypto_box_publickey_from_secretkey($user_secret)), 'scope' => "keymgmt:list");
  $claims = $mod($claims);
  $post_data = json_encode( array('auth' => ejwt_generate($claims, $user_secret, base64_decode($ret_val['spk']))) );
  $ret_val = false;
  return http_transaction("http", "POST", $cfg_domain, "/api/auth/token", $ret_val, $post_data);
}


/////////////////////////////////////////////////////////////////////
// Subtest: 1        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST1:
echo "  subtest-1\n";
$test_cfg['subtests'][1] = 'ERROR';                         // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) get TOE status - discover correct domain & https status
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/status", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
if ( isset($ret_val['inited']) ) goto print_and_exit;      // exit as well if prereq not fulfill - dev not inited!
if ( isset($ret_val['hostname']) ) {                       // remap domain name to the correct one
  $cfg_domain = $ret_val['hostname'];
}
// b) detect, get version details etc
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/version", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
$test_cfg['hwv'] = $ret_val['hwv'];                         //   or follow on with processing
$test_cfg['blv'] = @$ret_val['blv'];
$test_cfg['fwv'] = $ret_val['fwv'];
$test_cfg['conf'] = "ENCEDO PPA";
if ( strstr($ret_val['hwv'], "EPA") ) $test_cfg['conf'] = "ENCEDO EPA";
$uptime = 0;
if ( !check_alive($uptime) ) goto print_and_exit;
// c) set RTC clock - code from T-1.3
$ret = helper_checkin($cfg_domain);
if ($ret == false) goto print_and_exit;                     // exit on error
// d) HTTP request body (DEV-438 A1): only Content-Length bytes are the body, a missing length is refused
$body = "{}" . str_repeat("x", 200);                        // bytes after the declared body arrive together with the headers
$cases = array();
$cases[] = array("body longer than Content-Length", raw_https_request($cfg_domain, "POST /api/auth/token HTTP/1.1\r\nHost: $cfg_domain\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n" . $body), 400);
$cases[] = array("no Content-Length", raw_https_request($cfg_domain, "POST /api/auth/token HTTP/1.1\r\nHost: $cfg_domain\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}"), 411);
if ( !check_cases($cases) ) goto print_and_exit;
if ( !check_alive($uptime) ) goto print_and_exit;
// d) set result
$test_cfg['subtests'][1] = 'OK';                              // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 2        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST2:
echo "  subtest-2\n";
$test_cfg['subtests'][2] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) KID must be exactly 32 hex characters (DEV-438 R1)
$token_upd = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:upd");
if ($token_upd == false) goto print_and_exit;
$cases = array();
foreach (array("30 hex" => str_repeat("ab", 15), "31 hex" => str_repeat("a", 31), "33 hex" => str_repeat("a", 33), "32 non-hex" => str_repeat("g", 32)) as $name => $kid) {
  $ret_val = false;
  $post_data = json_encode( array('kid' => $kid, 'label' => "T-15") );
  $cases[] = array("keymgmt/update, kid $name", http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/update", $ret_val, $post_data, $token_upd), 400);
  $ret_val = false;
  $post_data = json_encode( array('kid' => $kid, 'msg' => base64_encode("T-15")) );
  $cases[] = array("crypto/hmac/hash, kid $name", http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/hash", $ret_val, $post_data, $token_upd), 400);
}
if ( !check_cases($cases) ) goto print_and_exit;
if ( !check_alive($uptime) ) goto print_and_exit;
// b) set result
$test_cfg['subtests'][2] = 'OK';                              // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 3        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST3:
echo "  subtest-3\n";
$test_cfg['subtests'][3] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) base64 padding only at the end, at most 2 characters (DEV-438 R2)
$token_imp = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:imp");
if ($token_imp == false) goto print_and_exit;
$run = bin2hex(openssl_random_pseudo_bytes(3));
$pk = base64_encode(sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));   // 44 characters, one '='
$cases = array();
foreach (array("'=' inside" => substr($pk, 0, 10) . "=" . substr($pk, 11), "3 padding characters" => substr($pk, 0, 42) . "===") as $name => $val) {
  $ret_val = false;
  $post_data = json_encode( array('label' => "T-15 $run", 'type' => "ED25519", 'pubkey' => $val, 'mode' => "ExDSA") );
  $cases[] = array("keymgmt/import, pubkey $name", http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/import", $ret_val, $post_data, $token_imp), 400);
}
$ret_val = false;
$post_data = json_encode( array('label' => "T-15 $run", 'type' => "ED25519", 'pubkey' => $pk, 'mode' => "ExDSA", 'descr' => base64_encode("CCTEST:T-15")) );
$cases[] = array("keymgmt/import, valid pubkey (reference)", http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/import", $ret_val, $post_data, $token_imp), 200);
if ( !check_cases($cases) ) goto print_and_exit;
if ( !check_alive($uptime) ) goto print_and_exit;
// b) set result
$test_cfg['subtests'][3] = 'OK';                              // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 4        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST4:
echo "  subtest-4\n";
$test_cfg['subtests'][4] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) local authentication JWT: required claims present, jti exactly the 32 bytes issued by the device (DEV-438 R4, R5)
$cases = array();
$cases[] = array("auth, valid (reference)", auth_with_claims(function ($c) { return $c; }), 200);
$cases[] = array("auth, jti cut to 4 bytes", auth_with_claims(function ($c) { $c['jti'] = base64_encode(substr(base64_decode($c['jti']), 0, 4)); return $c; }), 401);
$cases[] = array("auth, jti 33 bytes", auth_with_claims(function ($c) { $c['jti'] = base64_encode(base64_decode($c['jti']) . "x"); return $c; }), 401);
$cases[] = array("auth, no jti", auth_with_claims(function ($c) { unset($c['jti']); return $c; }), 401);
$cases[] = array("auth, no iss", auth_with_claims(function ($c) { unset($c['iss']); return $c; }), 401);
if ( !check_cases($cases) ) goto print_and_exit;
if ( !check_alive($uptime) ) goto print_and_exit;
// b) set result
$test_cfg['subtests'][4] = 'OK';                              // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 5        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST5:
echo "  subtest-5\n";
$test_cfg['subtests'][5] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) AES-CBC around the block size (DEV-438 A3): encrypt + decrypt round trip for short messages
$token_gen = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:gen");
if ($token_gen == false) goto print_and_exit;
$ret_val = false;
$post_data = json_encode( array('label' => "T-15 AES $run", 'type' => "AES256", 'descr' => base64_encode("CCTEST:T-15_AES")) );
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/create", $ret_val, $post_data, $token_gen);
if ( $ret_stat != 200 ) goto print_and_exit;
$kid = $ret_val['kid'];
$token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid");
if ($token == false) goto print_and_exit;
$failed = 0;
foreach (array(1, 15, 16, 17, 31, 32) as $len) {
  $msg = base64_encode( openssl_random_pseudo_bytes( $len ) );
  $ret_val = false;
  $post_data = json_encode( array('kid' => $kid, 'msg' => $msg, 'alg' => "AES256-CBC") );
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/encrypt", $ret_val, $post_data, $token);
  if ( $ret_stat != 200 ) { echo "    encrypt $len B: HTTP $ret_stat\n"; $failed++; continue; }
  $post_data = json_encode( array('kid' => $kid, 'msg' => $ret_val['ciphertext'], 'iv' => $ret_val['iv'], 'alg' => "AES256-CBC") );
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/decrypt", $ret_val, $post_data, $token);
  if ( ($ret_stat != 200) || ($ret_val['plaintext'] !== $msg) ) { echo "    decrypt $len B: HTTP $ret_stat or plaintext differs\n"; $failed++; }
}
if ($failed) goto print_and_exit;
if ( !check_alive($uptime) ) goto print_and_exit;
// b) set result
$test_cfg['subtests'][5] = 'OK';                              // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 6        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST6:
echo "  subtest-6\n";
$test_cfg['subtests'][6] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) TLS bundles in the config that cannot be imported (DEV-438 A7): nothing is stored, the device keeps running
//    (DEV-438: a failed import was a silent 200 without reboot_required - now 400)
$token_cfg = helper_authorize($cfg_domain, $cfg_passpharse, "system:config");
if ($token_cfg == false) goto print_and_exit;
$cases = array();
// self-signed certificates for the certificate only mode: of another domain; of the device domain with another key (not the TLS key)
$t15_keyargs = array('private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => "prime256v1", 'digest_alg' => "sha256");
$cnf = dirname(PHP_BINARY) . "/extras/ssl/openssl.cnf";
if ( (getenv("OPENSSL_CONF") === false) && (PHP_OS_FAMILY == "Windows") && file_exists($cnf) ) {
  $t15_keyargs['config'] = $cnf;
}
$crt = array();
foreach (array("other.example.com", $cfg_domain) as $cn) {
  $pkey = openssl_pkey_new($t15_keyargs);
  $x509 = ($pkey === false) ? false : openssl_csr_sign(openssl_csr_new(array('commonName' => $cn), $pkey, $t15_keyargs), null, $pkey, 30, $t15_keyargs, random_int(1, 0x7fffffff));   // serial 0 is refused by wolfSSL (ASN_PARSE_E)
  if ( ($x509 === false) || !openssl_x509_export($x509, $pem) ) { echo "ERROR: test certificate for $cn\n"; goto print_and_exit; }
  $crt[] = preg_replace('/-----[A-Z ]+-----|\s/', '', $pem);   // the PEM body is the base64 of the DER
}
foreach (array("tls: crt of another domain" => array('crt' => $crt[0]),                     // DEV-470: the cert must be issued for the device domain
               "tls: crt of the domain, another key" => array('crt' => $crt[1]),            // DEV-470: ... and match the TLS private key
               "tls: random emp + key" => array('emp' => base64_encode(openssl_random_pseudo_bytes(91)),
                                                'key' => base64_encode(openssl_random_pseudo_bytes(60)) . "." . substr(base64_encode(openssl_random_pseudo_bytes(60)), 0, 32)),   // 80 + 1 + 32 = 113 characters, as a real key
               "tls: emp not a key" => array('emp' => "AAAA", 'key' => "x", 'crt' => "AAAA"),
               "tls: crt only, not base64" => array('crt' => "!!!"),
               "tls: not an object" => "x") as $name => $tls) {
  $ret_val = false;
  $post_data = json_encode( array('tls' => $tls) );
  $cases[] = array($name, http_transaction("https", "POST", $cfg_domain, "/api/system/config", $ret_val, $post_data, $token_cfg), 400);
}
if ( !check_cases($cases) ) goto print_and_exit;
sleep(2);
if ( !check_alive($uptime) ) goto print_and_exit;
// b) set result
$test_cfg['subtests'][6] = 'OK';                              // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 7        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST7:
echo "  subtest-7\n";
$test_cfg['subtests'][7] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) external authenticator (DEV-438 A5, N4, N5): pairing and access token directly with the HEM (libs/extauth.php),
//    then malformed sealed scopes and pairing ids of a wrong length
$app = false;
$code_ok = false;
if ( extauth_pair_direct($cfg_domain, $token_cfg, "T-15 ExtAuth", $app, $code_ok) != 200 ) goto print_and_exit;
if ( !$code_ok ) { echo "    ext/validate: code does not match\n"; goto print_and_exit; }
$authreq = false;
if ( extauth_request_direct($cfg_domain, "system:config", $authreq) != 200 ) goto print_and_exit;
$sealed = isset($authreq['scope'][$app['pid']]) ? $authreq['scope'][$app['pid']] : false;
$m = extauth_session_key($app['aid_prv'], $app['eid'], $authreq['jti']);
$plain = extauth_unseal($sealed, $m);
if ( $plain === false ) { echo "    ext/request: sealed scope missing or MAC wrong\n"; goto print_and_exit; }
$raw = base64_decode(substr($sealed, 1));
$mac = hash_hmac("sha256", $plain, $m, true);
$pad0 = openssl_encrypt(str_repeat("x", 15) . "\0", "aes-128-cbc", substr($m, 0, 16), OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, substr($m, 16, 16));
$short = $app;
$short['pid'] = base64_encode(substr(base64_decode($app['pid']), 0, 16));
$t = false;
$app16 = false;
$cases = array();
$cases[] = array("ext/token, valid (reference)", extauth_token_direct($cfg_domain, $app, $authreq['jti'], extauth_seal($plain, $m), $t), 200);
$cases[] = array("ext/token, scope one block, no MAC", extauth_token_direct($cfg_domain, $app, $authreq['jti'], "A" . base64_encode(random_bytes(16)), $t), 406);
$cases[] = array("ext/token, scope not whole blocks", extauth_token_direct($cfg_domain, $app, $authreq['jti'], "A" . base64_encode(random_bytes(20) . $mac), $t), 406);
$cases[] = array("ext/token, scope padding byte 0", extauth_token_direct($cfg_domain, $app, $authreq['jti'], "A" . base64_encode($pad0 . $mac), $t), 406);
$cases[] = array("ext/token, scope wrong MAC", extauth_token_direct($cfg_domain, $app, $authreq['jti'], "A" . base64_encode(substr($raw, 0, -32) . random_bytes(32)), $t), 406);
$cases[] = array("ext/token, pid = 16 B prefix of the paired pid", extauth_token_direct($cfg_domain, $short, $authreq['jti'], extauth_seal($plain, $m), $t), 406);
$cases[] = array("ext/validate, pid 16 B", extauth_pair_direct($cfg_domain, $token_cfg, "T-15 ExtAuth 16", $app16, $code_ok, 16), 400);
if ( !check_cases($cases) ) goto print_and_exit;
if ( !check_alive($uptime) ) goto print_and_exit;
// b) set result
$test_cfg['subtests'][7] = 'OK';                              // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 8        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST8:
echo "  subtest-8\n";
$test_cfg['subtests'][8] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) HTTP header names and the values with a defined case rule are case-insensitive (DEV-438 N8, RFC 9110)
$cases = array();
// media type in capitals: still a JSON request (not an upload), so the empty JSON body is a validation error
$cases[] = array("content-type: Application/JSON, CONTENT-LENGTH", raw_https_request($cfg_domain, "POST /api/auth/token HTTP/1.1\r\nhost: $cfg_domain\r\ncontent-type: Application/JSON\r\nCONTENT-LENGTH: 2\r\nConnection: close\r\n\r\n{}"), 400);
// media type with parameters (RFC 9110 8.3): still JSON
$cases[] = array("Content-Type: application/json; Charset=UTF-8", raw_https_request($cfg_domain, "POST /api/auth/token HTTP/1.1\r\nHost: $cfg_domain\r\nContent-Type: application/json; Charset=UTF-8\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"), 400);
// header name and auth scheme in lower case
$cases[] = array("authorization: bearer <token>", raw_https_request($cfg_domain, "GET /api/system/config HTTP/1.1\r\nHost: $cfg_domain\r\nauthorization: bearer $token_cfg\r\nConnection: close\r\n\r\n"), 200);
// Connection is a token list in any case: the connection stays open for a second request
$sock = raw_https_connect($cfg_domain);
$cases[] = array("Connection: Keep-Alive, TE - request 1", raw_https_transaction($sock, "GET /api/system/status HTTP/1.1\r\nHost: $cfg_domain\r\nConnection: Keep-Alive, TE\r\n\r\n"), 200);
$cases[] = array("Connection: Keep-Alive, TE - request 2 on the same connection", raw_https_transaction($sock, "GET /api/system/status HTTP/1.1\r\nHost: $cfg_domain\r\nConnection: close\r\n\r\n"), 200);
if ($sock) fclose($sock);
if ( !check_cases($cases) ) goto print_and_exit;
if ( !check_alive($uptime) ) goto print_and_exit;
// b) set result
$test_cfg['subtests'][8] = 'OK';                              // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 9        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST9:
echo "  subtest-9\n";
$test_cfg['subtests'][9] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) a token requested without a scope gets an empty scope and is refused by scoped endpoints (DEV-438: was a crash)
$cases = array();
$token_noscope = helper_authorize($cfg_domain, $cfg_passpharse, "");
if ($token_noscope == false) goto print_and_exit;
$ret_val = false;
$post_data = json_encode( array('epk' => base64_encode(sodium_crypto_scalarmult_base(random_bytes(32)))) );
$cases[] = array("ext/init with a token without scope", http_transaction("https", "POST", $cfg_domain, "/api/auth/ext/init", $ret_val, $post_data, $token_noscope), 403);
$ret_val = false;
$not_used = false;
$cases[] = array("GET config with a token without scope", http_transaction("https", "GET", $cfg_domain, "/api/system/config", $ret_val, $not_used, $token_noscope), 403);
// b) firmware upload: a wrong extension and a file of 3 MiB or more are answered (DEV-438: was no response at all)
$token_upg = helper_authorize($cfg_domain, $cfg_passpharse, "system:upgrade");
if ($token_upg == false) goto print_and_exit;
$cases[] = array("upload_fw, name x.txt", raw_https_request($cfg_domain, "POST /api/system/upgrade/upload_fw HTTP/1.1\r\nHost: $cfg_domain\r\nAuthorization: Bearer $token_upg\r\nContent-Disposition: attachment; filename=\"x.txt\"\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0123456789"), 400);
$cases[] = array("upload_fw, 3 MiB (body not sent)", raw_https_request($cfg_domain, "POST /api/system/upgrade/upload_fw HTTP/1.1\r\nHost: $cfg_domain\r\nAuthorization: Bearer $token_upg\r\nContent-Disposition: attachment; filename=\"fw.bin\"\r\nContent-Length: 3145728\r\nConnection: close\r\n\r\n"), 413);
// c) storage_disk0size: the value read can be written back unchanged; 0 and negative values are refused (DEV-438)
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/config", $ret_val, $not_used, $token_cfg);
if ( $ret_stat != 200 ) goto print_and_exit;
$disk0size = $ret_val['storage_disk0size'];
$ret_val = false;
$post_data = json_encode( array('storage_disk0size' => $disk0size) );
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/system/config", $ret_val, $post_data, $token_cfg);
$cases[] = array("config storage_disk0size written back unchanged", $ret_stat, 200);
if ( ($ret_stat == 200) && ((@$ret_val['updated'] == true) || isset($ret_val['reboot_required'])) ) { echo "    storage_disk0size written back: reported as a change\n"; goto print_and_exit; }
foreach (array(0, -5) as $v) {
  $ret_val = false;
  $post_data = json_encode( array('storage_disk0size' => $v) );
  $cases[] = array("config storage_disk0size $v", http_transaction("https", "POST", $cfg_domain, "/api/system/config", $ret_val, $post_data, $token_cfg), 400);
}
if ( !check_cases($cases) ) goto print_and_exit;
if ( !check_alive($uptime) ) goto print_and_exit;
// d) set result
$test_cfg['subtests'][9] = 'OK';                              // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 10       ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST10:
echo "  subtest-10\n";
$test_cfg['subtests'][10] = 'ERROR';                          // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) key derivation with a descr or a peer public key that passes the character check but does not decode is refused as
//    input (DEV-438 phase 2 group 2: the descr was dropped / the derive ran on partly decoded bytes, then 406)
$token_gen = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:gen");
$token_der = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:derive");
if (($token_gen == false) || ($token_der == false)) goto print_and_exit;
$ret_val = false;
$post_data = json_encode( array('label' => "T-15 derive $run", 'type' => "CURVE25519", 'mode' => "ECDH", 'descr' => base64_encode("CCTEST:T-15_derive")) );
if ( http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/create", $ret_val, $post_data, $token_gen) != 200 ) goto print_and_exit;
$kid_ecdh = $ret_val['kid'];
$peer = base64_encode(sodium_crypto_scalarmult_base(random_bytes(32)));
$cases = array();
foreach (array("valid (reference)" => array($peer, base64_encode("CCTEST:T-15"), 200),
               "descr of 5 characters" => array($peer, "QUJDR", 400),
               "pubkey of 43 characters" => array(substr($peer, 0, 43), base64_encode("CCTEST:T-15"), 400)) as $name => $v) {
  $ret_val = false;
  $post_data = json_encode( array('kid' => $kid_ecdh, 'label' => "T-15 d " . bin2hex(openssl_random_pseudo_bytes(3)), 'type' => "AES256", 'pubkey' => $v[0], 'descr' => $v[1]) );
  $cases[] = array("keymgmt/derive, $name", http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/derive", $ret_val, $post_data, $token_der), $v[2]);
}
if ( !check_cases($cases) ) goto print_and_exit;
if ( !check_alive($uptime) ) goto print_and_exit;
// b) set result
$test_cfg['subtests'][10] = 'OK';                             // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 11       ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST11:
echo "  subtest-11\n";
$test_cfg['subtests'][11] = 'ERROR';                          // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) AES decryption needs the IV for CBC and GCM and the tag for GCM (DEV-438 phase 2 group 3: CBC used a zero IV)
$ret_val = false;
$post_data = json_encode( array('label' => "T-15 AES2 $run", 'type' => "AES256", 'descr' => base64_encode("CCTEST:T-15_AES2")) );
if ( http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/create", $ret_val, $post_data, $token_gen) != 200 ) goto print_and_exit;
$kid_aes = $ret_val['kid'];
$token_aes = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid_aes");
if ($token_aes == false) goto print_and_exit;
$cases = array();
foreach (array("AES256-CBC" => "iv", "AES256-GCM" => "tag") as $alg => $drop) {
  $ret_val = false;
  $post_data = json_encode( array('kid' => $kid_aes, 'msg' => base64_encode(openssl_random_pseudo_bytes(32)), 'alg' => $alg) );
  if ( http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/encrypt", $ret_val, $post_data, $token_aes) != 200 ) goto print_and_exit;
  $arg = array('kid' => $kid_aes, 'msg' => $ret_val['ciphertext'], 'alg' => $alg);
  if ( isset($ret_val['iv']) ) $arg['iv'] = $ret_val['iv'];
  if ( isset($ret_val['tag']) ) $arg['tag'] = $ret_val['tag'];
  unset($arg[$drop]);
  $ret_val = false;
  $post_data = json_encode($arg);
  $cases[] = array("cipher/decrypt $alg without $drop", http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/decrypt", $ret_val, $post_data, $token_aes), 400);
}
if ( !check_cases($cases) ) goto print_and_exit;
// b) remote authentication (ext/token): failed attempts are answered after at least 500 ms, from the 4th one after 1500 ms
//    (DEV-438 phase 2 group 3: the delay guard was inverted - no delay, no count)
$times = array();
for ($i = 0; $i < 5; $i++) {
  $t0 = hrtime(true);
  $ret_val = false;
  $post_data = json_encode( array('authreply' => "eyJhbGciOiJIUzI1NiJ9.e30.AAAA") );
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/auth/ext/token", $ret_val, $post_data);
  $times[] = intval((hrtime(true) - $t0) / 1000000);
  if ( $ret_stat != 401 ) { echo "    ext/token with an invalid authreply: HTTP $ret_stat, expected 401\n"; goto print_and_exit; }
}
if ( ($times[0] < 450) || ($times[4] < 1400) ) { echo "    ext/token failure delays (ms): " . implode(", ", $times) . " - expected >= 500, from the 4th >= 1500\n"; goto print_and_exit; }
sleep(16);                                                   // let the failure counter expire (15 s lockdown window)
if ( !check_alive($uptime) ) goto print_and_exit;
// c) set result
$test_cfg['subtests'][11] = 'OK';                             // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 12       ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST12:
echo "  subtest-12\n";
$test_cfg['subtests'][12] = 'ERROR';                          // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) verify endpoints answer 200 with "verified" - false for a wrong MAC / signature, 404 for an unknown key (DEV-438 phase 3:
//    a wrong MAC / signature was 406)
$keys = array();
foreach (array('ed' => array('type' => "ED25519", 'mode' => "ExDSA"), 'hm' => array('type' => "SHA2-256")) as $k => $v) {
  $ret_val = false;
  $post_data = json_encode( $v + array('label' => "T-15 $k $run", 'descr' => base64_encode("CCTEST:T-15_$k")) );
  if ( http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/create", $ret_val, $post_data, $token_gen) != 200 ) goto print_and_exit;
  $keys[$k] = array($ret_val['kid'], helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:" . $ret_val['kid']));
  if ($keys[$k][1] == false) goto print_and_exit;
}
$kid_none = bin2hex(random_bytes(16));
$keys['none'] = array($kid_none, helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid_none"));
if ($keys['none'][1] == false) goto print_and_exit;
$msg = base64_encode(random_bytes(64));
$ret_val = false;
$post_data = json_encode( array('kid' => $keys['hm'][0], 'msg' => $msg) );
if ( http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/hash", $ret_val, $post_data, $keys['hm'][1]) != 200 ) goto print_and_exit;
$mac = base64_decode($ret_val['mac']);
$ret_val = false;
$post_data = json_encode( array('kid' => $keys['ed'][0], 'msg' => $msg, 'alg' => "Ed25519") );
if ( http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/sign", $ret_val, $post_data, $keys['ed'][1]) != 200 ) goto print_and_exit;
$sig = base64_decode($ret_val['sign']);
$mac[0] = chr(ord($mac[0]) ^ 1);
$sig[0] = chr(ord($sig[0]) ^ 1);
foreach (array("hmac/verify, wrong MAC" => array("/api/crypto/hmac/verify", array('kid' => $keys['hm'][0], 'msg' => $msg, 'mac' => base64_encode($mac)), $keys['hm'][1]),
               "exdsa/verify, wrong signature" => array("/api/crypto/exdsa/verify", array('kid' => $keys['ed'][0], 'msg' => $msg, 'alg' => "Ed25519", 'sign' => base64_encode($sig)), $keys['ed'][1])) as $name => $v) {
  $ret_val = false;
  $post_data = json_encode($v[1]);
  $ret_stat = http_transaction("https", "POST", $cfg_domain, $v[0], $ret_val, $post_data, $v[2]);
  if ( ($ret_stat != 200) || (@$ret_val['verified'] !== false) ) { echo "    $name: HTTP $ret_stat " . json_encode($ret_val) . ", expected 200 {\"verified\":false}\n"; goto print_and_exit; }
}
// b) error codes by the HEM API docs: 400 input, 403 scope, 404 not found, 409 state (DEV-438 phase 3: mostly 406); $peer is the
//    X25519 peer key of subtest 10
$token_d0 = helper_authorize($cfg_domain, $cfg_passpharse, "storage:disk0");
$token_ecdh = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid_ecdh");
$token_keylist = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:list");
if (($token_d0 == false) || ($token_ecdh == false) || ($token_keylist == false)) goto print_and_exit;
$cases = array();
foreach (array("hmac/verify, unknown kid" => array("https", "POST", "/api/crypto/hmac/verify", array('kid' => $kid_none, 'msg' => $msg, 'mac' => base64_encode($mac)), $keys['none'][1], 404),
               "exdsa/verify, unknown kid" => array("https", "POST", "/api/crypto/exdsa/verify", array('kid' => $kid_none, 'msg' => $msg, 'alg' => "Ed25519", 'sign' => base64_encode($sig)), $keys['none'][1], 404),
               "cipher/encrypt, unknown kid" => array("https", "POST", "/api/crypto/cipher/encrypt", array('kid' => $kid_none, 'msg' => $msg, 'alg' => "AES256-ECB"), $keys['none'][1], 404),
               "cipher/wrap, unknown kid" => array("https", "POST", "/api/crypto/cipher/wrap", array('kid' => $kid_none, 'msg' => base64_encode(random_bytes(32)), 'alg' => "AES256"), $keys['none'][1], 404),
               "ecdh, unknown kid" => array("https", "POST", "/api/crypto/ecdh", array('kid' => $kid_none, 'pubkey' => $peer), $keys['none'][1], 404),
               "pqc/mlkem/encaps, unknown kid" => array("https", "POST", "/api/crypto/pqc/mlkem/encaps", array('kid' => $kid_none), $keys['none'][1], 404),
               "cipher/encrypt, ED25519 key" => array("https", "POST", "/api/crypto/cipher/encrypt", array('kid' => $keys['ed'][0], 'msg' => $msg, 'alg' => "AES256-ECB"), $keys['ed'][1], 400),
               "ecdh, ExDSA-only key" => array("https", "POST", "/api/crypto/ecdh", array('kid' => $keys['ed'][0], 'pubkey' => $peer), $keys['ed'][1], 400),
               "hmac/hash, alg too long" => array("https", "POST", "/api/crypto/hmac/hash", array('kid' => $keys['hm'][0], 'msg' => $msg, 'alg' => "SHA2-256-X"), $keys['hm'][1], 400),
               "ecdh, no pubkey / ext_kid" => array("https", "POST", "/api/crypto/ecdh", array('kid' => $kid_ecdh), $token_ecdh, 400),
               "cipher/decrypt CBC, 20 B" => array("https", "POST", "/api/crypto/cipher/decrypt", array('kid' => $kid_aes, 'msg' => base64_encode(random_bytes(20)), 'alg' => "AES256-CBC", 'iv' => base64_encode(random_bytes(16))), $token_aes, 400),
               "keymgmt/search, mode not a string" => array("https", "POST", "/api/keymgmt/search", array('descr' => "^" . base64_encode("CCTEST:"), 'mode' => 5), $token_keylist, 400),
               "keymgmt/list, offset not a number" => array("https", "GET", "/api/keymgmt/list/abc", false, $token_keylist, 400),
               "storage/unlock/rw, ro scope" => array("https", "GET", "/api/storage/unlock/rw", false, $token_d0, 403),
               "storage/unlock/xx" => array("https", "GET", "/api/storage/unlock/xx", false, $token_d0, 404),
               "auth/init, initialised" => array("http", "GET", "/api/auth/init", false, false, 409)) as $name => $v) {
  $ret_val = false;
  $post_data = ($v[3] === false) ? false : json_encode($v[3]);
  $cases[] = array($name, ($v[4] === false) ? http_transaction($v[0], $v[1], $cfg_domain, $v[2], $ret_val) : http_transaction($v[0], $v[1], $cfg_domain, $v[2], $ret_val, $post_data, $v[4]), $v[5]);
}
if ( !check_cases($cases) ) goto print_and_exit;
if ( !check_alive($uptime) ) goto print_and_exit;
// c) set result
$test_cfg['subtests'][12] = 'OK';                             // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 13       ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST13:
echo "  subtest-13\n";
$test_cfg['subtests'][13] = 'ERROR';                          // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) a message of the maximum length (2048 B) can be encrypted and decrypted, wrapped and unwrapped (DEV-438: the wrap
//    of a max message (+8 B) was over the input limit of unwrap - 400)
$cases = array();
$msg = base64_encode(random_bytes(2048));
foreach (array("cipher/encrypt + decrypt AES256-CBC" => array("/api/crypto/cipher/encrypt", "/api/crypto/cipher/decrypt", array('alg' => "AES256-CBC"), 'ciphertext', 'plaintext'),
               "cipher/wrap + unwrap AES256" => array("/api/crypto/cipher/wrap", "/api/crypto/cipher/unwrap", array('alg' => "AES256"), 'wrapped', 'unwrapped')) as $name => $v) {
  $ret_val = false;
  $post_data = json_encode( array('kid' => $kid_aes, 'msg' => $msg) + $v[2] );
  $ret_stat = http_transaction("https", "POST", $cfg_domain, $v[0], $ret_val, $post_data, $token_aes);
  if ( $ret_stat != 200 ) { echo "    $name: first call HTTP $ret_stat\n"; goto print_and_exit; }
  $arg = array('kid' => $kid_aes, 'msg' => $ret_val[$v[3]]) + $v[2];
  if ( isset($ret_val['iv']) ) $arg['iv'] = $ret_val['iv'];
  $ret_val = false;
  $post_data = json_encode($arg);
  $ret_stat = http_transaction("https", "POST", $cfg_domain, $v[1], $ret_val, $post_data, $token_aes);
  $cases[] = array("$name, 2048 B", (($ret_stat == 200) && (@$ret_val[$v[4]] !== $msg)) ? -1 : $ret_stat, 200);   // -1: wrong result
}
// b) numbers in the path and in the search request: empty, overflowing, negative or not a number are refused (DEV-438: an
//    empty number was 0, more than 9 digits overflowed, offset / limit were converted unchecked)
$token_keylist = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:list");
$token_log = helper_authorize($cfg_domain, $cfg_passpharse, "logger:get");
if (($token_keylist == false) || ($token_log == false)) goto print_and_exit;
foreach (array("keymgmt/list/ (empty offset)" => array("GET", "/api/keymgmt/list/", false, $token_keylist, 400),
               "keymgmt/list/99999999999" => array("GET", "/api/keymgmt/list/99999999999", false, $token_keylist, 400),
               "keymgmt/search, offset -1" => array("POST", "/api/keymgmt/search", array('descr' => "^" . base64_encode("CCTEST:"), 'offset' => -1), $token_keylist, 400),
               "keymgmt/search, limit \"x\"" => array("POST", "/api/keymgmt/search", array('descr' => "^" . base64_encode("CCTEST:"), 'limit' => "x"), $token_keylist, 400),
               "logger/zzzzzzzz (file id not hex)" => array("GET", "/api/logger/zzzzzzzz", false, $token_log, 400)) as $name => $v) {
  $ret_val = false;
  $post_data = ($v[2] === false) ? false : json_encode($v[2]);
  $cases[] = array($name, http_transaction("https", $v[0], $cfg_domain, $v[1], $ret_val, $post_data, $v[3]), $v[4]);
}
// c) upload_ui accepts only webroot.tar - the name install_ui reads (DEV-438: any name was stored in /tmp)
$cases[] = array("upload_ui, name x.tar", raw_https_request($cfg_domain, "POST /api/system/upgrade/upload_ui HTTP/1.1\r\nHost: $cfg_domain\r\nAuthorization: Bearer $token_upg\r\nContent-Disposition: attachment; filename=\"x.tar\"\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0123456789"), 400);
// d) request framing: Content-Length repeated with another value 400, Content-Length 0 400 (was 411), Transfer-Encoding 501
//    (DEV-438: the last Content-Length was used, Transfer-Encoding was ignored - a chunked body would be read as the next request)
$body = json_encode( array('descr' => "^" . base64_encode("CCTEST")) );   // search without a token - 200 when the request is taken
$len = strlen($body);
$req = "POST /api/keymgmt/search HTTP/1.1\r\nHost: $cfg_domain\r\nContent-Type: application/json\r\nConnection: close\r\n";
$cases[] = array("search, reference", raw_https_request($cfg_domain, $req . "Content-Length: $len\r\n\r\n" . $body), 200);
$cases[] = array("search, Content-Length " . ($len + 5) . " and $len", raw_https_request($cfg_domain, $req . "Content-Length: " . ($len + 5) . "\r\nContent-Length: $len\r\n\r\n" . $body), 400);
$cases[] = array("search, Content-Length 0", raw_https_request($cfg_domain, $req . "Content-Length: 0\r\n\r\n"), 400);
$cases[] = array("search, Transfer-Encoding: chunked", raw_https_request($cfg_domain, $req . "Content-Length: $len\r\nTransfer-Encoding: chunked\r\n\r\n" . $body), 501);
if ( !check_cases($cases) ) goto print_and_exit;
if ( !check_alive($uptime) ) goto print_and_exit;
// e) set result
$test_cfg['subtests'][13] = 'OK';                             // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 14       ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST14:
echo "  subtest-14\n";
$test_cfg['subtests'][14] = 'ERROR';                          // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) service wipe to the factory default (DEV-438): an unknown wipeout value is refused; "factory" wipes the TOE and formats
//    the internal disk - the TOE comes back not initialised and without the TLS files of the previous owner, so HTTPS does
//    not start (a classic wipe empties /tmp as well, the UI stays). Runs last - the TOE has to be initialised again (T-2).
$ret_val = false;
$post_data = json_encode( array('wipeout' => "nonsense") );
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/system/config", $ret_val, $post_data, $token_cfg);
if ( $ret_stat != 400 ) { echo "    wipeout \"nonsense\": HTTP $ret_stat, expected 400\n"; goto print_and_exit; }
$ret_val = false;
$post_data = json_encode( array('wipeout' => "factory") );
$ret_stat = http_transaction("http", "POST", $cfg_domain, "/api/system/config", $ret_val, $post_data, $token_cfg);   // over http - also for a TOE with a broken TLS
if ( $ret_stat != 200 ) { echo "    wipeout \"factory\": HTTP $ret_stat\n"; goto print_and_exit; }
$back = false;
for ($i = 0; $i < 60; $i++) {                                // the TOE reboots
  sleep(2);
  $ret_val = false;
  if ( (http_transaction("http", "GET", $cfg_domain, "/api/system/status", $ret_val) == 200) && isset($ret_val['inited']) ) { $back = true; break; }
}
if ( !$back ) { echo "    TOE not back as not initialised\n"; goto print_and_exit; }
sleep(20);                                                   // HTTPS would be up by now after a classic wipe
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/status", $ret_val);
if ( ($ret_stat != 200) || !isset($ret_val['inited']) || ($ret_val['https'] != false) ) { echo "    after the factory wipe: " . json_encode($ret_val) . "\n"; goto print_and_exit; }
// b) set result
$test_cfg['subtests'][14] = 'OK';                             // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Test summary      ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
// if execution reach this point - all test are passed
$check_passed = 0;
$check_failed = 0;
foreach($test_cfg['subtests'] as $no => $val) {
  if ($val === 'OK') $check_passed++;
  else $check_failed++;
}
if ($check_failed == 0) $test_cfg['result'] = 'PASS';


/////////////////////////////////////////////////////////////////////
// Print summary      ///////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
print_and_exit:
  $test_cfg['elapsed'] = intval((hrtime(true) - $test_cfg['elapsed']) / 1000000);
  echo "\nTest summary:\n";
  print_result( $test_cfg );
  die;

/////////////////////////////////////////////////////////////////////
// end of file    ///////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
