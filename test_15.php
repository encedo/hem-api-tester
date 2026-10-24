<?php

include "libs/lib.php";
include "libs/extauth.php";
include "config.php";


// test name, descr & number of subtests
$test_name = "T-15";
$test_descr = "Input validation and robustness";   // malformed input is rejected, the device keeps running (DEV-438)
$test_subtest_cnt = 11;


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
// a) TLS key in the config that cannot be decrypted (DEV-438 A7): not imported, no reboot requested, device keeps running
$token_cfg = helper_authorize($cfg_domain, $cfg_passpharse, "system:config");
if ($token_cfg == false) goto print_and_exit;
$tls = array('emp' => base64_encode(openssl_random_pseudo_bytes(91)),
             'key' => base64_encode(openssl_random_pseudo_bytes(60)) . "." . substr(base64_encode(openssl_random_pseudo_bytes(60)), 0, 32));   // 80 + 1 + 32 = 113 characters, as a real key
$ret_val = false;
$post_data = json_encode( array('tls' => $tls) );
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/system/config", $ret_val, $post_data, $token_cfg);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
if ( isset($ret_val['reboot_required']) ) { echo "    invalid TLS key accepted (reboot_required)\n"; goto print_and_exit; }
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
// a) service wipe to the factory default (DEV-438): an unknown wipeout value is refused; "factory" wipes the TOE and formats
//    the internal disk - the TOE comes back not initialised and without the TLS files of the previous owner, so HTTPS does
//    not start (after a classic wipe it starts with /tmp/tls.json). Runs last - the TOE has to be initialised again (T-2).
$ret_val = false;
$post_data = json_encode( array('wipeout' => "nonsense") );
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/system/config", $ret_val, $post_data, $token_cfg);
if ( $ret_stat != 406 ) { echo "    wipeout \"nonsense\": HTTP $ret_stat, expected 406\n"; goto print_and_exit; }
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
$test_cfg['subtests'][11] = 'OK';                             // mark this subtest as OK
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
