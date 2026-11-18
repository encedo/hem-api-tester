<?php

include "libs/lib.php";
include "libs/extauth.php";
include "config.php";


// test name, descr & number of subtests
$test_name = "T-15";
$test_descr = "Input validation and robustness";   // malformed input is rejected, the device keeps running (DEV-438)
$test_subtest_cnt = 22;   // DEV-436: 15-17 multi-scope tokens (run before 14, the factory wipe); DEV-502: 18 Host-less status + nonce replay; DEV-519: 19 JWT segments, folded header, Origin length; 20 web UI manifest; 21 pairing descr, token lifetime, nonce order; 22 AES key size, upload close


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

// DEV-519: a small web UI archive - index.html + manifest (+ $extra files not in the manifest), the manifest hash token of
// index.html replaced by $hash_token when given; signed as the firmware checks it (Ed25519 over SHA-512(tar || pub), trailer
// pub || sig) with a throw-away key (publisher pinning is off). upload_ui + check_ui, no install_ui; returns check_ui's status
function ui_archive_check($token, $extra = array(), $hash_token = null) {
  global $cfg_domain;
  $index = "<html><body>T-15.20</body></html>\n";
  $files = array('index.html' => $index, 'manifest' => (($hash_token === null) ? hash('sha256', $index) : $hash_token) . " *./index.html\n");
  foreach ($extra as $name => $data) $files[$name] = $data;
  $tarfile = sys_get_temp_dir() . '/t15_ui_' . bin2hex(random_bytes(4)) . '.tar';
  $tar = new PharData($tarfile);
  foreach ($files as $name => $data) $tar->addFromString($name, $data);
  unset($tar);
  $bytes = file_get_contents($tarfile);
  unlink($tarfile);
  $kp = sodium_crypto_sign_keypair();
  $pub = sodium_crypto_sign_publickey($kp);
  $sig = sodium_crypto_sign_detached(hash('sha512', $bytes . $pub, true), sodium_crypto_sign_secretkey($kp));
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/system/upgrade/upload_ui", $ret_val, $bytes . $pub . $sig, $token, "webroot.tar");
  if ($ret_stat != 200) return $ret_stat;
  for ($i = 0; $i < 30; $i++) {                               // check_ui: 201 started, 202 running, 200 passed, 406 refused
    $ret_val = false; $not_used = false;
    $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/upgrade/check_ui", $ret_val, $not_used, $token);
    if (($ret_stat != 201) && ($ret_stat != 202)) return $ret_stat;
    sleep(2);
  }
  return 0;
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
// DEV-502 (T-15.1 d): a request that is 200 only when the extra bytes are not read (auth/token with "{}" gave 400 either way);
//   keymgmt/search without a token (prefix pattern of 6 B) answers 200 also when nothing matches
$sbody = json_encode(array('descr' => "^" . base64_encode("CCTEST")));
$body = $sbody . str_repeat("x", 200);                      // bytes after the declared body arrive together with the headers
$cases = array();
$cases[] = array("body longer than Content-Length", raw_https_request($cfg_domain, "POST /api/keymgmt/search HTTP/1.1\r\nHost: $cfg_domain\r\nContent-Type: application/json\r\nContent-Length: " . strlen($sbody) . "\r\nConnection: close\r\n\r\n" . $body), 200);
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
// DEV-499 (D4): a jti is accepted once (A4) - every ext/token case below needs its own ext/request; the closure returns the request and the values derived from its jti
$t15_req = function () use ($cfg_domain, $app) {
  $a = false;
  if ( extauth_request_direct($cfg_domain, "system:config", $a) != 200 ) return false;
  $s = isset($a['scope'][$app['pid']]) ? $a['scope'][$app['pid']] : false;
  $m = extauth_session_key($app['aid_prv'], $app['eid'], $a['jti']);
  $p = extauth_unseal($s, $m);
  if ( $p === false ) return false;
  return array('jti' => $a['jti'], 'm' => $m, 'plain' => $p, 'raw' => base64_decode(substr($s, 1)), 'mac' => hash_hmac("sha256", $p, $m, true),
               'pad0' => openssl_encrypt(str_repeat("x", 15) . "\0", "aes-128-cbc", substr($m, 0, 16), OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, substr($m, 16, 16)));
};
$short = $app;
$short['pid'] = base64_encode(substr(base64_decode($app['pid']), 0, 16));
$t = false;
$app16 = false;
$cases = array();
if ( ($r = $t15_req()) === false ) { echo "    ext/request: sealed scope missing or MAC wrong\n"; goto print_and_exit; }
$cases[] = array("ext/token, valid (reference)", extauth_token_direct($cfg_domain, $app, $r['jti'], extauth_seal($r['plain'], $r['m']), $t), 200);
if ( ($r = $t15_req()) === false ) goto print_and_exit;
$cases[] = array("ext/token, scope one block, no MAC", extauth_token_direct($cfg_domain, $app, $r['jti'], "A" . base64_encode(random_bytes(16)), $t), 406);
if ( ($r = $t15_req()) === false ) goto print_and_exit;
$cases[] = array("ext/token, scope not whole blocks", extauth_token_direct($cfg_domain, $app, $r['jti'], "A" . base64_encode(random_bytes(20) . $r['mac']), $t), 406);
if ( ($r = $t15_req()) === false ) goto print_and_exit;
$cases[] = array("ext/token, scope padding byte 0", extauth_token_direct($cfg_domain, $app, $r['jti'], "A" . base64_encode($r['pad0'] . $r['mac']), $t), 406);
if ( ($r = $t15_req()) === false ) goto print_and_exit;
$cases[] = array("ext/token, scope wrong MAC", extauth_token_direct($cfg_domain, $app, $r['jti'], "A" . base64_encode(substr($r['raw'], 0, -32) . random_bytes(32)), $t), 406);
if ( ($r = $t15_req()) === false ) goto print_and_exit;
$cases[] = array("ext/token, pid = 16 B prefix of the paired pid", extauth_token_direct($cfg_domain, $short, $r['jti'], extauth_seal($r['plain'], $r['m']), $t), 406);
if ( ($r = $t15_req()) === false ) goto print_and_exit;
$cases[] = array("ext/token, the same authreply again (DEV-499 A4: jti single use)", extauth_token_direct($cfg_domain, $app, $r['jti'], extauth_seal($r['plain'], $r['m']), $t), 200);
$cases[] = array("ext/token, replayed authreply", extauth_token_direct($cfg_domain, $app, $r['jti'], extauth_seal($r['plain'], $r['m']), $t), 401);
$cases[] = array("ext/validate, pid 16 B", extauth_pair_direct($cfg_domain, $token_cfg, "T-15 ExtAuth 16", $app16, $code_ok, 16), 400);
// DEV-502 (T-15.7): a pairing reply with an epk that is not 32 B is refused before the app key is stored (DEV-501 G1 D4) - the same
//   app then pairs with a valid reply (a stored key would answer 409 already paired)
$app_e = extauth_new_app();
foreach (array(30 => 400, 32 => 200) as $epk_len => $want) {
  $ret_val = false;
  $post_data = json_encode(array('epk' => base64_encode(sodium_crypto_scalarmult_base(random_bytes(32)))));
  if ( http_transaction("https", "POST", $cfg_domain, "/api/auth/ext/init", $ret_val, $post_data, $token_cfg) != 200 ) goto print_and_exit;
  $req = extauth_payload($ret_val['request']);
  $req['aud'] = base64_encode(substr(base64_decode($req['aud']), 0, $epk_len));   // becomes the epk claim of the reply
  $app_e['eid'] = base64_decode($ret_val['eid']);
  $app_e['pid'] = base64_encode(random_bytes(32));
  $ret_val = false;
  $post_data = json_encode(array('pid' => $app_e['pid'], 'reply' => extauth_pairing_reply($app_e, $req, "T-15 ExtAuth epk")));
  $cases[] = array("ext/validate, epk $epk_len B" . (($epk_len == 32) ? ", same app again (not stored before)" : ""), http_transaction("https", "POST", $cfg_domain, "/api/auth/ext/validate", $ret_val, $post_data, $token_cfg), $want);
}
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
// a) a token without a scope is not issued (DEV-436: auth/token answers 400; DEV-438: an empty scope was a crash)
$cases = array();
$cases[] = array("auth/token with an empty scope is refused", auth_with_claims(function ($c) { $c['scope'] = ""; return $c; }), 400);   // DEV-502 (T-15.9 a): the real status (was 400 for any failure of helper_authorize)
$not_used = false;
// b) firmware upload: a wrong extension and a file of 3 MiB or more are answered (DEV-438: was no response at all)
$token_upg = helper_authorize($cfg_domain, $cfg_passpharse, "system:upgrade");
if ($token_upg == false) goto print_and_exit;
$cases[] = array("upload_fw, name x.txt", raw_https_request($cfg_domain, "POST /api/system/upgrade/upload_fw HTTP/1.1\r\nHost: $cfg_domain\r\nAuthorization: Bearer $token_upg\r\nContent-Disposition: attachment; filename=\"x.txt\"\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0123456789"), 400);
$cases[] = array("upload_fw, 3 MiB (body not sent)", raw_https_request($cfg_domain, "POST /api/system/upgrade/upload_fw HTTP/1.1\r\nHost: $cfg_domain\r\nAuthorization: Bearer $token_upg\r\nContent-Disposition: attachment; filename=\"fw.bin\"\r\nContent-Length: 3145728\r\nConnection: close\r\n\r\n"), 413);
// DEV-502 (T-15.9 b): upload_fw while check_fw runs is refused (DEV-501 G6 D.10); the running image passes the check (about 5 s)
$fw_image = getenv("ENCEDO_FW_IMAGE") ? getenv("ENCEDO_FW_IMAGE") : __DIR__ . "/../encedo_firmware/Firmware/EncedoKey/Encedo_FW_USB_v1_signed.bin";   // DEV-519: the post-build names the signed bin like the signed hex (was tmp_signed.bin)
$post_data = @file_get_contents($fw_image);
if ( $post_data === false ) echo "    $fw_image not found - upload_fw during check_fw skipped\n";
else {
  $ret_val = false;
  $cases[] = array("upload_fw, signed image", http_transaction("https", "POST", $cfg_domain, "/api/system/upgrade/upload_fw", $ret_val, $post_data, $token_upg, "firmware.bin"), 200);
  $ret_val = false;
  $cases[] = array("check_fw, start", http_transaction("https", "GET", $cfg_domain, "/api/system/upgrade/check_fw", $ret_val, $not_used, $token_upg), 201);
  $cases[] = array("upload_fw during check_fw", raw_https_request($cfg_domain, "POST /api/system/upgrade/upload_fw HTTP/1.1\r\nHost: $cfg_domain\r\nAuthorization: Bearer $token_upg\r\nContent-Disposition: attachment; filename=\"firmware.bin\"\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0123456789"), 409);
  for ($i = 0; $i < 60; $i++) {
    usleep(500000);
    $ret_val = false;
    if ( ($ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/upgrade/check_fw", $ret_val, $not_used, $token_upg)) != 202 ) break;
  }
  $cases[] = array("check_fw, result (the 409 upload did not touch the image)", $ret_stat, 200);
}
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
// b) remote authentication (ext/token): failed attempts are answered after at least 500 ms; after more than 3 failures after at least 1500 ms
//    (DEV-438 phase 2 group 3: the delay guard was inverted - no delay, no count)
// DEV-499 (D3): the counter is still loaded by the 406s of subtest 7 - a success more than 15 s after the last failure clears it, so the
//    measurement starts from zero (400 replies are neither delayed nor counted)
sleep(16);
$authreq = false;
if ( extauth_request_direct($cfg_domain, "keymgmt:list", $authreq) != 200 ) goto print_and_exit;
$t = false;
if ( extauth_token_direct($cfg_domain, $app, $authreq['jti'], $authreq['scope'][$app['pid']], $t) != 200 ) { echo "    ext/token (counter reset): refused\n"; goto print_and_exit; }   // expected is 200
$times = array();
for ($i = 0; $i < 5; $i++) {
  $t0 = hrtime(true);
  $ret_val = false;
  $post_data = json_encode( array('authreply' => "eyJhbGciOiJIUzI1NiJ9.e30.AAAA") );
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/auth/ext/token", $ret_val, $post_data);
  $times[] = intval((hrtime(true) - $t0) / 1000000);
  if ( $ret_stat != 401 ) { echo "    ext/token with an invalid authreply: HTTP $ret_stat, expected 401\n"; goto print_and_exit; }
}
if ( ($times[0] < 450) || ($times[0] >= 1400) || ($times[4] < 1400) ) { echo "    ext/token failure delays (ms): " . implode(", ", $times) . " - expected >= 500 (not 1500) for the 1st, >= 1500 for the 5th\n"; goto print_and_exit; }   // DEV-499 (D3)
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
               "cipher/encrypt, unknown kid" => array("https", "POST", "/api/crypto/cipher/encrypt", array('kid' => $kid_none, 'msg' => $msg, 'alg' => "AES256-CBC"), $keys['none'][1], 404),   // DEV-481 (B7): CBC (ECB is off in the build)
               "cipher/wrap, unknown kid" => array("https", "POST", "/api/crypto/cipher/wrap", array('kid' => $kid_none, 'msg' => base64_encode(random_bytes(32)), 'alg' => "AES256"), $keys['none'][1], 404),
               "ecdh, unknown kid" => array("https", "POST", "/api/crypto/ecdh", array('kid' => $kid_none, 'pubkey' => $peer, 'alg' => "SHA2-256"), $keys['none'][1], 404),   // DEV-499 (D2): alg - without it the raw_ecdh policy answers 403 first
               "pqc/mlkem/encaps, unknown kid" => array("https", "POST", "/api/crypto/pqc/mlkem/encaps", array('kid' => $kid_none), $keys['none'][1], 404),
               "cipher/encrypt, ED25519 key" => array("https", "POST", "/api/crypto/cipher/encrypt", array('kid' => $keys['ed'][0], 'msg' => $msg, 'alg' => "AES256-CBC"), $keys['ed'][1], 400),   // DEV-481 (B7): CBC (ECB is off in the build)
               "ecdh, ExDSA-only key" => array("https", "POST", "/api/crypto/ecdh", array('kid' => $keys['ed'][0], 'pubkey' => $peer, 'alg' => "SHA2-256"), $keys['ed'][1], 400),   // DEV-499 (D2)
               "ecdh, alg not a string (DEV-499 B7)" => array("https", "POST", "/api/crypto/ecdh", array('kid' => $kid_ecdh, 'pubkey' => $peer, 'alg' => 5), $token_ecdh, 400),
               "system/config, storage_mode 0x10 (DEV-499 B2: Disk1 without crypto)" => array("https", "POST", "/api/system/config", array('storage_mode' => 16), $token_cfg, 400),
               "hmac/hash, alg too long" => array("https", "POST", "/api/crypto/hmac/hash", array('kid' => $keys['hm'][0], 'msg' => $msg, 'alg' => "SHA2-256-X"), $keys['hm'][1], 400),
               "ecdh, no pubkey / ext_kid" => array("https", "POST", "/api/crypto/ecdh", array('kid' => $kid_ecdh, 'alg' => "SHA2-256"), $token_ecdh, 400),   // DEV-499 (D2)
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
// e) keymgmt/get of the TLS private key gives its public key only, of the TLS certificate the DER - the pubkey must be the certificate key
//    (DEV-472: the DER of the TLS private key was returned)
$token_get = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:get");
if ($token_get == false) goto print_and_exit;
$tls = array();
$offset = 0;
do {                                                          // DEV-499 (D2): all pages - a renewed TLS record is stored after the keys of T-10 .. T-14; the check-in renewal labels it "TLS x509 CERT"
  $ret_val = false;
  $not_used = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/keymgmt/list/$offset", $ret_val, $not_used, $token_keylist);
  if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
  foreach ($ret_val['list'] as $k) {
    if ( @$k['label'] === "TLS PrivateKey" ) $tls["TLS PrivateKey"] = $k['kid'];
    if ( in_array(@$k['label'], array("TLS Certificate", "TLS x509 CERT")) ) $tls["TLS Certificate"] = $k['kid'];
  }
  $offset = $offset + $ret_val['listed'];
  if ( ($offset >= $ret_val['total']) || ($ret_val['listed'] == 0) ) break;
} while(true);
if ( count($tls) != 2 ) { echo "    TLS key / certificate not listed\n"; goto print_and_exit; }
$got = array();
foreach (array("TLS PrivateKey" => false, "TLS Certificate" => true) as $label => $der) {
  $ret_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/keymgmt/get/" . $tls[$label], $ret_val, $not_used, $token_get);
  $cases[] = array("keymgmt/get $label, der " . ($der ? "returned" : "not returned"), (($ret_stat == 200) && (isset($ret_val['der']) !== $der)) ? -1 : $ret_stat, 200);   // -1: der returned / missing
  $got[$label] = $ret_val;
}
$pub = false;   // the certificate public key as a compressed x963 point (the pubkey format of the ECC keys)
if ( isset($got["TLS Certificate"]['der']) ) {
  $ec = @openssl_pkey_get_details(openssl_pkey_get_public("-----BEGIN CERTIFICATE-----\n" . chunk_split($got["TLS Certificate"]['der'], 64, "\n") . "-----END CERTIFICATE-----\n"));
  if ( isset($ec['ec']['x'], $ec['ec']['y']) ) $pub = base64_encode(((ord(substr($ec['ec']['y'], -1)) & 1) ? "\x03" : "\x02") . str_pad($ec['ec']['x'], 32, "\0", STR_PAD_LEFT));   // P-256 (the TLS key)
}
$cases[] = array("keymgmt/get TLS PrivateKey, pubkey = the certificate key", (($pub !== false) && (@$got["TLS PrivateKey"]['pubkey'] === $pub)) ? 200 : -1, 200);
if ( !check_cases($cases) ) goto print_and_exit;
if ( !check_alive($uptime) ) goto print_and_exit;
// f) set result
$test_cfg['subtests'][13] = 'OK';                             // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 15       ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST15:
echo "  subtest-15\n";
$test_cfg['subtests'][15] = 'ERROR';                          // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) multi-scope tokens (DEV-436), issuing: scope is a string or an array of 1..8 valid values; the token gets the type
//    requested; a missing / empty / invalid scope is refused with 400 and no token is issued
$kid_any = bin2hex(random_bytes(16));                         // keymgmt:use:<kid> needs no existing key
$eight = array("keymgmt:list");
for ($i = 0; $i < 7; $i++) $eight[] = "keymgmt:use:" . bin2hex(random_bytes(16));
$cases = array();
foreach (array("scope claim missing" => null, "scope \"\"" => "", "scope []" => array(), "scope null" => "null",
               "scope number" => 5, "scope bool" => true, "scope object" => new stdClass(),
               "keymgmt:delXYZ (trailing data)" => "keymgmt:delXYZ", "uppercase" => "KEYMGMT:LIST", "trailing space" => "keymgmt:list ",
               "with #" => "keymgmt:list#x", "45 chars" => "keymgmt:use:" . $kid_any . "0", "not a scope (system:reboot)" => "system:reboot",
               "x509 scope (ca:sign)" => "ca:sign", "keymgmt:use: non-hex KID" => "keymgmt:use:" . str_repeat("zz", 16),
               "keymgmt:use: 30 hex" => "keymgmt:use:" . substr($kid_any, 2), "storage:disk0:xx" => "storage:disk0:xx", "storage:disk9" => "storage:disk9",
               "array of 9" => array_merge($eight, array("logger:get")), "element number" => array("keymgmt:list", 1),
               "element null" => array(null), "element bool" => array(true), "nested array" => array(array("keymgmt:list")),
               "element object" => array(new stdClass()), "element \"\"" => array(""), "duplicate" => array("keymgmt:list", "keymgmt:list"),
               "two storage" => array("storage:disk0", "storage:disk1"), "storage:disk0 + storage:disk0:rw" => array("storage:disk0", "storage:disk0:rw")) as $name => $scope) {
  $cases[] = array("auth/token, $name", auth_with_claims(function($c) use ($scope) {
    if ($scope === null) unset($c['scope']); else $c['scope'] = ($scope === "null") ? null : $scope;
    return $c; }), 400);
}
foreach (array("string" => "keymgmt:list", "array of 1" => array("keymgmt:list"), "array of 8 (7 x 44 chars)" => $eight,
               "keymgmt:use:<kid of no key>" => "keymgmt:use:$kid_any", "storage:disk0:rw" => "storage:disk0:rw",
               "keymgmt:list + storage:disk1:ro" => array("keymgmt:list", "storage:disk1:ro")) as $name => $scope) {
  $cases[] = array("auth/token, $name", auth_with_claims(function($c) use ($scope) { $c['scope'] = $scope; return $c; }), 200);
}
if ( !check_cases($cases) ) goto print_and_exit;
// b) the issued token keeps the type requested
$t = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:list");
$t1 = helper_authorize($cfg_domain, $cfg_passpharse, array("keymgmt:list"));
$t8 = helper_authorize($cfg_domain, $cfg_passpharse, $eight);
if ( ($t == false) || ($t1 == false) || ($t8 == false) ) goto print_and_exit;
$p = extauth_payload($t); $p1 = extauth_payload($t1); $p8 = extauth_payload($t8);
if ( $p['scope'] !== "keymgmt:list" ) { echo "    string request: token scope " . json_encode($p['scope']) . "\n"; goto print_and_exit; }
if ( $p1['scope'] !== array("keymgmt:list") ) { echo "    1-element array request: token scope " . json_encode($p1['scope']) . "\n"; goto print_and_exit; }
if ( $p8['scope'] !== $eight ) { echo "    8-element array request: token scope " . json_encode($p8['scope']) . "\n"; goto print_and_exit; }
if ( !check_alive($uptime) ) goto print_and_exit;
// c) set result
$test_cfg['subtests'][15] = 'OK';                             // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 16       ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST16:
echo "  subtest-16\n";
$test_cfg['subtests'][16] = 'ERROR';                          // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) multi-scope tokens (DEV-436), access: the values of an array are checked in order, the first one the endpoint
//    accepts grants access (exact match; storage takes the disk and :rw from the matching value)
$not_used = false;
$t_list = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:list");
$t_arr = helper_authorize($cfg_domain, $cfg_passpharse, array("logger:get", "keymgmt:list"));
$t_cfg2 = helper_authorize($cfg_domain, $cfg_passpharse, array("keymgmt:list", "system:config"));
$t_st = helper_authorize($cfg_domain, $cfg_passpharse, array("keymgmt:list", "storage:disk0"));
$t_use8 = array();
for ($i = 0; $i < 8; $i++) $t_use8[] = "keymgmt:use:" . bin2hex(random_bytes(16));
$t_use8 = helper_authorize($cfg_domain, $cfg_passpharse, $t_use8);
$t_wc = helper_authorize($cfg_domain, $cfg_passpharse, $eight);   // from subtest 15: keymgmt:list first, then 7 x 44 chars
if ( ($t_list == false) || ($t_arr == false) || ($t_cfg2 == false) || ($t_st == false) || ($t_use8 == false) || ($t_wc == false) ) goto print_and_exit;
$ret_val = false;
if ( http_transaction("https", "GET", $cfg_domain, "/api/keymgmt/list", $ret_val, $not_used, $t_list) != 200 ) goto print_and_exit;
if ( !isset($ret_val['list'][0]['kid']) ) { echo "    no key on the TOE for the KID case\n"; goto print_and_exit; }
$kid = $ret_val['list'][0]['kid'];
$t_kid = helper_authorize($cfg_domain, $cfg_passpharse, array("logger:get", "keymgmt:use:$kid"));
$t_kid2 = helper_authorize($cfg_domain, $cfg_passpharse, array("logger:get", "keymgmt:use:" . bin2hex(random_bytes(16))));
if ( ($t_kid == false) || ($t_kid2 == false) ) goto print_and_exit;
$cases = array();
foreach (array("array, 2nd value matches (keymgmt/list)" => array("/api/keymgmt/list", $t_arr, 200),
               "array, 1st value matches (logger/list/0)" => array("/api/logger/list/0", $t_arr, 200),
               "array, no value matches (storage/unlock)" => array("/api/storage/unlock", $t_arr, 403),
               "array, system:config 2nd (system/config)" => array("/api/system/config", $t_cfg2, 200),
               "string keymgmt:list (keymgmt/list)" => array("/api/keymgmt/list", $t_list, 200),
               "string keymgmt:list (system/config)" => array("/api/system/config", $t_list, 403),
               "worst-case token, 8 values (keymgmt/list)" => array("/api/keymgmt/list", $t_wc, 200),
               "8 x keymgmt:use:<other> (keymgmt/list)" => array("/api/keymgmt/list", $t_use8, 403),
               "array, keymgmt:use:<kid> 2nd (keymgmt/get/<kid>)" => array("/api/keymgmt/get/$kid", $t_kid, 200),
               "array, keymgmt:use:<other kid> (keymgmt/get/<kid>)" => array("/api/keymgmt/get/$kid", $t_kid2, 403),
               "array, storage:disk0 2nd (storage/unlock)" => array("/api/storage/unlock", $t_st, 200),
               "array, storage:disk0 (storage/unlock/rw, ro value)" => array("/api/storage/unlock/rw", $t_st, 403),
               "array, storage:disk0 (storage/lock)" => array("/api/storage/lock", $t_st, 200),
               "string token, crypto/random (no scope)" => array("/api/crypto/random", $t_list, 200),
               "array token, crypto/random (no scope)" => array("/api/crypto/random", $t_arr, 200),
               "string token, system/selftest (system:config needed)" => array("/api/system/selftest", $t_list, 403),   // DEV-501 (G5 D12): was any scope -> 200
               "array token, system/selftest (system:config needed)" => array("/api/system/selftest", $t_arr, 403),    // DEV-501 (G5 D12)
               "string token, config/attestation (no scope)" => array("/api/system/config/attestation", $t_list, 200),
               "array token, config/attestation (no scope)" => array("/api/system/config/attestation", $t_arr, 200)) as $name => $v) {
  $ret_val = false;
  $cases[] = array($name, http_transaction("https", "GET", $cfg_domain, $v[0], $ret_val, $not_used, $v[1]), $v[2]);
}
if ( !check_cases($cases) ) goto print_and_exit;
// b) DEV-502 (T-15.16 b): system/selftest with system:config runs (200); a second call during the run gets 409 instead of
//    waiting (DEV-501 G5 D12) - the synchronous part takes about 1.5 s
$t_self = helper_authorize($cfg_domain, $cfg_passpharse, "system:config");
if ( $t_self == false ) goto print_and_exit;
$req = "GET /api/system/selftest HTTP/1.1\r\nHost: $cfg_domain\r\nAuthorization: Bearer $t_self\r\n\r\n";
$sock_a = raw_https_connect($cfg_domain);
$sock_b = raw_https_connect($cfg_domain);
if ( ($sock_a == false) || ($sock_b == false) ) goto print_and_exit;
stream_set_timeout($sock_a, 60);
fwrite($sock_a, $req);
usleep(100000);                                               // the first call is inside the test
$cases = array();
$cases[] = array("system/selftest during a running one", raw_https_transaction($sock_b, $req), 409);
$cases[] = array("system/selftest, system:config", raw_https_transaction($sock_a, ""), 200);
fclose($sock_a);
fclose($sock_b);
if ( !check_cases($cases) ) goto print_and_exit;
if ( !check_alive($uptime) ) goto print_and_exit;
// c) set result
$test_cfg['subtests'][16] = 'OK';                             // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 17       ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST17:
echo "  subtest-17\n";
$test_cfg['subtests'][17] = 'ERROR';                          // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) multi-scope tokens (DEV-436), external authenticator directly with the HEM (libs/extauth.php): ext/request takes a
//    string or an array (same rules as auth/token), the sealed plaintext is the values separated by spaces; ext/token
//    issues a string for one value and an array for more; a tampered blob fails the MAC
$app = false;
$code_ok = false;
if ( extauth_pair_direct($cfg_domain, $token_cfg, "T-15 ExtAuth DEV-436", $app, $code_ok) != 200 ) goto print_and_exit;
foreach (array(array(array("keymgmt:list"), "keymgmt:list", "keymgmt:list"),
               array(array("keymgmt:list", "logger:get"), "keymgmt:list logger:get", array("keymgmt:list", "logger:get")),
               array("keymgmt:list", "keymgmt:list", "keymgmt:list")) as $v) {
  $authreq = false;
  if ( extauth_request_direct($cfg_domain, $v[0], $authreq) != 200 ) { echo "    ext/request " . json_encode($v[0]) . " refused\n"; goto print_and_exit; }
  $sealed = isset($authreq['scope'][$app['pid']]) ? $authreq['scope'][$app['pid']] : false;
  $m = extauth_session_key($app['aid_prv'], $app['eid'], $authreq['jti']);
  $plain = extauth_unseal($sealed, $m);
  if ( $plain !== $v[1] ) { echo "    ext/request " . json_encode($v[0]) . ": sealed plaintext " . var_export($plain, true) . "\n"; goto print_and_exit; }
  $t = false;
  if ( extauth_token_direct($cfg_domain, $app, $authreq['jti'], $sealed, $t) != 200 ) { echo "    ext/token " . json_encode($v[0]) . " refused\n"; goto print_and_exit; }
  $p = extauth_payload($t);
  if ( $p['scope'] !== $v[2] ) { echo "    ext/token " . json_encode($v[0]) . ": token scope " . json_encode($p['scope']) . "\n"; goto print_and_exit; }
}
$ret_val = false;
$not_used = false;
if ( http_transaction("https", "GET", $cfg_domain, "/api/system/config", $ret_val, $not_used, $t) != 403 ) { echo "    ext token keymgmt:list accepted by system/config\n"; goto print_and_exit; }
// b) the KID info (#...) is added for the first keymgmt:use: value of a list
$authreq = false;
if ( extauth_request_direct($cfg_domain, array("keymgmt:use:$kid", "logger:get"), $authreq) != 200 ) goto print_and_exit;
$m = extauth_session_key($app['aid_prv'], $app['eid'], $authreq['jti']);
$plain = extauth_unseal(isset($authreq['scope'][$app['pid']]) ? $authreq['scope'][$app['pid']] : false, $m);
if ( !is_string($plain) || (strpos($plain, "keymgmt:use:$kid logger:get#") !== 0) ) { echo "    KID info: " . var_export($plain, true) . "\n"; goto print_and_exit; }
if ( ($authreq['exp'] - $authreq['iat']) != 900 ) { echo "    KID request lifetime " . ($authreq['exp'] - $authreq['iat']) . " s, expected 900\n"; goto print_and_exit; }
// c) a 2-value token from ext works on the endpoint of its 2nd value; a tampered blob is refused
$authreq = false;
if ( extauth_request_direct($cfg_domain, array("keymgmt:list", "logger:get"), $authreq) != 200 ) goto print_and_exit;
$sealed = $authreq['scope'][$app['pid']];
$raw = base64_decode(substr($sealed, 1));
$raw[0] = chr(ord($raw[0]) ^ 1);
$t = false;
$t2 = false;
$cases = array();
$cases[] = array("ext/token, tampered blob", extauth_token_direct($cfg_domain, $app, $authreq['jti'], "A" . base64_encode($raw), $t2), 406);
$authreq = false;   // DEV-499 (D4): the jti above is consumed by the tampered attempt - a fresh request for the valid case
if ( extauth_request_direct($cfg_domain, array("keymgmt:list", "logger:get"), $authreq) != 200 ) goto print_and_exit;
$sealed = $authreq['scope'][$app['pid']];
$cases[] = array("ext/token, 2 values", extauth_token_direct($cfg_domain, $app, $authreq['jti'], $sealed, $t), 200);
$ret_val = false;
$cases[] = array("ext token [keymgmt:list, logger:get], logger/list/0", http_transaction("https", "GET", $cfg_domain, "/api/logger/list/0", $ret_val, $not_used, $t), 200);
// d) ext/request refuses what auth/token refuses
foreach (array("\"\"" => "", "[]" => array(), "array of 9" => array_merge($eight, array("logger:get")), "trailing data" => "keymgmt:delXYZ",
               "duplicate" => array("logger:get", "logger:get"), "null" => null, "number" => 5) as $name => $scope) {
  $authreq = false;
  $cases[] = array("ext/request, scope $name", extauth_request_direct($cfg_domain, $scope, $authreq), 400);
}
if ( !check_cases($cases) ) goto print_and_exit;
if ( !check_alive($uptime) ) goto print_and_exit;
// e) set result
$test_cfg['subtests'][17] = 'OK';                             // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 18       ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST18:
echo "  subtest-18\n";
$test_cfg['subtests'][18] = 'ERROR';                          // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) DEV-502 (G5 D1): a request without the Host header is answered (strstr(NULL) before) and carries the hostname
$cases = array();
$hdrs = false; $body = false;
$cases[] = array("GET status without Host", raw_https_request($cfg_domain, "GET /api/system/status HTTP/1.0\r\nConnection: close\r\n\r\n", $hdrs, $body), 200);
$j = json_decode((string)$body, true);
$cases[] = array("status without Host carries hostname", (is_array($j) && isset($j['hostname'])) ? 200 : 500, 200);
// b) DEV-502 (G1 D1): a consumed auth jti stays consumed for its whole 120 s window, not only for the next 16 validations
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/auth/token", $ret_val);
if ( $ret_stat != 200 ) goto print_and_exit;
$secret = hash_pbkdf2("sha256", $cfg_passpharse, $ret_val['eid'], 600000, 32, true);
$iat = time() - 5;
$auth = ejwt_generate(array('jti' => $ret_val['jti'], 'aud' => $ret_val['spk'], 'exp' => $iat + 3600, 'iat' => $iat,
                            'iss' => base64_encode(sodium_crypto_box_publickey_from_secretkey($secret)), 'scope' => "keymgmt:list"), $secret, base64_decode($ret_val['spk']));
$post_data = json_encode(array('auth' => $auth));
$ret_val = false;
$cases[] = array("auth JWT, first use", http_transaction("http", "POST", $cfg_domain, "/api/auth/token", $ret_val, $post_data), 200);
for ($i = 0; $i < 20; $i++) {                                 // 20 other consumed nonces - the old ring of 16 evicted the first one here
  if ( helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:list") == false ) goto print_and_exit;
}
$ret_val = false;
$cases[] = array("auth JWT replayed after 20 other authorizations", http_transaction("http", "POST", $cfg_domain, "/api/auth/token", $ret_val, $post_data), 401);
if ( !check_cases($cases) ) goto print_and_exit;
if ( !check_alive($uptime) ) goto print_and_exit;
// c) set result
$test_cfg['subtests'][18] = 'OK';                             // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////
// Subtest: 19       ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST19:
echo "  subtest-19\n";
$test_cfg['subtests'][19] = 'ERROR';                          // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) DEV-519 (M2, H11): JWTs whose segments do not decode - an empty header / body segment, a header segment of 7000 chars in
//    a request body - are refused as any bad JWT; the TOE stays out of the failure state (fls_state 0) and does not restart
//    (before: an empty segment set fls_state 0x10 until reboot, the long segment overflowed the worker stack - restart, 0x20)
$cases = array();
$ret_val = false;
$cases[] = array("auth/token, JWT with an empty header", http_transaction("http", "POST", $cfg_domain, "/api/auth/token", $ret_val, json_encode(array('auth' => ".e30.AAAA"))), 401);
$ret_val = false;
$cases[] = array("auth/token, JWT with an empty body", http_transaction("http", "POST", $cfg_domain, "/api/auth/token", $ret_val, json_encode(array('auth' => "eyJhbGciOiJIUzI1NiJ9..AAAA"))), 401);
$cases[] = array("bearer JWT with an empty header", raw_https_request($cfg_domain, "GET /api/system/config HTTP/1.1\r\nHost: $cfg_domain\r\nAuthorization: Bearer .e30.AAAA\r\nConnection: close\r\n\r\n"), 401);
$ret_val = false;
$cases[] = array("checkin, JWT header segment of 7000 chars", http_transaction("http", "POST", $cfg_domain, "/api/system/checkin", $ret_val, json_encode(array('checked' => str_repeat("A", 7000) . ".e30.AAAA"))), 401);
if ( !check_cases($cases) ) goto print_and_exit;
$ret_val = false;
if ( (http_transaction("http", "GET", $cfg_domain, "/api/system/status", $ret_val) != 200) || (@$ret_val['fls_state'] != 0) ) { echo "    fls_state " . @$ret_val['fls_state'] . " after the JWT cases, expected 0\n"; goto print_and_exit; }
if ( !check_alive($uptime) ) goto print_and_exit;
// b) DEV-519 (M3, M1): a folded header line (obs-fold) and an Origin over 256 chars are refused with 400 and the connection
//    closed (before: the folded line was served after a write through NULL; any Origin length was copied and echoed - over http
//    the headers outgrew the 2920 B buffer and bytes past it were sent); an Origin of 256 chars is still served (origin "*")
$o = "https://" . str_repeat("a", 248);                       // 256 chars
$cases = array();
$cases[] = array("folded header line", raw_https_request($cfg_domain, "GET /api/system/status HTTP/1.1\r\nHost: $cfg_domain\r\nX-Test: a\r\n b\r\nConnection: close\r\n\r\n"), 400);
$cases[] = array("Origin of 256 chars", raw_https_request($cfg_domain, "GET /api/system/status HTTP/1.1\r\nHost: $cfg_domain\r\nOrigin: $o\r\nConnection: close\r\n\r\n"), 200);
$cases[] = array("Origin of 257 chars", raw_https_request($cfg_domain, "GET /api/system/status HTTP/1.1\r\nHost: $cfg_domain\r\nOrigin: " . $o . "a\r\nConnection: close\r\n\r\n"), 400);
$cases[] = array("Origin of 2780 chars", raw_https_request($cfg_domain, "GET /api/system/status HTTP/1.1\r\nHost: $cfg_domain\r\nOrigin: https://" . str_repeat("b", 2772) . "\r\nConnection: close\r\n\r\n"), 400);
if ( !check_cases($cases) ) goto print_and_exit;
if ( !check_alive($uptime) ) goto print_and_exit;
// c) set result
$test_cfg['subtests'][19] = 'OK';                             // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////
// Subtest: 20       ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST20:
echo "  subtest-20\n";
$test_cfg['subtests'][20] = 'ERROR';                          // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) DEV-519 (H3): web UI archive check (upload_ui + check_ui, nothing installed): a valid archive passes; a file not in the
//    manifest and a hash token that is not 64 hex chars are refused (before: the extra file passed unchecked, a token of
//    400 hex chars was decoded into a 32-byte stack buffer - restart); the TOE does not restart
$token_ui = helper_authorize($cfg_domain, $cfg_passpharse, "system:upgrade");
if ($token_ui == false) goto print_and_exit;
$cases = array();
$cases[] = array("UI archive, valid", ui_archive_check($token_ui), 200);
$cases[] = array("UI archive, a file not in the manifest", ui_archive_check($token_ui, array('extra.js' => "alert(1)\n")), 406);
$cases[] = array("UI archive, hash token of 66 hex chars", ui_archive_check($token_ui, array(), hash('sha256', 'x') . 'ab'), 406);
$cases[] = array("UI archive, hash token of 400 hex chars", ui_archive_check($token_ui, array(), str_repeat('ab', 200)), 406);
$cases[] = array("UI archive, hash token of 63 hex chars", ui_archive_check($token_ui, array(), substr(hash('sha256', 'x'), 1)), 406);
if ( !check_cases($cases) ) goto print_and_exit;
if ( !check_alive($uptime) ) goto print_and_exit;
// b) set result
$test_cfg['subtests'][20] = 'OK';                             // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////
// Subtest: 21       ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST21:
echo "  subtest-21
";
$test_cfg['subtests'][21] = 'ERROR';                          // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) DEV-519 (H4): the descr of a paired external authenticator ("EXTAID" + pid) is reserved - keymgmt create / import / derive /
//    update refuse it (400) and a pairing record cannot be updated (409); before, an imported X25519 public key with that descr
//    was a pairing for ext/request / ext/token
$token_gen = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:gen");
$token_imp = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:imp");
$token_upd = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:upd");
$token_der = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:derive");
$token_src = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:search");
$token_del = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:del");
if ( ($token_gen == false) || ($token_imp == false) || ($token_upd == false) || ($token_der == false) || ($token_src == false) || ($token_del == false) ) goto print_and_exit;
$run = bin2hex(random_bytes(3));
$extaid = base64_encode("EXTAID" . random_bytes(32));
$made = array();                                              // KIDs of keys this subtest made - deleted at the end
$cases = array();
$ret_val = false;
$post_data = json_encode( array('label' => "T-15.21 imp $run", 'type' => "CURVE25519", 'mode' => "ECDH", 'pubkey' => base64_encode(sodium_crypto_scalarmult_base(random_bytes(32))), 'descr' => $extaid) );
$cases[] = array("keymgmt/import X25519 public key, descr EXTAID+pid", $st = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/import", $ret_val, $post_data, $token_imp), 400);
if ( ($st == 200) && isset($ret_val['kid']) ) $made[] = $ret_val['kid'];
$ret_val = false;
$post_data = json_encode( array('label' => "T-15.21 gen $run", 'type' => "AES256", 'descr' => $extaid) );
$cases[] = array("keymgmt/create AES256, descr EXTAID+pid", $st = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/create", $ret_val, $post_data, $token_gen), 400);
if ( ($st == 200) && isset($ret_val['kid']) ) $made[] = $ret_val['kid'];
$ret_val = false;
$post_data = json_encode( array('label' => "T-15.21 ecdh $run", 'type' => "CURVE25519", 'mode' => "ECDH", 'descr' => base64_encode("CCTEST:T-15.21")) );
if ( http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/create", $ret_val, $post_data, $token_gen) != 200 ) goto print_and_exit;
$kid_ecdh = $ret_val['kid'];
$made[] = $kid_ecdh;
$ret_val = false;
$post_data = json_encode( array('kid' => $kid_ecdh, 'label' => "T-15.21 der $run", 'type' => "AES256", 'pubkey' => base64_encode(sodium_crypto_scalarmult_base(random_bytes(32))), 'descr' => $extaid) );
$cases[] = array("keymgmt/derive, descr EXTAID+pid", $st = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/derive", $ret_val, $post_data, $token_der), 400);
if ( ($st == 200) && isset($ret_val['kid']) ) $made[] = $ret_val['kid'];
$ret_val = false;
$post_data = json_encode( array('kid' => $kid_ecdh, 'label' => "T-15.21 upd $run", 'descr' => $extaid) );
$cases[] = array("keymgmt/update, descr EXTAID+pid", http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/update", $ret_val, $post_data, $token_upd), 400);
$app = false;
$code_ok = false;
if ( extauth_pair_direct($cfg_domain, $token_cfg, "T-15.21 $run", $app, $code_ok) != 200 ) goto print_and_exit;
$ret_val = false;
$post_data = json_encode( array('descr' => "^" . base64_encode("EXTAID" . substr(base64_decode($app['pid']), 0, 30))) );   // 36 B - a prefix without padding
if ( (http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/search", $ret_val, $post_data, $token_src) != 200) || !isset($ret_val['list'][0]['kid']) ) { echo "    pairing record not found\n"; goto print_and_exit; }
$kid_pair = $ret_val['list'][0]['kid'];
$made[] = $kid_pair;
// (the update of the pairing record runs last, in d): before the fix it went through and, without descr, removed the pairing)
// b) DEV-519 (M5): token lifetime - no exp: 5 min (was 60 s); a later exp is cut to 12 h (auth/token took it unchanged, ext/token
//    took the authenticator's); ext/token: the scope of the reply must pass the auth/token scope rules (was taken as it came)
$tok_exp = function($claims_mod) use ($cfg_domain, $cfg_passpharse) {   // auth/token as helper_authorize, claims changed; the token's exp - iat, or false
  $ret_val = false;
  if ( http_transaction("http", "GET", $cfg_domain, "/api/auth/token", $ret_val) != 200 ) return false;
  $secret = hash_pbkdf2("sha256", $cfg_passpharse, $ret_val['eid'], 600000, 32, true);
  $iat = time() - 5;
  $claims = $claims_mod(array('jti' => $ret_val['jti'], 'aud' => $ret_val['spk'], 'exp' => $iat + 600, 'iat' => $iat,
                              'iss' => base64_encode(sodium_crypto_box_publickey_from_secretkey($secret)), 'scope' => "keymgmt:list"));
  $post_data = json_encode( array('auth' => ejwt_generate($claims, $secret, base64_decode($ret_val['spk']))) );
  $ret_val = false;
  if ( http_transaction("http", "POST", $cfg_domain, "/api/auth/token", $ret_val, $post_data) != 200 ) return false;
  $p = extauth_payload($ret_val['token']);
  return $p['exp'] - $p['iat'];
};
$d = $tok_exp(function($c) { unset($c['exp']); return $c; });
if ( ($d === false) || ($d < 290) || ($d > 310) ) { echo "    auth/token without exp: lifetime " . var_export($d, true) . " s, expected 300\n"; $cases[] = array("auth/token lifetime without exp", 0, 200); }
$d = $tok_exp(function($c) { $c['exp'] = time() + 2 * 86400; return $c; });
if ( ($d === false) || ($d > 12 * 3600 + 10) ) { echo "    auth/token exp +2 days: lifetime " . var_export($d, true) . " s, expected <= 12 h\n"; $cases[] = array("auth/token lifetime cap", 0, 200); }
$authreq = false;
if ( extauth_request_direct($cfg_domain, "keymgmt:list", $authreq) != 200 ) goto print_and_exit;
$t = false;
if ( extauth_token_direct($cfg_domain, $app, $authreq['jti'], $authreq['scope'][$app['pid']], $t, 2 * 86400) != 200 ) { echo "    ext/token exp +2 days refused\n"; goto print_and_exit; }
$p = extauth_payload($t);
if ( $p['exp'] > time() + 12 * 3600 + 10 ) { echo "    ext/token exp +2 days: token exp " . ($p['exp'] - time()) . " s ahead, expected <= 12 h\n"; $cases[] = array("ext/token lifetime cap", 0, 200); }
$authreq = false;
if ( extauth_request_direct($cfg_domain, "keymgmt:list", $authreq) != 200 ) goto print_and_exit;
$m = extauth_session_key($app['aid_prv'], $app['eid'], $authreq['jti']);
$t = false;
$cases[] = array("ext/token, reply scope system:reboot (not a token scope)", extauth_token_direct($cfg_domain, $app, $authreq['jti'], extauth_seal("system:reboot", $m), $t), 406);
// c) DEV-519 (M10): a nonce is consumed only by a request of a known issuer - a JWT with the same jti signed by another key is
//    refused and the jti stays usable (before: the foreign JWT consumed it and the real one got 401)
$ret_val = false;
if ( http_transaction("http", "GET", $cfg_domain, "/api/auth/token", $ret_val) != 200 ) goto print_and_exit;
$chal = $ret_val;
$secret = hash_pbkdf2("sha256", $cfg_passpharse, $chal['eid'], 600000, 32, true);
$foreign = random_bytes(32);
$iat = time() - 5;
$claims = array('jti' => $chal['jti'], 'aud' => $chal['spk'], 'exp' => $iat + 600, 'iat' => $iat, 'scope' => "keymgmt:list");
$ret_val = false;
$cases[] = array("auth/token, jti signed by another key", http_transaction("http", "POST", $cfg_domain, "/api/auth/token", $ret_val,
                 json_encode(array('auth' => ejwt_generate($claims + array('iss' => base64_encode(sodium_crypto_box_publickey_from_secretkey($foreign))), $foreign, base64_decode($chal['spk']))))), 401);
$ret_val = false;
$cases[] = array("auth/token, the same jti by the user", http_transaction("http", "POST", $cfg_domain, "/api/auth/token", $ret_val,
                 json_encode(array('auth' => ejwt_generate($claims + array('iss' => base64_encode(sodium_crypto_box_publickey_from_secretkey($secret))), $secret, base64_decode($chal['spk']))))), 200);
$authreq = false;
if ( extauth_request_direct($cfg_domain, "keymgmt:list", $authreq) != 200 ) goto print_and_exit;
$other = extauth_new_app();                                   // not paired: same pid and eid, its own key
$other['eid'] = $app['eid'];
$other['pid'] = $app['pid'];
$t = false;
$cases[] = array("ext/token, authreply signed by another key", extauth_token_direct($cfg_domain, $other, $authreq['jti'], $authreq['scope'][$app['pid']], $t), 406);
$cases[] = array("ext/token, the same jti by the paired app", extauth_token_direct($cfg_domain, $app, $authreq['jti'], $authreq['scope'][$app['pid']], $t), 200);
// d) DEV-519: keymgmt/update changes each field on its own - absent = kept, descr "" = removed, descr null and a request with neither
//    field = 400 (before: label required, an absent / empty / null descr removed the description); a pairing record: its label can
//    change and the pairing stays, its descr cannot (409) - before, an update with a label only removed the descr, i.e. the pairing
$token_get = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:get");
if ($token_get == false) goto print_and_exit;
$key_info = function($k) use ($cfg_domain, $token_get) {   // label and descr (decoded) of a key, false on error
  $ret_val = false;
  $not_used = false;
  if ( http_transaction("https", "GET", $cfg_domain, "/api/keymgmt/get/$k", $ret_val, $not_used, $token_get) != 200 ) return false;
  return array('label' => $ret_val['label'], 'descr' => isset($ret_val['descr']) ? (string)base64_decode((string)$ret_val['descr']) : "");
};
$upd = function($body) use ($cfg_domain, $token_upd) {
  $ret_val = false;
  return http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/update", $ret_val, json_encode($body), $token_upd);
};
$cases[] = array("keymgmt/update, label only", $upd(array('kid' => $kid_ecdh, 'label' => "T-15.21 L $run")), 200);
$i = $key_info($kid_ecdh);
if ( $i !== array('label' => "T-15.21 L $run", 'descr' => "CCTEST:T-15.21") ) { echo "    after label only: " . json_encode($i) . "\n"; $cases[] = array("label only keeps descr", 0, 200); }
$cases[] = array("keymgmt/update, descr only", $upd(array('kid' => $kid_ecdh, 'descr' => base64_encode("CCTEST:T-15.21 D"))), 200);
$i = $key_info($kid_ecdh);
if ( $i !== array('label' => "T-15.21 L $run", 'descr' => "CCTEST:T-15.21 D") ) { echo "    after descr only: " . json_encode($i) . "\n"; $cases[] = array("descr only keeps label", 0, 200); }
$cases[] = array("keymgmt/update, descr \"\" (removes it)", $upd(array('kid' => $kid_ecdh, 'descr' => "")), 200);
$i = $key_info($kid_ecdh);
if ( $i !== array('label' => "T-15.21 L $run", 'descr' => "") ) { echo "    after descr \"\": " . json_encode($i) . "\n"; $cases[] = array("descr \"\" removes it", 0, 200); }
$cases[] = array("keymgmt/update, descr null", $upd(array('kid' => $kid_ecdh, 'descr' => null)), 400);
$cases[] = array("keymgmt/update, neither label nor descr", $upd(array('kid' => $kid_ecdh)), 400);
$cases[] = array("keymgmt/update, label \"\"", $upd(array('kid' => $kid_ecdh, 'label' => "")), 400);
$cases[] = array("keymgmt/update of a pairing record, label only", $upd(array('kid' => $kid_pair, 'label' => "T-15.21 relabel $run")), 200);
$authreq = false;
if ( extauth_request_direct($cfg_domain, "keymgmt:list", $authreq) != 200 ) goto print_and_exit;
$t = false;
$cases[] = array("ext/token after the pairing was relabelled", isset($authreq['scope'][$app['pid']]) ? extauth_token_direct($cfg_domain, $app, $authreq['jti'], $authreq['scope'][$app['pid']], $t) : 0, 200);
$cases[] = array("keymgmt/update of a pairing record, descr", $upd(array('kid' => $kid_pair, 'descr' => base64_encode("CCTEST:T-15.21"))), 409);
$cases[] = array("keymgmt/update of a pairing record, descr \"\"", $upd(array('kid' => $kid_pair, 'descr' => "")), 409);
// e) clean up: the keys made here and the pairing
foreach ($made as $k) {
  $ret_val = false;
  $not_used = false;
  http_transaction("https", "DELETE", $cfg_domain, "/api/keymgmt/delete/$k", $ret_val, $not_used, $token_del);
}
if ( !check_cases($cases) ) goto print_and_exit;
if ( !check_alive($uptime) ) goto print_and_exit;
// f) set result
$test_cfg['subtests'][21] = 'OK';                             // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////
// Subtest: 22       ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST22:
echo "  subtest-22
";
$test_cfg['subtests'][22] = 'ERROR';                          // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) DEV-519 (L1): a stored AES key is used only at its own size - a shorter alg (AES128 / AES192 with an AES256 key) was a key cut
//    from the stored one (encrypt, decrypt, wrap, unwrap); now 400
$token_gen = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:gen");
$token_del = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:del");
if ( ($token_gen == false) || ($token_del == false) ) goto print_and_exit;
$ret_val = false;
$post_data = json_encode( array('label' => "T-15.22 AES256 " . bin2hex(random_bytes(3)), 'type' => "AES256", 'descr' => base64_encode("CCTEST:T-15.22")) );
if ( http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/create", $ret_val, $post_data, $token_gen) != 200 ) goto print_and_exit;
$kid_aes = $ret_val['kid'];
$token_aes = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid_aes");
if ($token_aes == false) goto print_and_exit;
$msg = base64_encode(random_bytes(32));
$cases = array();
foreach (array("AES256-CBC" => 200, "AES128-CBC" => 400, "AES192-CBC" => 400) as $alg => $exp) {
  $ret_val = false;
  $cases[] = array("cipher/encrypt AES256 key, alg $alg", http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/encrypt", $ret_val, json_encode(array('kid' => $kid_aes, 'msg' => $msg, 'alg' => $alg)), $token_aes), $exp);
}
$ret_val = false;
$cases[] = array("cipher/wrap AES256 key, alg AES256", http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/wrap", $ret_val, json_encode(array('kid' => $kid_aes, 'msg' => $msg, 'alg' => "AES256")), $token_aes), 200);
$ret_val = false;
$cases[] = array("cipher/wrap AES256 key, alg AES128", http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/wrap", $ret_val, json_encode(array('kid' => $kid_aes, 'msg' => $msg, 'alg' => "AES128")), $token_aes), 400);
$ret_val = false;
$not_used = false;
http_transaction("https", "DELETE", $cfg_domain, "/api/keymgmt/delete/$kid_aes", $ret_val, $not_used, $token_del);
// b) DEV-519 (L13): an upload refused with 406 because its body did not all arrive closes the connection - the rest of the body,
//    sent later, was read as the next request on a kept-alive connection
$token_upg = helper_authorize($cfg_domain, $cfg_passpharse, "system:upgrade");
if ($token_upg == false) goto print_and_exit;
$sock = raw_https_connect($cfg_domain);
if ($sock == false) goto print_and_exit;
$part = random_bytes(1024);
$hdrs = false;
$st = raw_https_transaction($sock, "POST /api/system/upgrade/upload_fw HTTP/1.1\r\nHost: $cfg_domain\r\nAuthorization: Bearer $token_upg\r\nContent-Disposition: attachment; filename=\"firmware.bin\"\r\nContent-Length: 4096\r\nConnection: keep-alive\r\n\r\n" . $part, $hdrs);
$cases[] = array("upload_fw, 1 KB of 4 KB then silence", $st, 406);
$hdrs = false;
$st2 = raw_https_transaction($sock, "GET /api/system/status HTTP/1.1\r\nHost: $cfg_domain\r\nConnection: close\r\n\r\n", $hdrs);
$cases[] = array("the same connection: rest of the body sent as a request (closed = 0)", ($st2 === false) ? 0 : $st2, 0);
fclose($sock);
if ( !check_cases($cases) ) goto print_and_exit;
if ( !check_alive($uptime) ) goto print_and_exit;
// c) set result
$test_cfg['subtests'][22] = 'OK';                             // mark this subtest as OK
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
