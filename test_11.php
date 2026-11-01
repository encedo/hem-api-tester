<?php

include "libs/lib.php";
include "config.php";


// test name, descr & number of subtests
$test_name = "T-11";
$test_descr = "Cryptography functionality";
$test_subtest_cnt = 12;


function t11_ossl($args) {                  // OpenSSL CLI (>= 3.5); returns true on exit code 0 - as t13_ossl (T-13)
  $bin = getenv("ENCEDO_OPENSSL") ? getenv("ENCEDO_OPENSSL") : "openssl";
  $cmd = escapeshellarg($bin);
  foreach ($args as $a) $cmd .= " " . escapeshellarg($a);
  exec($cmd . " 2>&1", $out, $rc);
  return ($rc == 0);
}

function t11_shake256_64($data) {           // DEV-481 (B3): SHAKE256 with 64 B output (OpenSSL CLI); false on error
  $in = tempnam(sys_get_temp_dir(), "t11");
  $out = tempnam(sys_get_temp_dir(), "t11");
  file_put_contents($in, $data);
  $ok = t11_ossl(array("dgst", "-shake256", "-xoflen", "64", "-binary", "-out", $out, $in));
  $ret = $ok ? file_get_contents($out) : false;
  @unlink($in);
  @unlink($out);
  return ($ret !== false) && (strlen($ret) == 64) ? $ret : false;
}

function t11_hotp($key, $counter, $digits = 6) {   // DEV-481 (B6): HOTP RFC 4226 (HMAC-SHA1, dynamic truncation)
  $h = hash_hmac('sha1', pack('J', $counter), $key, true);
  $o = ord($h[19]) & 0x0f;
  $bin = ((ord($h[$o]) & 0x7f) << 24) | (ord($h[$o + 1]) << 16) | (ord($h[$o + 2]) << 8) | ord($h[$o + 3]);
  return str_pad((string)($bin % (10 ** $digits)), $digits, "0", STR_PAD_LEFT);
}

function t11_p256_pem($point) {             // DEV-481 (B6): compressed P-256 point -> SubjectPublicKeyInfo PEM
  $bit = "\x03" . chr(strlen($point) + 1) . "\x00" . $point;
  $alg = "\x30\x13" . hex2bin("06072a8648ce3d0201") . hex2bin("06082a8648ce3d030107");
  $der = "\x30" . chr(strlen($alg) + strlen($bit)) . $alg . $bit;
  return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
}

function t11_xwing($ss_m, $ss_x, $ct_x, $pk_x) {   // DEV-482: X-Wing combiner SHA3-256(ss_M || ss_X || ct_X || pk_X || "\.//^\")
  return hash('sha3-256', $ss_m . $ss_x . $ct_x . $pk_x . "\x5c\x2e\x2f\x2f\x5e\x5c", true);
}

function t11_mlkem768_der($pk) {            // DEV-482: raw ML-KEM-768 public key (1184 B) -> SubjectPublicKeyInfo DER (OID 2.16.840.1.101.3.4.4.2)
  return hex2bin("308204b2300b0609608648016503040402038204a100") . $pk;
}

function t11_ecdsa_local_ok($sign_b64, $msg, $algo, $pub_pem, $sig_len) {   // DEV-484: HEM ECDSA signature is r || s of the expected length and verifies in OpenSSL
  $sig = base64_decode($sign_b64);
  return (strlen($sig) == $sig_len) && (openssl_verify($msg, ecdsa_rs2der($sig), $pub_pem, $algo) === 1);
}


// initialize the execution env
init_env();
$test_cfg = init_test($test_name, $test_descr, $test_subtest_cnt, $cfg_tester);
if ( $cfg_debug ) var_dump( $cfg_domain );
$test_cfg['elapsed'] = hrtime(true);

echo "Processing...\n";


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
if ( intval($ret_val['fls_state']) !== 0) {
  echo "ERROR: fls_state !=0, is " . $ret_val['fls_state'] . "\r\n";
  goto print_and_exit;     // exit as well if prereq not fulfill
}
if ( isset($ret_val['hostname']) ) {                       // remap domain name to the correct one
  $cfg_domain = $ret_val['hostname'];
}
// b) detect, get version details etc
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/version", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
$test_cfg['hwv'] = $ret_val['hwv'];                         //   or follow on with processing
$test_cfg['blv'] = @$ret_val['blv'];
$test_cfg['fwv'] = $ret_val['fwv'];
$test_cfg['conf'] = "ENCEDO PPA";
if ( strstr($ret_val['hwv'], "EPA") ) $test_cfg['conf'] = "ENCEDO EPA";
$diag_mode = strstr($test_cfg['fwv'], "-DIAG");
// c) set RTC clock - code from T-1.3
$ret = helper_checkin($cfg_domain);
if ($ret == false) goto print_and_exit;                     // exit on error
// d) generate keychain search over pattern keys for HMAC operations
$pattern_plain = "CCTEST:T-10.1_SHA";
$pattern = "^".base64_encode($pattern_plain);  //^ denotes 'begining by following bytes' - like regexpr :)
$offset = 0;
$keychain = array();
do {
  $ret_val = false;
  $post_array = array('descr' => $pattern, 'offset' => $offset );  //^ denotes 'begining by following bytes' - like regexpr :)
  $post_data = json_encode( $post_array );
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/search", $ret_val, $post_data);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //200 if found, 404 if not
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  if ($listed == 0) break;  // go all the keys
  foreach($ret_val['list'] as $item) $keychain[] = $item;
  $offset = $offset + $listed;
  if ($offset >= $total) break;
} while (true);
// e) ranodm message to perform test on
$msg_raw = base64_encode( openssl_random_pseudo_bytes( 250 ) );    // ranodm bytes of data
$keys_to_test = $ret_val['list'];
// f) iterate over found keys to call HMAC sign & verify
$counter = 0;
foreach($keychain as $item) {
  $kid = $item['kid'];
  // gen access token for that KID
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid");   // more here https://docs.encedo.com/hem-api/reference/api-reference/cryptography-operations/hmac#required-access-scope
  if ($token == false) goto print_and_exit;                    // exit on error
  // gen mac
  $ret_val = false;
  $oper_arg = array('kid' => $kid, 'msg' => $msg_raw);
  $post_data = json_encode( $oper_arg );
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/hash", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - HMAC hash generated
  $mac = $ret_val['mac'];
  //set two variables used in Subtest 6 and Subtest 7
  if (!isset($kid_subtest6a)) {
    $kid_subtest6a = $kid;
  } else {
    if (!isset($kid_subtest6b)) {
      $kid_subtest6b = $kid;
    }
  }
  // verify mac
  $ret_val = false;
  $oper_arg = array('kid' => $kid, 'msg' => $msg_raw, 'mac' => $mac);
  $post_data = json_encode( $oper_arg );
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/verify", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( ($ret_stat != 200) || (@$ret_val['verified'] !== true) ) goto print_and_exit;        // expected is 200 - HMAC verify success
  $counter++;
}
// g) if above loop ends and no 'goto' calls, all HMAC tests passed!
//echo "    Executed $counter tests over ". count($keys_to_test) . " keys\n";
if ($counter != count($keychain)) goto print_and_exit;
// h) set result
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
// a) generate keychain search over pattern keys for ExDSA operations - NIST curves
$pattern_plain = "CCTEST:T-10.1_SECP";
$pattern = "^".base64_encode($pattern_plain);  //^ denotes 'begining by following bytes' - like regexpr :)
$offset = 0;
$keychain = array();
do {
  $ret_val = false;
  $post_array = array('descr' => $pattern, 'offset' => $offset );  //^ denotes 'begining by following bytes' - like regexpr :)
  $post_data = json_encode( $post_array );
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/search", $ret_val, $post_data);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //200 if found, 404 if not
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  if ($listed == 0) break;  // go all the keys
  foreach($ret_val['list'] as $item) $keychain[] = $item;
  $offset = $offset + $listed;
  if ($offset >= $total) break;   //?
} while (true);
// b) add ED255 and ED448 keys
$pattern_plain = "CCTEST:T-10.1_ED";
$pattern = "^".base64_encode($pattern_plain);  //^ denotes 'begining by following bytes' - like regexpr :)
$offset = 0;
do {
  $ret_val = false;
  $post_array = array('descr' => $pattern, 'offset' => $offset );  //^ denotes 'begining by following bytes' - like regexpr :)
  $post_data = json_encode( $post_array );
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/search", $ret_val, $post_data);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //200 if found, 404 if not
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  if ($listed == 0) break;  // go all the keys
  foreach($ret_val['list'] as $item) $keychain[] = $item;
  $offset = $offset + $listed;
  if ($offset >= $total) break;   //?
} while (true);
$keys_to_test = $keychain;
$msg_raw = base64_encode( openssl_random_pseudo_bytes( 32 ) );    // random
// DEV-484: local OpenSSL cross-check of every ECDSA signature: SubjectPublicKeyInfo DER prefix of a compressed SEC1 point, coordinate size
$t11_ec = array(
  "SECP256R1" => array("3039301306072a8648ce3d020106082a8648ce3d030107032200", 32),
  "SECP384R1" => array("3046301006072a8648ce3d020106052b81040022033200", 48),
  "SECP521R1" => array("3058301006072a8648ce3d020106052b81040023034400", 66),
  "SECP256K1" => array("3036301006072a8648ce3d020106052b8104000a032200", 32),
);
$token_keyget = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:get");
if ($token_keyget == false) goto print_and_exit;
// f) iterate over found keys to call ExDSA sign & verify
$counter = 0;
foreach($keys_to_test as $item) {
  $kid = $item['kid'];
  $is_ecdh = strstr($item['type'], "ECDH") ? true : false;
  $is_exdsa = strstr($item['type'], "ExDSA") ? true : false;
  $is_pkey = strstr($item['type'], "PKEY") ? true : false;
  $type = false;
  $item_type = explode(",",  $item['type']);
  if ($item_type == false) goto print_and_exit; // wtf? this is odd
  $type = $item_type[ count($item_type) - 1];
  //echo "    Process key type: $type over ECDH:$is_ecdh and ExDSA:$is_exdsa, PKEY:$is_pkey\n";
   if ($is_pkey != true) continue; // process only keys with private key
  // gen access token for that KID
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid");   // more here https://docs.encedo.com/hem-api/reference/api-reference/cryptography-operations/hmac#required-access-scope
  if ($token == false) goto print_and_exit;                    // exit on error
  // process key by type
  if ($type == "ED25519") {
    //Ed25519 - EdDSA
    $oper_arg = array('kid' => $kid, 'msg' => $msg_raw, 'alg' => "Ed25519");
    $post_data = json_encode( $oper_arg );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/sign", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - ExDSA signature generated
    $oper_arg['sign'] = $ret_val['sign'];
    $post_data = json_encode( $oper_arg );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/verify", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( ($ret_stat != 200) || (@$ret_val['verified'] !== true) ) goto print_and_exit;        // expected is 200 - ExDSA signature verified
    //Ed25519ph - EdDSA
    $context = base64_encode( openssl_random_pseudo_bytes( 32 ) );    // random context
    $oper_arg = array('kid' => $kid, 'msg' => $msg_raw, 'alg' => "Ed25519ph", 'ctx' => $context);
    $post_data = json_encode( $oper_arg );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/sign", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - ExDSA signature generated
    $oper_arg['sign'] = $ret_val['sign'];
    $post_data = json_encode( $oper_arg );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/verify", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( ($ret_stat != 200) || (@$ret_val['verified'] !== true) ) goto print_and_exit;        // expected is 200 - ExDSA signature verified
    //Ed25519ctx - EdDSA
    $oper_arg = array('kid' => $kid, 'msg' => $msg_raw, 'alg' => "Ed25519ctx", 'ctx' => $context);
    $post_data = json_encode( $oper_arg );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/sign", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - ExDSA signature generated
    $oper_arg['sign'] = $ret_val['sign'];
    $post_data = json_encode( $oper_arg );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/verify", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( ($ret_stat != 200) || (@$ret_val['verified'] !== true) ) goto print_and_exit;        // expected is 200 - ExDSA signature verified
    $counter++;
  } else
  if ($type == "ED448") {
    //Ed448 - EdDSA
    $context = base64_encode( openssl_random_pseudo_bytes( 32 ) );    // random context
    $oper_arg = array('kid' => $kid, 'msg' => $msg_raw, 'alg' => "Ed448", 'ctx' => $context);
    $post_data = json_encode( $oper_arg );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/sign", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - ExDSA signature generated
    $oper_arg['sign'] = $ret_val['sign'];
    $post_data = json_encode( $oper_arg );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/verify", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( ($ret_stat != 200) || (@$ret_val['verified'] !== true) ) goto print_and_exit;        // expected is 200 - ExDSA signature verified
    //Ed448ph - EdDSA
    $context = base64_encode( openssl_random_pseudo_bytes( 32 ) );    // random context
    $oper_arg = array('kid' => $kid, 'msg' => $msg_raw, 'alg' => "Ed448ph", 'ctx' => $context);
    $post_data = json_encode( $oper_arg );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/sign", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - ExDSA signature generated
    $oper_arg['sign'] = $ret_val['sign'];
    $post_data = json_encode( $oper_arg );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/verify", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( ($ret_stat != 200) || (@$ret_val['verified'] !== true) ) goto print_and_exit;        // expected is 200 - ExDSA signature verified
    $counter++;
  } else {
    // DEV-484: public key of the key pair for the local check
    $ret_val = false;
    $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/keymgmt/get/$kid", $ret_val, $dummy_val, $token_keyget);
    if ( ($ret_stat != 200) || !isset($ret_val['pubkey']) || !isset($t11_ec[$type]) ) { echo "ERROR: keymgmt/get $type: HTTP $ret_stat\n"; goto print_and_exit; }
    $pub_pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode(hex2bin($t11_ec[$type][0]) . base64_decode($ret_val['pubkey'])), 64, "\n") . "-----END PUBLIC KEY-----\n";
    $sig_len = 2 * $t11_ec[$type][1];
    //SHA256WithECDSA  - ECDSA
    $oper_arg = array('kid' => $kid, 'msg' => $msg_raw, 'alg' => "SHA256WithECDSA");
    $post_data = json_encode( $oper_arg );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/sign", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - ExDSA signature generated
    $oper_arg['sign'] = $ret_val['sign'];
    $post_data = json_encode( $oper_arg );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/verify", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( ($ret_stat != 200) || (@$ret_val['verified'] !== true) ) goto print_and_exit;        // expected is 200 - ExDSA signature verified
    if ( !t11_ecdsa_local_ok($oper_arg['sign'], base64_decode($msg_raw), OPENSSL_ALGO_SHA256, $pub_pem, $sig_len) ) { echo "ERROR: SHA256WithECDSA ($type): not r || s or no local OpenSSL verify\n"; goto print_and_exit; }   // DEV-484
    //SHA384WithECDSA  - ECDSA
    $oper_arg = array('kid' => $kid, 'msg' => $msg_raw, 'alg' => "SHA384WithECDSA");
    $post_data = json_encode( $oper_arg );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/sign", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - ExDSA signature generated
    $oper_arg['sign'] = $ret_val['sign'];
    $post_data = json_encode( $oper_arg );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/verify", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( ($ret_stat != 200) || (@$ret_val['verified'] !== true) ) goto print_and_exit;        // expected is 200 - ExDSA signature verified
    if ( !t11_ecdsa_local_ok($oper_arg['sign'], base64_decode($msg_raw), OPENSSL_ALGO_SHA384, $pub_pem, $sig_len) ) { echo "ERROR: SHA384WithECDSA ($type): not r || s or no local OpenSSL verify\n"; goto print_and_exit; }   // DEV-484
    //SHA512WithECDSA  - ECDSA
    $oper_arg = array('kid' => $kid, 'msg' => $msg_raw, 'alg' => "SHA512WithECDSA");
    $post_data = json_encode( $oper_arg );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/sign", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - ExDSA signature generated
    $oper_arg['sign'] = $ret_val['sign'];
    $post_data = json_encode( $oper_arg );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/verify", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( ($ret_stat != 200) || (@$ret_val['verified'] !== true) ) goto print_and_exit;        // expected is 200 - ExDSA signature verified
    if ( !t11_ecdsa_local_ok($oper_arg['sign'], base64_decode($msg_raw), OPENSSL_ALGO_SHA512, $pub_pem, $sig_len) ) { echo "ERROR: SHA512WithECDSA ($type): not r || s or no local OpenSSL verify\n"; goto print_and_exit; }   // DEV-484
    // DEV-481 (A6): det:true - RFC 6979, the same signature twice and still valid; det not a bool -> 400
    $oper_arg = array('kid' => $kid, 'msg' => $msg_raw, 'alg' => "SHA256WithECDSA", 'det' => true);
    $post_data = json_encode( $oper_arg );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/sign", $ret_val, $post_data, $token);
    if ( $ret_stat != 200 ) goto print_and_exit;
    $sign_det = $ret_val['sign'];
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/sign", $ret_val, $post_data, $token);
    if ( ($ret_stat != 200) || ($ret_val['sign'] !== $sign_det) ) { echo "ERROR: det:true signatures differ ($type)\n"; goto print_and_exit; }
    unset($oper_arg['det']);
    $oper_arg['sign'] = $sign_det;
    $post_data = json_encode( $oper_arg );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/verify", $ret_val, $post_data, $token);
    if ( ($ret_stat != 200) || (@$ret_val['verified'] !== true) ) goto print_and_exit;
    if ( !t11_ecdsa_local_ok($sign_det, base64_decode($msg_raw), OPENSSL_ALGO_SHA256, $pub_pem, $sig_len) ) { echo "ERROR: det:true SHA256WithECDSA ($type): not r || s or no local OpenSSL verify\n"; goto print_and_exit; }   // DEV-484
    $post_data = json_encode( array('kid' => $kid, 'msg' => $msg_raw, 'alg' => "SHA256WithECDSA", 'det' => "yes") );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/sign", $ret_val, $post_data, $token);
    if ( $ret_stat != 400 ) { echo "ERROR: det \"yes\": HTTP $ret_stat (400 expected)\n"; goto print_and_exit; }
    // DEV-481 (B1): alg ECDSA - msg is a digest made here; the signature verifies as SHA256WithECDSA over the data; a 19 B digest -> 400
    $post_data = json_encode( array('kid' => $kid, 'msg' => base64_encode(hash('sha256', base64_decode($msg_raw), true)), 'alg' => "ECDSA") );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/sign", $ret_val, $post_data, $token);
    if ( $ret_stat != 200 ) goto print_and_exit;
    $sign_ph = $ret_val['sign'];
    $post_data = json_encode( array('kid' => $kid, 'msg' => $msg_raw, 'alg' => "SHA256WithECDSA", 'sign' => $sign_ph) );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/verify", $ret_val, $post_data, $token);
    if ( ($ret_stat != 200) || (@$ret_val['verified'] !== true) ) { echo "ERROR: ECDSA prehash signature does not verify as SHA256WithECDSA ($type)\n"; goto print_and_exit; }
    if ( !t11_ecdsa_local_ok($sign_ph, base64_decode($msg_raw), OPENSSL_ALGO_SHA256, $pub_pem, $sig_len) ) { echo "ERROR: ECDSA prehash ($type): not r || s or no local OpenSSL verify\n"; goto print_and_exit; }   // DEV-484
    $post_data = json_encode( array('kid' => $kid, 'msg' => base64_encode(openssl_random_pseudo_bytes(19)), 'alg' => "ECDSA") );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/sign", $ret_val, $post_data, $token);
    if ( $ret_stat != 400 ) { echo "ERROR: ECDSA 19 B digest: HTTP $ret_stat (400 expected)\n"; goto print_and_exit; }
    $counter++;
  }
}
// g) if above loop ends and no 'goto' calls, all HMAC tests passed!
//echo "    Executed $counter tests over ". count($keys_to_test) . " keys\n";
if ($counter != count($keys_to_test)) goto print_and_exit;
// h) set result
$test_cfg['subtests'][2] = 'OK';                           // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 3        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST3:
echo "  subtest-3\n";
$test_cfg['subtests'][3] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) generate keychain search over pattern keys for AES operations
$pattern_plain = "CCTEST:T-10.1_AES";
$pattern = "^".base64_encode($pattern_plain);  //^ denotes 'begining by following bytes' - like regexpr :)
$offset = 0;
$keychain = array();
do {
  $ret_val = false;
  $post_array = array('descr' => $pattern, 'offset' => $offset );  //^ denotes 'begining by following bytes' - like regexpr :)
  $post_data = json_encode( $post_array );
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/search", $ret_val, $post_data);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //200 if found, 404 if not
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  if ($listed == 0) break;  // go all the keys
  foreach($ret_val['list'] as $item) $keychain[] = $item;
  $offset = $offset + $listed;
  if ($offset >= $total) break;   //?
} while (true);
// b) iterate over found keys
$counter = 0;
foreach($keychain as $item) {
  $kid = $item['kid'];
  $type = false;
  //parse keytype
  $item_type = explode(",",  $item['type']);
  if ($item_type == false) goto print_and_exit; // wtf? this is odd
  $type = $item_type[ count($item_type) - 1];
  //echo "    Process key type: $type   KID: $kid\n";
  // gen access token for that KID
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid");   // more here https://docs.encedo.com/hem-api/reference/api-reference/cryptography-operations/encryption/encryption-decryption#required-access-scope
  if ($token == false) goto print_and_exit;                    // exit on error
  // DEV-481 (B7): AES-ECB is off in the build (CRYPTO_AES_ECB 0) - encrypt and decrypt "-ECB" -> 400
  $msg = base64_encode( openssl_random_pseudo_bytes( 64 ) );
  $alg = "$type-ECB";
  foreach (array("encrypt", "decrypt") as $op) {
    $post_data = json_encode( array('kid' => $kid, 'msg' => $msg, 'alg' => $alg) );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/$op", $ret_val, $post_data, $token);
    if ( $ret_stat != 400 ) { echo "ERROR: $op $alg: HTTP $ret_stat (400 expected)\n"; goto print_and_exit; }
  }
  //AES in CBC mode
  //encrypt example message
  $msg = base64_encode( openssl_random_pseudo_bytes( 100 ) ); //CBC can handle any message size - padding
  $alg = "$type-CBC";
  $post_array = array('kid' => $kid, 'msg' => $msg, 'alg' => $alg);
  $post_data = json_encode( $post_array );
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/encrypt", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $ciphertext = $ret_val['ciphertext'];
  $iv = $ret_val['iv'];
  //try to decrypt the message
  $post_array['msg'] = $ciphertext;
  $post_array['iv'] = $iv;
  $post_data = json_encode( $post_array );
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/decrypt", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $msg_test = $ret_val['plaintext'];
  //compare
  if ($msg != $msg_test) goto print_and_exit;    //expected is 200 on success
  // DEV-481 (A7): CBC padding checked in full - the last ciphertext block cut off, the message end is read as padding
  foreach (array("\x05" => 406, "\x03\x03\x03" => 200) as $tail => $want) {
    $raw = substr(openssl_random_pseudo_bytes(96), 0, 96 - strlen($tail) - 4) . "\xAA\xAA\xAA\xAA" . $tail;
    $post_array = array('kid' => $kid, 'msg' => base64_encode($raw), 'alg' => $alg);
    $post_data = json_encode( $post_array );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/encrypt", $ret_val, $post_data, $token);
    if ( $ret_stat != 200 ) goto print_and_exit;
    $post_array['msg'] = base64_encode(substr(base64_decode($ret_val['ciphertext']), 0, 96));
    $post_array['iv'] = $ret_val['iv'];
    $post_data = json_encode( $post_array );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/decrypt", $ret_val, $post_data, $token);
    if ( $ret_stat != $want ) { echo "ERROR: CBC padding " . bin2hex($tail) . ": HTTP $ret_stat ($want expected)\n"; goto print_and_exit; }
    if ( ($want == 200) && (base64_decode($ret_val['plaintext']) !== substr($raw, 0, 93)) ) goto print_and_exit;
  }
  //AES in GCM mode
  //encrypt example message
  $msg = base64_encode( openssl_random_pseudo_bytes( 100 ) ); //GCM can handle any message size
  $alg = "$type-GCM";
  // DEV-481 (A5): aad over the limit (257 B) -> 400
  $post_array = array('kid' => $kid, 'msg' => $msg, 'alg' => $alg, 'aad' => base64_encode( openssl_random_pseudo_bytes( 257 ) ));
  $post_data = json_encode( $post_array );
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/encrypt", $ret_val, $post_data, $token);
  if ( $ret_stat != 400 ) { echo "ERROR: GCM aad 257 B: HTTP $ret_stat (400 expected)\n"; goto print_and_exit; }
  $aad = base64_encode( openssl_random_pseudo_bytes( 256 ) );   // DEV-481 (A5): max aad (was 32 B)
  $post_array = array('kid' => $kid, 'msg' => $msg, 'alg' => $alg, 'aad' => $aad);
  $post_data = json_encode( $post_array );
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/encrypt", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $ciphertext = $ret_val['ciphertext'];
  $iv = $ret_val['iv'];
  if (strlen(base64_decode($iv)) != 12) { echo "ERROR: GCM iv " . strlen(base64_decode($iv)) . " B (12 expected)\n"; goto print_and_exit; }   // DEV-481 (B2): 96-bit IV (SP 800-38D)
  $tag = $ret_val['tag'];
  //try to decrypt the message
  $post_array['msg'] = $ciphertext;
  $post_array['iv'] = $iv;
  $post_array['tag'] = $tag;
  $post_data = json_encode( $post_array );
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/decrypt", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $msg_test = $ret_val['plaintext'];
  //compare
  if ($msg != $msg_test) goto print_and_exit;    //expected is equal
  $counter++;
}
if ($counter != count($keychain)) goto print_and_exit;
// c) set result
$test_cfg['subtests'][3] = 'OK';                            // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 4        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST4:
echo "  subtest-4\n";
$test_cfg['subtests'][4] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) generate keychain search over pattern keys for AES operations
$pattern_plain = "CCTEST:T-10.1_AES";
$pattern = "^".base64_encode($pattern_plain);  //^ denotes 'begining by following bytes' - like regexpr :)
$offset = 0;
$keychain = array();
do {
  $ret_val = false;
  $post_array = array('descr' => $pattern, 'offset' => $offset );  //^ denotes 'begining by following bytes' - like regexpr :)
  $post_data = json_encode( $post_array );
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/search", $ret_val, $post_data);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //200 if found, 404 if not
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  if ($listed == 0) break;  // go all the keys
  foreach($ret_val['list'] as $item) $keychain[] = $item;
  $offset = $offset + $listed;
  if ($offset >= $total) break;   //?
} while (true);
// b) iterate over found keys
$counter = 0;
foreach($keychain as $item) {
  //var_dump($item);
  $kid = $item['kid'];
  $type = false;
  //parse keytype
  $item_type = explode(",",  $item['type']);
  if ($item_type == false) goto print_and_exit; // wtf? this is odd
  $type = $item_type[ count($item_type) - 1];
  //echo "    Process key type: $type   KID: $kid\n";
  // gen access token for that KID
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid");   // more here https://docs.encedo.com/hem-api/reference/api-reference/cryptography-operations/encryption/encryption-decryption#required-access-scope
  if ($token == false) goto print_and_exit;                    // exit on error
  //WRAP
  $msg = base64_encode( openssl_random_pseudo_bytes( 32 ) ); // example random message to wrap (KEK by NIST)
  $post_array = array('kid' => $kid, 'alg' => $type, 'msg' => $msg);
  $post_data = json_encode( $post_array );
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/wrap", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $wrapped = $ret_val['wrapped'];
  //UNWARP
  $post_array = array('kid' => $kid, 'alg' => $type, 'msg' => $wrapped);
  $post_data = json_encode( $post_array );
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/unwrap", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $msg_test = $ret_val['unwrapped'];
  //compare
  if ($msg != $msg_test) goto print_and_exit;    //expected is equal
  $counter++;
}
if ($counter != count($keychain)) goto print_and_exit;
// c) set result
$test_cfg['subtests'][4] = 'OK';                           // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 5        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST5:
echo "  subtest-5\n";
$test_cfg['subtests'][5] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) generate keychain search over pattern keys for ECDH operations - NIST curves
$pattern_plain = "CCTEST:T-10.1_SECP";
$pattern = "^".base64_encode($pattern_plain);  //^ denotes 'begining by following bytes' - like regexpr :)
$offset = 0;
$keychain = array();
do {
  $ret_val = false;
  $post_array = array('descr' => $pattern, 'offset' => $offset );  //^ denotes 'begining by following bytes' - like regexpr :)
  $post_data = json_encode( $post_array );
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/search", $ret_val, $post_data);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //200 if found, 404 if not
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  if ($listed == 0) break;  // go all the keys
  foreach($ret_val['list'] as $item) $keychain[] = $item;
  $offset = $offset + $listed;
  if ($offset >= $total) break;   //?
} while (true);
// b) add Curve255 and Curve448 keys
$pattern_plain = "CCTEST:T-10.1_CURVE";
$pattern = "^".base64_encode($pattern_plain);  //^ denotes 'begining by following bytes' - like regexpr :)
$offset = 0;
do {
  $ret_val = false;
  $post_array = array('descr' => $pattern, 'offset' => $offset );  //^ denotes 'begining by following bytes' - like regexpr :)
  $post_data = json_encode( $post_array );
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/search", $ret_val, $post_data);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //200 if found, 404 if not
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  if ($listed == 0) break;  // go all the keys
  foreach($ret_val['list'] as $item) $keychain[] = $item;
  $offset = $offset + $listed;
  if ($offset >= $total) break;   //?
} while (true);
$msg_raw = base64_encode( openssl_random_pseudo_bytes( 8 ) );    // ranodm
//below example public keys will be used to perform ECDH
$supported_key_types_ecdh = array(  "SECP256R1"  => "AyH/xovr5aRefadZgVL8+ydEwEa6dzgBXmvPxFv+/LIq",
                                    "SECP384R1"  => "AscrwMd9jmdQOdC4aMbcMqaTzx4xm3DUnVhotIieMG7JyWd+UADS0snfBegnwM2NJQ==",
                                    "SECP521R1"  => "AgGFg+WSt3MRDdu8JQRLrG2eTrm9yhiS7JKIwQfdyZl229qzaIxKigK0XVYUn1SNo5ZW8HltDEcre2wf86ZGKBYlfA==",
                                    "SECP256K1"  => "A5wQQqNR4mRCzgyykxp9D/I0968QHLBGEGONyIQVs0Qh",
                                    "CURVE25519" => "X7xUStEGknG4goyuP1VlgelMwYaau0I3SddDU3wQsmc=",
                                    "CURVE448"   => "A75QwnTMiUJd0T1TPsvZBpIUCmb79FWBMQyKuQkHwlsm5gNugOQwmZkb+EFekuL1fiHQNZN5X0I="
);
$supported_alg = array( "SHA2-256", "SHA2-384", "SHA2-512", "SHA3-256", "SHA3-384", "SHA3-512", "" ); // last is RAW - no hash, raw ECDH result
// c) iterate over found keys to call ECDH derive
$counter = 0;
foreach($keychain as $item) {
  $kid = $item['kid'];
  $is_ecdh = strstr($item['type'], "ECDH") ? true : false;
  $is_pkey = strstr($item['type'], "PKEY") ? true : false;
  $type = false;
  //parse keytype
  $item_type = explode(",",  $item['type']);
  if ($item_type == false) goto print_and_exit; // wtf? this is odd
  $type = $item_type[ count($item_type) - 1];
  //echo "    Process key type: $type over ECDH:$is_ecdh, PKEY:$is_pkey\n";
  if ($is_pkey != true) continue; // process only keys with private key
  // gen access token for that KID
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid");   // more here https://docs.encedo.com/hem-api/reference/api-reference/cryptography-operations/ecdh#required-access-scope
  if ($token == false) goto print_and_exit;                    // exit on error
  // get pubkey assosiatec by keytype and process through all possible algs supported https://docs.encedo.com/hem-api/reference/api-reference/cryptography-operations/ecdh
  $pubkey = $supported_key_types_ecdh[ $type ];
  foreach( $supported_alg  as $alg) {
    //echo "    alg: $alg  type: $type  pubkey: $pubkey\n";
    // kid & pubkey version
    $post_array = array('kid' => $kid, 'pubkey' => $pubkey );
    if ($alg != "") $post_array['alg'] = $alg;
    $post_data = json_encode( $post_array );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/ecdh", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
    // kid &ext_kid version
    $post_array = array('kid' => $kid, 'ext_kid' => $kid );
    if ($alg != "") $post_array['alg'] = $alg;
    $post_data = json_encode( $post_array );
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/ecdh", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
    //all good, got secret (ECDH result) hashed by ALG
    $counter++;
  }
  // DEV-427: ECDH with HKDF - result must equal HKDF over the raw ECDH secret (hkdf_salt, hkdf_ctx = HKDF info, hkdf_len)
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/ecdh", $ret_val, json_encode(array('kid' => $kid, 'pubkey' => $pubkey)), $token);
  if ( $ret_stat != 200 ) goto print_and_exit;                // raw ECDH secret
  $z = base64_decode($ret_val['ecdh']);
  $hkdf_salt = openssl_random_pseudo_bytes(16);
  $hkdf_ctx = openssl_random_pseudo_bytes(12);
  foreach (array("HKDF-SHA2-256" => "sha256", "HKDF-SHA2-384" => "sha384", "HKDF-SHA2-512" => "sha512") as $alg => $php_alg) {
    foreach (array(0, 16, 33, 128) as $hkdf_len) {             // 0: default length = digest size
      $post_array = array('kid' => $kid, 'pubkey' => $pubkey, 'alg' => $alg, 'hkdf_salt' => base64_encode($hkdf_salt), 'hkdf_ctx' => base64_encode($hkdf_ctx));
      if ($hkdf_len) $post_array['hkdf_len'] = $hkdf_len;
      $ret_val = false;
      $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/ecdh", $ret_val, json_encode($post_array), $token);
      if ( $ret_stat != 200 ) { echo "ERROR: ECDH $type $alg hkdf_len $hkdf_len: HTTP $ret_stat\n"; goto print_and_exit; }
      $expected = hash_hkdf($php_alg, $z, $hkdf_len ? $hkdf_len : 0, $hkdf_ctx, $hkdf_salt);
      if ( base64_decode($ret_val['ecdh']) !== $expected ) { echo "ERROR: ECDH $type $alg hkdf_len $hkdf_len: result differs from local HKDF\n"; goto print_and_exit; }
    }
  }
  // without salt and context
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/ecdh", $ret_val, json_encode(array('kid' => $kid, 'pubkey' => $pubkey, 'alg' => "HKDF-SHA2-256")), $token);
  if ( ($ret_stat != 200) || (base64_decode($ret_val['ecdh']) !== hash_hkdf('sha256', $z, 0, '', '')) ) { echo "ERROR: ECDH $type HKDF without salt/ctx\n"; goto print_and_exit; }
  // limits: hkdf_len 16..128, hkdf_salt and hkdf_ctx up to 128 B
  $limits = array( array('hkdf_len' => 15), array('hkdf_len' => 129),
                   array('hkdf_salt' => base64_encode(str_repeat("s", 129))), array('hkdf_ctx' => base64_encode(str_repeat("c", 129))) );
  foreach ($limits as $bad) {
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/ecdh", $ret_val, json_encode(array('kid' => $kid, 'pubkey' => $pubkey, 'alg' => "HKDF-SHA2-256") + $bad), $token);
    if ( $ret_stat != 400 ) { echo "ERROR: ECDH $type " . json_encode(array_keys($bad)) . " over the limit: HTTP $ret_stat (expected 400)\n"; goto print_and_exit; }
  }
  // reserved hkdf_ctx prefix (DEV-447): internal labels "encedo-..." -> 400; the prefix counts only at the start
  foreach (array("encedo-derive:v1:secp256r1" => 400, "encedo-wrap:v1:x" => 400, "encedo-" => 400, "encedo" => 200, "x-encedo-" => 200) as $ctx => $exp) {
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/ecdh", $ret_val, json_encode(array('kid' => $kid, 'pubkey' => $pubkey, 'alg' => "HKDF-SHA2-256", 'hkdf_ctx' => base64_encode($ctx))), $token);
    if ( $ret_stat != $exp ) { echo "ERROR: ECDH $type hkdf_ctx \"$ctx\": HTTP $ret_stat (expected $exp)\n"; goto print_and_exit; }
  }
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/ecdh", $ret_val, json_encode(array('kid' => $kid, 'pubkey' => $pubkey, 'alg' => "HKDF-SHA2-256", 'hkdf_salt' => base64_encode(str_repeat("s", 128)), 'hkdf_ctx' => base64_encode(str_repeat("c", 128)))), $token);
  if ( ($ret_stat != 200) || (base64_decode($ret_val['ecdh']) !== hash_hkdf('sha256', $z, 0, str_repeat("c", 128), str_repeat("s", 128))) ) { echo "ERROR: ECDH $type HKDF with 128 B salt/ctx\n"; goto print_and_exit; }
  // DEV-468: hkdf_args - one ECDH, up to 8 HKDF derivations; each equals the local HKDF, item 1 equals the single-set call
  $set = array();
  for ($i = 0; $i < 8; $i++) $set[] = array('hkdf_salt' => base64_encode("salt-$i-$type"), 'hkdf_ctx' => base64_encode("ctx-$i"), 'hkdf_len' => 16 + 8 * $i);
  $set[3] = new stdClass();                                  // all defaults: no salt, no ctx, 32 B
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/ecdh", $ret_val, json_encode(array('kid' => $kid, 'pubkey' => $pubkey, 'alg' => "HKDF-SHA2-256", 'hkdf_args' => $set)), $token);
  if ( ($ret_stat != 200) || !is_array(@$ret_val['hkdf']) || (count($ret_val['hkdf']) != 8) ) { echo "ERROR: ECDH $type hkdf_args: HTTP $ret_stat " . json_encode($ret_val) . "\n"; goto print_and_exit; }
  foreach ($set as $i => $a) {
    $a = (array)$a;
    $exp = hash_hkdf('sha256', $z, isset($a['hkdf_len']) ? $a['hkdf_len'] : 32, isset($a['hkdf_ctx']) ? base64_decode($a['hkdf_ctx']) : '', isset($a['hkdf_salt']) ? base64_decode($a['hkdf_salt']) : '');
    if ( base64_decode($ret_val['hkdf'][$i]) !== $exp ) { echo "ERROR: ECDH $type hkdf_args item $i differs from the local HKDF\n"; goto print_and_exit; }
  }
  $first = $ret_val['hkdf'][0];
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/ecdh", $ret_val, json_encode(array('kid' => $kid, 'pubkey' => $pubkey, 'alg' => "HKDF-SHA2-256") + $set[0]), $token);
  if ( ($ret_stat != 200) || ($ret_val['ecdh'] !== $first) ) { echo "ERROR: ECDH $type hkdf_args item 1 differs from the single-set call\n"; goto print_and_exit; }
  // errors (nothing derived): 9 items, empty, mixed with a single field, a bad item, no HKDF alg, not an array
  $bad = array(
    "9 items" => array('alg' => "HKDF-SHA2-256", 'hkdf_args' => array_merge($set, array(new stdClass()))),
    "empty" => array('alg' => "HKDF-SHA2-256", 'hkdf_args' => array()),
    "with hkdf_salt" => array('alg' => "HKDF-SHA2-256", 'hkdf_salt' => base64_encode("s"), 'hkdf_args' => array(new stdClass())),
    "with hkdf_len" => array('alg' => "HKDF-SHA2-256", 'hkdf_len' => 32, 'hkdf_args' => array(new stdClass())),
    "salt 129 B" => array('alg' => "HKDF-SHA2-256", 'hkdf_args' => array(array('hkdf_salt' => base64_encode(str_repeat("s", 129))))),
    "reserved ctx" => array('alg' => "HKDF-SHA2-256", 'hkdf_args' => array(new stdClass(), array('hkdf_ctx' => base64_encode("encedo-wrap:v1:")))),
    "len 15" => array('alg' => "HKDF-SHA2-256", 'hkdf_args' => array(array('hkdf_len' => 15))),
    "item not an object" => array('alg' => "HKDF-SHA2-256", 'hkdf_args' => array("x")),
    "alg SHA2-256" => array('alg' => "SHA2-256", 'hkdf_args' => array(new stdClass())),
    "not an array" => array('alg' => "HKDF-SHA2-256", 'hkdf_args' => new stdClass()),
  );
  foreach ($bad as $what => $extra) {
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/ecdh", $ret_val, json_encode(array('kid' => $kid, 'pubkey' => $pubkey) + $extra), $token);
    if ( $ret_stat != 400 ) { echo "ERROR: ECDH $type hkdf_args $what: HTTP $ret_stat (expected 400)\n"; goto print_and_exit; }
  }
  //additional tests - ECDH as a source of secrets for hmac,encryption&wrap
  //reuse code from subtest1,3&4
  //echo "HMAC - EXT_KID\n";
  $msg = base64_encode( openssl_random_pseudo_bytes( 64 ) );
  //hash
  $ret_val = false;
  $oper_arg = array('kid' => $kid, 'ext_kid' => $kid, 'msg' => $msg_raw, 'alg' => "SHA2-256");
  $post_data = json_encode( $oper_arg );
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/hash", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - HMAC hash generated
  $mac = $ret_val['mac'];
  // verify mac
  $ret_val = false;
  $oper_arg['mac'] = $mac;
  $post_data = json_encode( $oper_arg );
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/verify", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( ($ret_stat != 200) || (@$ret_val['verified'] !== true) ) goto print_and_exit;        // expected is 200 - HMAC verify success
  //echo "HMAC - PUBKEY\n";
  $msg = base64_encode( openssl_random_pseudo_bytes( 64 ) );
  //hash
  $ret_val = false;
  $oper_arg = array('kid' => $kid, 'pubkey' => $pubkey, 'msg' => $msg_raw, 'alg' => "SHA2-256");
  $post_data = json_encode( $oper_arg );
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/hash", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - HMAC hash generated
  $mac = $ret_val['mac'];
  // verify mac
  $ret_val = false;
  $oper_arg['mac'] = $mac;
  $post_data = json_encode( $oper_arg );
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/verify", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( ($ret_stat != 200) || (@$ret_val['verified'] !== true) ) goto print_and_exit;        // expected is 200 - HMAC verify success
  //echo "CIPHER - EXT_KID\n";
  $msg = base64_encode( openssl_random_pseudo_bytes( 100 ) ); //CBC can handle any message size - padding
  $alg = "AES128-CBC";
  $post_array = array('kid' => $kid, 'ext_kid' => $kid, 'msg' => $msg, 'alg' => $alg);
  $post_data = json_encode( $post_array );
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/encrypt", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $ciphertext = $ret_val['ciphertext'];
  $iv = $ret_val['iv'];
  //try to decrypt the message
  $post_array['msg'] = $ciphertext;
  $post_array['iv'] = $iv;
  $post_data = json_encode( $post_array );
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/decrypt", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $msg_test = $ret_val['plaintext'];
  //compare
  if ($msg != $msg_test) goto print_and_exit;    //expected is 200 on success
  //echo "CIPHER - PUBKEY\n";
  $msg = base64_encode( openssl_random_pseudo_bytes( 100 ) ); //CBC can handle any message size - padding
  $ctx = base64_encode( openssl_random_pseudo_bytes( 8 ) );
  $alg = "AES128-CBC";
  $post_array = array('kid' => $kid, 'pubkey' => $pubkey, 'msg' => $msg, 'alg' => $alg, 'ctx' => $ctx);
  $post_data = json_encode( $post_array );
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/encrypt", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $ciphertext = $ret_val['ciphertext'];
  $iv = $ret_val['iv'];
  //try to decrypt the message
  $post_array['msg'] = $ciphertext;
  $post_array['iv'] = $iv;
  $post_data = json_encode( $post_array );
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/decrypt", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $msg_test = $ret_val['plaintext'];
  //compare
  if ($msg != $msg_test) goto print_and_exit;    //expected is equal
  //echo "WRAP - EXT_KID\n";
  $msg = base64_encode( openssl_random_pseudo_bytes( 32 ) ); // example random message to wrap (KEK by NIST)
  $post_array = array('kid' => $kid, 'ext_kid' => $kid, 'alg' => "AES128", 'msg' => $msg);
  $post_data = json_encode( $post_array );
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/wrap", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $wrapped = $ret_val['wrapped'];
  //UNWARP
  $post_array['msg'] = $wrapped;
  $post_data = json_encode( $post_array );
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/unwrap", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $msg_test = $ret_val['unwrapped'];
  //compare
  if ($msg != $msg_test) goto print_and_exit;    //expected is equal
  //echo "WRAP - PUBKEY\n";
  $msg = base64_encode( openssl_random_pseudo_bytes( 32 ) ); // example random message to wrap (KEK by NIST)
  $ctx = base64_encode( openssl_random_pseudo_bytes( 8 ) );
  $post_array = array('kid' => $kid, 'pubkey' => $pubkey, 'alg' => "AES128", 'msg' => $msg, 'ctx' => $ctx);
  $post_data = json_encode( $post_array );
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/wrap", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $wrapped = $ret_val['wrapped'];
  //UNWARP
  $post_array['msg'] = $wrapped;
  $post_data = json_encode( $post_array );
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/unwrap", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $msg_test = $ret_val['unwrapped'];
  //compare
  if ($msg != $msg_test) goto print_and_exit;    //expected is equal
}
if ($counter != count($supported_alg)*count($keychain)) goto print_and_exit;
// DEV-422: ED25519 dual-mode key (mode "ECDH,ExDSA") - EdDSA signature and ECDH (Ed25519 key converted to X25519) both work
$token_keygen = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:gen");
if ($token_keygen == false) goto print_and_exit;             // exit on error
$run = bin2hex(openssl_random_pseudo_bytes(3));
foreach (array("ECDH,ExDSA" => true, "ExDSA" => false) as $mode => $has_ecdh) {
  $ret_val = false;
  $post_data = json_encode(array('label' => "T-11.5 ED25519 $mode $run", 'type' => "ED25519", 'mode' => $mode, 'descr' => base64_encode("CCTEST:T-11.5_ED25519_dual")));
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/create", $ret_val, $post_data, $token_keygen);
  if ( $ret_stat != 200 ) { echo "ERROR: create ED25519 mode $mode: HTTP $ret_stat\n"; goto print_and_exit; }
  $kid = $ret_val['kid'];
  $ret_val = false;
  $dummy_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/keymgmt/get/$kid", $ret_val, $dummy_val, $token_keygen);
  if ( ($ret_stat != 200) || !isset($ret_val['pubkey']) ) goto print_and_exit;
  $ed_pub = base64_decode($ret_val['pubkey']);
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid");
  if ($token == false) goto print_and_exit;
  // a) EdDSA signature, verified locally
  $msg = openssl_random_pseudo_bytes(48);
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/sign", $ret_val, json_encode(array('kid' => $kid, 'msg' => base64_encode($msg), 'alg' => "Ed25519")), $token);
  if ( ($ret_stat != 200) || !sodium_crypto_sign_verify_detached(base64_decode($ret_val['sign']), $msg, $ed_pub) ) { echo "ERROR: ED25519 mode $mode: signature (HTTP $ret_stat) does not verify locally\n"; goto print_and_exit; }
  // b) ECDH with a local X25519 key: Z = X25519(peer private, Ed25519 public key converted to Curve25519)
  $peer_priv = openssl_random_pseudo_bytes(32);
  $peer_pub = sodium_crypto_scalarmult_base($peer_priv);
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/ecdh", $ret_val, json_encode(array('kid' => $kid, 'pubkey' => base64_encode($peer_pub))), $token);
  if ($has_ecdh) {
    $z = sodium_crypto_scalarmult($peer_priv, sodium_crypto_sign_ed25519_pk_to_curve25519($ed_pub));
    if ( ($ret_stat != 200) || (base64_decode($ret_val['ecdh']) !== $z) ) { echo "ERROR: ED25519 mode $mode: ECDH (HTTP $ret_stat) differs from local X25519\n"; goto print_and_exit; }
  } else {
    if ( $ret_stat == 200 ) { echo "ERROR: ED25519 mode $mode: ECDH allowed without the ECDH mode\n"; goto print_and_exit; }
  }
}
// d) set result
$test_cfg['subtests'][5] = 'OK';                           // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 6        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST6:
echo "  subtest-6\n";
$test_cfg['subtests'][6] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) prerequirements
if (!isset($kid_subtest6a)) goto print_and_exit;
if (!isset($kid_subtest6b)) goto print_and_exit;
// b) get access tokens to two KIDs
$token_a = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid_subtest6a");
if ($token_a == false) goto print_and_exit;                    // exit on error
$token_b = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid_subtest6b");
if ($token_b == false) goto print_and_exit;                    // exit on error
// c) try to hash using wrong token
$msg = base64_encode( openssl_random_pseudo_bytes( 64 ) );
$ret_val = false;
$oper_arg = array('kid' => $kid_subtest6a, 'msg' => $msg);
$post_data = json_encode( $oper_arg );
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/hash", $ret_val, $post_data, $token_b);  //wrong token
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 403 ) goto print_and_exit;        // expected is 403 - HMAC hash executed with wrong token
// d) change token to the right one
$ret_val = false;
$oper_arg = array('kid' => $kid_subtest6a, 'msg' => $msg);
$post_data = json_encode( $oper_arg );
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/hash", $ret_val, $post_data, $token_a);  //rigth token
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - HMAC hash generated
// e) set result
$test_cfg['subtests'][6] = 'OK';                           // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 7        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST7:
echo "  subtest-7\n";
if ($diag_mode == false) {
  echo "    No DIAG mode, subtest will be skipped.\n";
  $test_cfg['subtests'][7] = 'SKIPPED (no DIAG)';             // not a failure - the DIAG endpoints exist only in R&D builds
  goto TEST8;
}
$test_cfg['subtests'][7] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) prerequirements
if (!isset($kid_subtest6a)) goto print_and_exit;
if (!isset($kid_subtest6b)) goto print_and_exit;
if (!isset($token_a)) goto print_and_exit;
if (!isset($token_b)) goto print_and_exit;
// b) check status to ensure no failure stated exists
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/status", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
if ( $ret_val['fls_state'] != 0 ) goto print_and_exit;     // expected is no failer (zero)
// c) gen token needed to reboot after test the TOE
$token = helper_authorize($cfg_domain, $cfg_passpharse, "system:config");       // token will be needed to reboot
if ($token == false) goto print_and_exit;                    // exit on error
// d) try to hash - should succeed
$msg = base64_encode( openssl_random_pseudo_bytes( 64 ) );
$ret_val = false;
$oper_arg = array('kid' => $kid_subtest6a, 'msg' => $msg);
$post_data = json_encode( $oper_arg );
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/hash", $ret_val, $post_data, $token_a);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - success
// e) execute simulated failer
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/diag/break_temp", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200
// f) check if in failer state is triggered - set asynchronously by the self-test, poll up to 10 s; evaluated after the reboot
$fls_ok = false;
for ($i = 0; $i < 10; $i++) {
  sleep(1);
  $ret_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/status", $ret_val);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( ($ret_stat == 200) && ($ret_val['fls_state'] != 0) ) { $fls_ok = true; break; }     // expected is failer state (non-zero)
}
// g) repeat above hash genearion
if ( $fls_ok ) {
  $ret_val = false;
  $post_data = json_encode( $oper_arg );
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/hash", $ret_val, $post_data, $token_a);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 409 ) $fls_ok = false;          // expected is 409 - FLS.1 involved
}
// h) reboot to clear simulated failer state - always, so a failed check does not leave the device in FLS
$ret_val = false;
$dummy_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/reboot", $ret_val, $dummy_val, $token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
sleep(30);  //wait
if ( !$fls_ok ) goto print_and_exit;                        // failure state not entered or the request not refused with 409
// i) set result
$test_cfg['subtests'][7] = 'OK';                           // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 8        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST8:
echo "  subtest-8\n";
$test_cfg['subtests'][8] = 'ERROR';                         // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) get TOE status
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/status", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
// b) set RTC clock - code from T-1.3
$ret = helper_checkin($cfg_domain);
// c) generate keychain search over pattern keys for ML-KEM operations
$pattern_plain = "CCTEST:T-10.1_MLKEM";
$pattern = "^".base64_encode($pattern_plain);  //^ denotes 'begining by following bytes' - like regexpr :)
$offset = 0;
$keychain = array();
do {
  $ret_val = false;
  $post_array = array('descr' => $pattern, 'offset' => $offset );  //^ denotes 'begining by following bytes' - like regexpr :)
  $post_data = json_encode( $post_array );
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/search", $ret_val, $post_data);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //200 if found, 404 if not
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  if ($listed == 0) break;  // go all the keys
  foreach($ret_val['list'] as $item) $keychain[] = $item;
  $offset = $offset + $listed;
  if ($offset >= $total) break;
} while (true);
// d) iterate over found keys to call ML-KEM Encapsulation and the Decapsulation
//var_dump($keychain);
$counter = 0;
foreach($keychain as $item) {
  $kid = $item['kid'];
  // gen access token for that KID
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid");   // more here https://docs.encedo.com/hem-api/reference/api-reference/cryptography-operations/hmac#required-access-scope
  if ($token == false) goto print_and_exit;                    // exit on error
  // encapsulation
  $ret_val = false;
  $oper_arg = array('kid' => $kid);
  $post_data = json_encode( $oper_arg );
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/mlkem/encaps", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - HMAC hash generated
  $ss_encaps = $ret_val['ss'];
  $ct_encaps = $ret_val['ct'];
  // decapsulation
  $ret_val = false;
  $oper_arg = array('kid' => $kid, 'ct' => $ct_encaps);
  $post_data = json_encode( $oper_arg );
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/mlkem/decaps", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - HMAC verify success
  // DEV-481 (A3): decaps "alg" is the key type (was the scope string)
  $item_type = explode(",", $item['type']);
  if (@$ret_val['alg'] !== $item_type[count($item_type) - 1]) { echo "ERROR: decaps alg " . @$ret_val['alg'] . "\n"; goto print_and_exit; }
  // compate two SS values - should be equal
  if ($ss_encaps !== $ret_val['ss']) goto print_and_exit;
  $counter++;
}
// e) if above loop ends and no 'goto' calls, all ML-KEM tests passed!
//echo "    Executed $counter tests over ". count($keychain) . " keys\n";
if ($counter != count($keychain)) goto print_and_exit;
// f) set result
$test_cfg['subtests'][8] = 'OK';                           // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 9        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST9:
echo "  subtest-9\n";
$test_cfg['subtests'][9] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) generate keychain search over pattern keys for ML-DSA operations
$pattern_plain = "CCTEST:T-10.1_MLDSA";
$pattern = "^".base64_encode($pattern_plain);  //^ denotes 'begining by following bytes' - like regexpr :)
$offset = 0;
$keychain = array();
do {
  $ret_val = false;
  $post_array = array('descr' => $pattern, 'offset' => $offset );  //^ denotes 'begining by following bytes' - like regexpr :)
  $post_data = json_encode( $post_array );
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/search", $ret_val, $post_data);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //200 if found, 404 if not
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  if ($listed == 0) break;  // go all the keys
  foreach($ret_val['list'] as $item) $keychain[] = $item;
  $offset = $offset + $listed;
  if ($offset >= $total) break;
} while (true);
// b) iterate over found keys to call ML-DSA Sign & Verification
//var_dump($keychain);
$token_keyget = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:get");   // DEV-481 (B3): public key for mu
if ($token_keyget == false) goto print_and_exit;
$counter = 0;
foreach($keychain as $item) {
  $kid = $item['kid'];
  // gen access token for that KID
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid");   // more here https://docs.encedo.com/hem-api/reference/api-reference/cryptography-operations/hmac#required-access-scope
  if ($token == false) goto print_and_exit;                    // exit on error
  // sign
  $msg_raw = base64_encode( openssl_random_pseudo_bytes( 250 ) );    // ranodm bytes of data
  $ret_val = false;
  $oper_arg = array('kid' => $kid, 'msg' => $msg_raw);
  $post_data = json_encode( $oper_arg );
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/mldsa/sign", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - HMAC hash generated
  $signature = $ret_val['sign'];
  // verification
  $ret_val = false;
  $oper_arg = array('kid' => $kid, 'msg' => $msg_raw, 'sign' => $signature);
  $post_data = json_encode( $oper_arg );
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/mldsa/verify", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( ($ret_stat != 200) || (@$ret_val['verified'] !== true) ) goto print_and_exit;        // expected is 200 - HMAC verify success
  // DEV-481 (B4): HashML-DSA-SHA512 - msg = SHA-512 of the data, with ctx; sign + verify
  $ctx = base64_encode( openssl_random_pseudo_bytes( 16 ) );
  $oper_arg = array('kid' => $kid, 'msg' => base64_encode(hash('sha512', base64_decode($msg_raw), true)), 'ctx' => $ctx, 'mode' => "HashML-DSA-SHA512");
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/mldsa/sign", $ret_val, json_encode( $oper_arg ), $token);
  if ( $ret_stat != 200 ) goto print_and_exit;
  $oper_arg['sign'] = $ret_val['sign'];
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/mldsa/verify", $ret_val, json_encode( $oper_arg ), $token);
  if ( ($ret_stat != 200) || (@$ret_val['verified'] !== true) ) { echo "ERROR: HashML-DSA-SHA512 verify (" . $item['type'] . ")\n"; goto print_and_exit; }
  // DEV-481 (B3): ML-DSA-mu - mu made here (FIPS 204: tr = SHAKE256(pk, 64), mu = SHAKE256(tr || 00 00 || M, 64)); the signature verifies as pure ML-DSA over M
  $ret_val = false;
  $dummy_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/keymgmt/get/$kid", $ret_val, $dummy_val, $token_keyget);
  if ( $ret_stat != 200 ) goto print_and_exit;
  $mu = t11_shake256_64( t11_shake256_64(base64_decode($ret_val['pubkey'])) . "\x00\x00" . base64_decode($msg_raw) );
  if ($mu === false) { echo "ERROR: openssl >= 3.5 needed (SHAKE256)\n"; goto print_and_exit; }
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/mldsa/sign", $ret_val, json_encode( array('kid' => $kid, 'msg' => base64_encode($mu), 'mode' => "ML-DSA-mu") ), $token);
  if ( $ret_stat != 200 ) goto print_and_exit;
  $ret_val_sign = $ret_val['sign'];
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/mldsa/verify", $ret_val, json_encode( array('kid' => $kid, 'msg' => $msg_raw, 'sign' => $ret_val_sign) ), $token);
  if ( ($ret_stat != 200) || (@$ret_val['verified'] !== true) ) { echo "ERROR: ML-DSA-mu signature is not a pure ML-DSA signature (" . $item['type'] . ")\n"; goto print_and_exit; }
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/mldsa/sign", $ret_val, json_encode( array('kid' => $kid, 'msg' => base64_encode(substr($mu, 1)), 'mode' => "ML-DSA-mu") ), $token);
  if ( $ret_stat != 400 ) { echo "ERROR: ML-DSA-mu 63 B: HTTP $ret_stat (400 expected)\n"; goto print_and_exit; }
  $counter++;
}
// c) if above loop ends and no 'goto' calls, all ML-KEM tests passed!
echo "    Executed $counter tests over ". count($keychain) . " keys\n";
if ($counter != count($keychain)) goto print_and_exit;
// d) set result
$test_cfg['subtests'][9] = 'OK';                           // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 10       ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST10:
echo "  subtest-10\n";
$test_cfg['subtests'][10] = 'ERROR';                          // mark this subtest default as ERROR - initialization as subtest is ongoing
// DEV-481 (A1, A2): ML-DSA verify and ML-KEM encaps on imported public keys; host side OpenSSL CLI >= 3.5
$token_keyimp = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:imp");
if ($token_keyimp == false) goto print_and_exit;
$token_keydel = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:del");
if ($token_keydel == false) goto print_and_exit;
$dir = sys_get_temp_dir() . "/t11_" . bin2hex(openssl_random_pseudo_bytes(4));
@mkdir($dir);
$imported = array();
// a) ML-DSA-65: key pair on the host, public key imported, host signature verified by HEM
if (!t11_ossl(array("genpkey", "-algorithm", "ML-DSA-65", "-out", "$dir/d.pem"))) { echo "ERROR: openssl >= 3.5 needed\n"; goto t11_10_end; }
t11_ossl(array("pkey", "-in", "$dir/d.pem", "-pubout", "-outform", "DER", "-out", "$dir/d.der"));
$msg = openssl_random_pseudo_bytes(250);
file_put_contents("$dir/m.bin", $msg);
if (!t11_ossl(array("pkeyutl", "-sign", "-rawin", "-inkey", "$dir/d.pem", "-in", "$dir/m.bin", "-out", "$dir/s.bin"))) goto t11_10_end;
$ret_val = false;
$post_data = json_encode(array('label' => "T-11.10 IMP MLDSA65", 'type' => "MLDSA65", 'descr' => base64_encode("CCTEST:T-11.10_MLDSA65_imported"), 'pubkey' => base64_encode(substr(file_get_contents("$dir/d.der"), -1952))));
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/import", $ret_val, $post_data, $token_keyimp);
if ( $ret_stat != 200 ) { echo "ERROR: import MLDSA65: HTTP $ret_stat\n"; goto t11_10_end; }
$kid = $ret_val['kid'];
$imported[] = $kid;
$token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid");
if ($token == false) goto t11_10_end;
$sig = file_get_contents("$dir/s.bin");
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/mldsa/verify", $ret_val, json_encode(array('kid' => $kid, 'msg' => base64_encode($msg), 'sign' => base64_encode($sig))), $token);
if ( ($ret_stat != 200) || (@$ret_val['verified'] !== true) ) { echo "ERROR: verify (imported MLDSA65): HTTP $ret_stat\n"; goto t11_10_end; }
$sig[100] = chr(ord($sig[100]) ^ 1);                          // one bit changed
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/mldsa/verify", $ret_val, json_encode(array('kid' => $kid, 'msg' => base64_encode($msg), 'sign' => base64_encode($sig))), $token);
if ( ($ret_stat != 200) || (@$ret_val['verified'] !== false) ) { echo "ERROR: verify of a bad signature: HTTP $ret_stat\n"; goto t11_10_end; }
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/mldsa/sign", $ret_val, json_encode(array('kid' => $kid, 'msg' => base64_encode($msg))), $token);
if ( $ret_stat != 406 ) { echo "ERROR: sign on a public key: HTTP $ret_stat (406 expected)\n"; goto t11_10_end; }
// b) ML-KEM-768: public key imported, HEM encaps, host decaps, the same shared secret
if (!t11_ossl(array("genpkey", "-algorithm", "ML-KEM-768", "-out", "$dir/k.pem"))) goto t11_10_end;
t11_ossl(array("pkey", "-in", "$dir/k.pem", "-pubout", "-outform", "DER", "-out", "$dir/k.der"));
$ret_val = false;
$post_data = json_encode(array('label' => "T-11.10 IMP MLKEM768", 'type' => "MLKEM768", 'descr' => base64_encode("CCTEST:T-11.10_MLKEM768_imported"), 'pubkey' => base64_encode(substr(file_get_contents("$dir/k.der"), -1184))));
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/import", $ret_val, $post_data, $token_keyimp);
if ( $ret_stat != 200 ) { echo "ERROR: import MLKEM768: HTTP $ret_stat\n"; goto t11_10_end; }
$kid = $ret_val['kid'];
$imported[] = $kid;
$token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid");
if ($token == false) goto t11_10_end;
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/mlkem/encaps", $ret_val, json_encode(array('kid' => $kid)), $token);
if ( $ret_stat != 200 ) { echo "ERROR: encaps (imported MLKEM768): HTTP $ret_stat\n"; goto t11_10_end; }
if (@$ret_val['alg'] !== "MLKEM768") goto t11_10_end;
$ct = $ret_val['ct'];
$ss = $ret_val['ss'];
file_put_contents("$dir/ct.bin", base64_decode($ct));
if (!t11_ossl(array("pkeyutl", "-decap", "-inkey", "$dir/k.pem", "-in", "$dir/ct.bin", "-secret", "$dir/ss.bin"))) goto t11_10_end;
if (base64_encode(file_get_contents("$dir/ss.bin")) !== $ss) { echo "ERROR: host decaps ss differs\n"; goto t11_10_end; }
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/mlkem/decaps", $ret_val, json_encode(array('kid' => $kid, 'ct' => $ct)), $token);
if ( $ret_stat != 400 ) { echo "ERROR: decaps on a public key: HTTP $ret_stat (400 expected)\n"; goto t11_10_end; }
// c) set result
$test_cfg['subtests'][10] = 'OK';                            // mark this subtest as OK
t11_10_end:
foreach ($imported as $kid) {                                // the imported keys are removed (fresh keys every run)
  $ret_val = false;
  $dummy_val = false;
  $ret_stat = http_transaction("https", "DELETE", $cfg_domain, "/api/keymgmt/delete/$kid", $ret_val, $dummy_val, $token_keydel);
  if ( $ret_stat != 200 ) $test_cfg['subtests'][10] = 'ERROR';
}
array_map('unlink', glob("$dir/*"));
@rmdir($dir);
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 11       ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST11:
echo "  subtest-11\n";
$test_cfg['subtests'][11] = 'ERROR';                          // mark this subtest default as ERROR - initialization as subtest is ongoing
// DEV-481 (B6): key type SHA1 and /api/crypto/hmac/otp. The seed is made as in an enrolment: derive over ECDH with type SHA1,
// the same seed is computed here (nothing is exported); HOTP / TOTP compared with the local RFC 4226 / 6238 values
$t11_created = array();
$token_keygen = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:gen");
if ($token_keygen == false) goto print_and_exit;
$token_keydel = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:del");
if ($token_keydel == false) goto print_and_exit;
if ( (t11_hotp("12345678901234567890", 0) !== "755224") || (t11_hotp("12345678901234567890", intdiv(1111111109, 30), 8) !== "07081804") ) goto print_and_exit;   // the local reference (RFC vectors)
$ret_val = false;
$post_data = json_encode(array('label' => "T-11.11 ECDH", 'type' => "SECP256R1", 'mode' => "ECDH", 'descr' => base64_encode("CCTEST:T-11.11_ECDH"), 'return_pubkey' => true));
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/create", $ret_val, $post_data, $token_keygen);
if ( $ret_stat != 200 ) goto t11_11_end;
$t11_created[] = $ret_val['kid'];
$keyargs = array('private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => "prime256v1");
$cnf = dirname(PHP_BINARY) . "\\extras\\ssl\\openssl.cnf";       // Windows PHP builds do not find openssl.cnf on their own
if ( (getenv("OPENSSL_CONF") === false) && (PHP_OS_FAMILY == "Windows") && file_exists($cnf) ) $keyargs['config'] = $cnf;
$peer = openssl_pkey_new($keyargs);
if ($peer === false) goto t11_11_end;
$z = openssl_pkey_derive(t11_p256_pem(base64_decode($ret_val['pubkey'])), $peer);
$ec = openssl_pkey_get_details($peer)['ec'];
$peer_pub = ((ord(substr($ec['y'], -1)) & 1) ? "\x03" : "\x02") . str_pad($ec['x'], 32, "\0", STR_PAD_LEFT);
$salt = openssl_random_pseudo_bytes(16);
$post_data = json_encode(array('kid' => $t11_created[0], 'label' => "T-11.11 OTP", 'type' => "SHA1", 'pubkey' => base64_encode($peer_pub), 'hkdf_salt' => base64_encode($salt), 'descr' => base64_encode("CCTEST:T-11.11_OTP")));
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/derive", $ret_val, $post_data, $token_keygen);
if ( ($ret_stat != 200) || (@$ret_val['type'] !== "SHA1") ) { echo "ERROR: derive SHA1: HTTP $ret_stat\n"; goto t11_11_end; }
$kid = $ret_val['kid'];
$t11_created[] = $kid;
$seed = hash_hkdf('sha512', $z, 20, "encedo-derive:v1:sha1", $salt);
$token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid");
if ($token == false) goto t11_11_end;
// a) HOTP compute, 6 and 8 digits
foreach (array(0, 1, 9, 1000000) as $c) foreach (array(6, 8) as $d) {
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/otp", $ret_val, json_encode(array('kid' => $kid, 'mode' => "HOTP", 'counter' => $c, 'digits' => $d)), $token);
  if ( ($ret_stat != 200) || (@$ret_val['code'] !== t11_hotp($seed, $c, $d)) ) { echo "ERROR: HOTP counter $c digits $d: HTTP $ret_stat\n"; goto t11_11_end; }
}
// b) TOTP compute with time (RFC 6238 times) and with the device RTC
foreach (array(59, 1111111109, 2000000000) as $t) {
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/otp", $ret_val, json_encode(array('kid' => $kid, 'mode' => "TOTP", 'time' => $t, 'digits' => 8)), $token);
  if ( ($ret_stat != 200) || (@$ret_val['code'] !== t11_hotp($seed, intdiv($t, 30), 8)) || (@$ret_val['step'] !== intdiv($t, 30)) ) { echo "ERROR: TOTP time $t: HTTP $ret_stat\n"; goto t11_11_end; }
}
$t0 = time();
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/otp", $ret_val, json_encode(array('kid' => $kid, 'mode' => "TOTP")), $token);
if ( ($ret_stat != 200) || !in_array(@$ret_val['code'], array(t11_hotp($seed, intdiv($t0, 30) - 1), t11_hotp($seed, intdiv($t0, 30)), t11_hotp($seed, intdiv($t0, 30) + 1)), true) ) { echo "ERROR: TOTP device RTC: HTTP $ret_stat\n"; goto t11_11_end; }
// c) verify: window +-1, step +2 outside, wrong code, HOTP look-ahead
$st = intdiv(1234567890, 30);
foreach (array(array(t11_hotp($seed, $st), true), array(t11_hotp($seed, $st - 1), true), array(t11_hotp($seed, $st + 1), true), array(t11_hotp($seed, $st + 2), false)) as $v) {
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/otp", $ret_val, json_encode(array('kid' => $kid, 'mode' => "TOTP", 'time' => 1234567890, 'code' => $v[0])), $token);
  if ( ($ret_stat != 200) || (@$ret_val['verified'] !== $v[1]) ) { echo "ERROR: TOTP verify " . $v[0] . ": HTTP $ret_stat\n"; goto t11_11_end; }
}
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/otp", $ret_val, json_encode(array('kid' => $kid, 'mode' => "HOTP", 'counter' => 5, 'code' => t11_hotp($seed, 7), 'window' => 2)), $token);
if ( ($ret_stat != 200) || (@$ret_val['verified'] !== true) || (@$ret_val['step'] !== 7) ) { echo "ERROR: HOTP verify look-ahead: HTTP $ret_stat\n"; goto t11_11_end; }
// d) bad input -> 400, SHA1 key in hmac/hash -> 406
foreach (array(array('mode' => "TOTP", 'time' => 59, 'digits' => 7), array('mode' => "TOTP", 'time' => 59, 'period' => 10), array('mode' => "TOTP", 'time' => 59, 'code' => "12a456"),
               array('mode' => "TOTP", 'time' => 59, 'code' => "123456", 'window' => 11), array('mode' => "HOTP"), array('mode' => "x")) as $bad) {
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/otp", $ret_val, json_encode(array_merge(array('kid' => $kid), $bad)), $token);
  if ( $ret_stat != 400 ) { echo "ERROR: otp " . json_encode($bad) . ": HTTP $ret_stat (400 expected)\n"; goto t11_11_end; }
}
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/hash", $ret_val, json_encode(array('kid' => $kid, 'msg' => base64_encode("x"))), $token);
if ( $ret_stat != 406 ) { echo "ERROR: hmac/hash on a SHA1 key: HTTP $ret_stat (406 expected)\n"; goto t11_11_end; }
// e) set result
$test_cfg['subtests'][11] = 'OK';                             // mark this subtest as OK
t11_11_end:
foreach ($t11_created as $k) {                                // the keys of this subtest are removed
  $ret_val = false;
  $dummy_val = false;
  $ret_stat = http_transaction("https", "DELETE", $cfg_domain, "/api/keymgmt/delete/$k", $ret_val, $dummy_val, $token_keydel);
  if ( $ret_stat != 200 ) $test_cfg['subtests'][11] = 'ERROR';
}
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 12       ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST12:
echo "  subtest-12\n";
$test_cfg['subtests'][12] = 'ERROR';                          // mark this subtest default as ERROR - initialization as subtest is ongoing
// DEV-482: X-Wing (ML-KEM-768 + X25519) on two stored keys; host side OpenSSL CLI >= 3.5 (ML-KEM), sodium (X25519), SHA3-256
$t12_keys = array();
$token_keygen = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:gen");
if ($token_keygen == false) goto print_and_exit;
$token_keyimp = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:imp");
if ($token_keyimp == false) goto print_and_exit;
$token_keydel = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:del");
if ($token_keydel == false) goto print_and_exit;
$dir = sys_get_temp_dir() . "/t11_" . bin2hex(openssl_random_pseudo_bytes(4));
@mkdir($dir);
// a) keys made by HEM: host encaps -> HEM decaps, HEM encaps -> HEM decaps
$pub = array();
foreach (array("MLKEM768", "CURVE25519") as $type) {
  $ret_val = false;
  $post_data = json_encode(array('label' => "T-11.12 $type", 'type' => $type, 'descr' => base64_encode("CCTEST:T-11.12_$type"), 'return_pubkey' => true));
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/create", $ret_val, $post_data, $token_keygen);
  if ( $ret_stat != 200 ) { echo "ERROR: create $type: HTTP $ret_stat\n"; goto t11_12_end; }
  $t12_keys[] = $ret_val['kid'];
  $pub[] = base64_decode($ret_val['pubkey']);
}
list($kid_m, $kid_x) = $t12_keys;
$token = helper_authorize($cfg_domain, $cfg_passpharse, array("keymgmt:use:$kid_m", "keymgmt:use:$kid_x"));
if ($token == false) goto t11_12_end;
file_put_contents("$dir/pk.der", t11_mlkem768_der($pub[0]));
if (!t11_ossl(array("pkeyutl", "-encap", "-pubin", "-keyform", "DER", "-inkey", "$dir/pk.der", "-out", "$dir/ct.bin", "-secret", "$dir/ss.bin"))) { echo "ERROR: openssl >= 3.5 needed\n"; goto t11_12_end; }
$eph = random_bytes(32);
$ct_x = sodium_crypto_scalarmult_base($eph);
$ct = file_get_contents("$dir/ct.bin") . $ct_x;
$ss = t11_xwing(file_get_contents("$dir/ss.bin"), sodium_crypto_scalarmult($eph, $pub[1]), $ct_x, $pub[1]);
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/xwing/decaps", $ret_val, json_encode(array('kid' => $kid_m, 'ext_kid' => $kid_x, 'ct' => base64_encode($ct))), $token);
if ( ($ret_stat != 200) || (@$ret_val['alg'] !== "X-Wing") || (@$ret_val['ss'] !== base64_encode($ss)) ) { echo "ERROR: decaps of a host ct: HTTP $ret_stat\n"; goto t11_12_end; }
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/xwing/encaps", $ret_val, json_encode(array('kid' => $kid_m, 'ext_kid' => $kid_x)), $token);
if ( ($ret_stat != 200) || (@$ret_val['alg'] !== "X-Wing") || (strlen(base64_decode(@$ret_val['ct'])) != 1120) ) { echo "ERROR: encaps: HTTP $ret_stat\n"; goto t11_12_end; }
$ss = $ret_val['ss'];
$ct = base64_decode($ret_val['ct']);
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/xwing/decaps", $ret_val, json_encode(array('kid' => $kid_m, 'ext_kid' => $kid_x, 'ct' => base64_encode($ct))), $token);
if ( ($ret_stat != 200) || (@$ret_val['ss'] !== $ss) ) { echo "ERROR: decaps of a HEM ct: HTTP $ret_stat\n"; goto t11_12_end; }
// b) bad input: ct 1119 B, kid / ext_kid swapped -> 400; one scope only -> 403; a changed ct_M or ct_X -> 200 with another ss
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/xwing/decaps", $ret_val, json_encode(array('kid' => $kid_m, 'ext_kid' => $kid_x, 'ct' => base64_encode(substr($ct, 0, 1119)))), $token);
if ( $ret_stat != 400 ) { echo "ERROR: decaps of a 1119 B ct: HTTP $ret_stat (400 expected)\n"; goto t11_12_end; }
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/xwing/encaps", $ret_val, json_encode(array('kid' => $kid_x, 'ext_kid' => $kid_m)), $token);
if ( $ret_stat != 400 ) { echo "ERROR: encaps with swapped keys: HTTP $ret_stat (400 expected)\n"; goto t11_12_end; }
$token_one = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid_m");
if ($token_one == false) goto t11_12_end;
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/xwing/encaps", $ret_val, json_encode(array('kid' => $kid_m, 'ext_kid' => $kid_x)), $token_one);
if ( $ret_stat != 403 ) { echo "ERROR: encaps with one scope: HTTP $ret_stat (403 expected)\n"; goto t11_12_end; }
foreach (array(100, 1100) as $pos) {                          // a byte of ct_M, a byte of ct_X
  $bad = $ct;
  $bad[$pos] = chr(ord($bad[$pos]) ^ 1);
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/xwing/decaps", $ret_val, json_encode(array('kid' => $kid_m, 'ext_kid' => $kid_x, 'ct' => base64_encode($bad))), $token);
  if ( ($ret_stat != 200) || (strlen(base64_decode(@$ret_val['ss'])) != 32) || ($ret_val['ss'] === $ss) ) { echo "ERROR: decaps of a changed ct ($pos): HTTP $ret_stat\n"; goto t11_12_end; }
}
// c) keys made by the host and imported: HEM encaps -> host decaps; decaps on the imported keys -> 400
if (!t11_ossl(array("genpkey", "-algorithm", "ML-KEM-768", "-out", "$dir/k.pem"))) goto t11_12_end;
t11_ossl(array("pkey", "-in", "$dir/k.pem", "-pubout", "-outform", "DER", "-out", "$dir/k.der"));
$xkp = sodium_crypto_box_keypair();
$sk_x = sodium_crypto_box_secretkey($xkp);
$pk_x = sodium_crypto_box_publickey($xkp);
$imp = array();
foreach (array(array("MLKEM768", substr(file_get_contents("$dir/k.der"), -1184)), array("CURVE25519", $pk_x)) as $k) {
  $ret_val = false;
  $post_data = json_encode(array('label' => "T-11.12 IMP " . $k[0], 'type' => $k[0], 'descr' => base64_encode("CCTEST:T-11.12_" . $k[0] . "_imported"), 'pubkey' => base64_encode($k[1])));
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/import", $ret_val, $post_data, $token_keyimp);
  if ( $ret_stat != 200 ) { echo "ERROR: import " . $k[0] . ": HTTP $ret_stat\n"; goto t11_12_end; }
  $t12_keys[] = $ret_val['kid'];
  $imp[] = $ret_val['kid'];
}
$token = helper_authorize($cfg_domain, $cfg_passpharse, array("keymgmt:use:" . $imp[0], "keymgmt:use:" . $imp[1]));
if ($token == false) goto t11_12_end;
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/xwing/encaps", $ret_val, json_encode(array('kid' => $imp[0], 'ext_kid' => $imp[1])), $token);
if ( $ret_stat != 200 ) { echo "ERROR: encaps (imported keys): HTTP $ret_stat\n"; goto t11_12_end; }
$ct = base64_decode($ret_val['ct']);
file_put_contents("$dir/ct.bin", substr($ct, 0, 1088));
if (!t11_ossl(array("pkeyutl", "-decap", "-inkey", "$dir/k.pem", "-in", "$dir/ct.bin", "-secret", "$dir/ss.bin"))) goto t11_12_end;
$ct_x = substr($ct, 1088);
if (base64_encode(t11_xwing(file_get_contents("$dir/ss.bin"), sodium_crypto_scalarmult($sk_x, $ct_x), $ct_x, $pk_x)) !== $ret_val['ss']) { echo "ERROR: host decaps ss differs\n"; goto t11_12_end; }
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/xwing/decaps", $ret_val, json_encode(array('kid' => $imp[0], 'ext_kid' => $imp[1], 'ct' => base64_encode($ct))), $token);
if ( $ret_stat != 400 ) { echo "ERROR: decaps on public keys: HTTP $ret_stat (400 expected)\n"; goto t11_12_end; }
// d) set result
$test_cfg['subtests'][12] = 'OK';                             // mark this subtest as OK
t11_12_end:
foreach ($t12_keys as $k) {                                   // the keys of this subtest are removed
  $ret_val = false;
  $dummy_val = false;
  $ret_stat = http_transaction("https", "DELETE", $cfg_domain, "/api/keymgmt/delete/$k", $ret_val, $dummy_val, $token_keydel);
  if ( $ret_stat != 200 ) $test_cfg['subtests'][12] = 'ERROR';
}
array_map('unlink', glob("$dir/*"));
@rmdir($dir);
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
  if (($val === 'OK') || ($val === 'SKIPPED (no DIAG)')) $check_passed++;   // a DIAG subtest skipped on a build without DIAG is not a failure
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
