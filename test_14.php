<?php

include "libs/lib.php";
include "config.php";


// test name, descr & number of subtests
$test_name = "T-14";
$test_descr = "Key derivation interoperability (local reproduction of /api/keymgmt/derive)";
$test_subtest_cnt = 4;


// initialize the execution env
init_env();
$test_cfg = init_test($test_name, $test_descr, $test_subtest_cnt, $cfg_tester);
if ( $cfg_debug ) var_dump( $cfg_domain );
$test_cfg['elapsed'] = hrtime(true);

// Windows PHP builds do not find openssl.cnf on their own - EC key generation fails without it
$t14_keyargs = array('private_key_type' => OPENSSL_KEYTYPE_EC);
$cnf = dirname(PHP_BINARY) . "\\extras\\ssl\\openssl.cnf";
if ( (getenv("OPENSSL_CONF") === false) && (PHP_OS_FAMILY == "Windows") && file_exists($cnf) ) {
  $t14_keyargs['config'] = $cnf;
}

echo "Processing...\n";


/////////////////////////////////////////////////////////////////////
// Local helpers (this test only)    ////////////////////////////////
/////////////////////////////////////////////////////////////////////
// FW 1.3.0 derive (DEV-428/429, see crypto.c CRYPTO_HkdfToEccScalar):
//   Z    = ECDH shared secret (NIST: x-coordinate, X25519: 32 bytes)
//   OKM  = HKDF-SHA512(IKM = Z, salt = "hkdf_salt" or none, info = "encedo-derive:v1:<type>", length)
//   NIST: length = L + 8, d = (OS2IP(OKM) mod (n - 1)) + 1, private key = I2OSP(d, L)
//   other types: length = key size, OKM is the key (X25519 / Ed25519 seed / HMAC / AES key)
$t14_curves = array(  // HEM type => OpenSSL curve name, curve OID (DER), L, order n (hex)
  "SECP256R1" => array("prime256v1", "06082a8648ce3d030107", 32, "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
  "SECP384R1" => array("secp384r1",  "06052b81040022",       48, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"),
  "SECP521R1" => array("secp521r1",  "06052b81040023",       66, "01FF" . str_repeat("FFFFFFFF", 7) . "FFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"),
  "SECP256K1" => array("secp256k1",  "06052b8104000a",       32, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
);

function t14_der($tag, $body) {             // DER TLV, lengths up to 65535
  $len = strlen($body);
  if ($len < 0x80) return chr($tag) . chr($len) . $body;
  if ($len < 0x100) return chr($tag) . "\x81" . chr($len) . $body;
  return chr($tag) . "\x82" . chr($len >> 8) . chr($len & 0xff) . $body;
}

function t14_compress($ec, $len) {          // openssl_pkey_get_details()['ec'] -> compressed point 02/03 || x
  // OpenSSL returns x without leading zero bytes (P-521: 65 bytes when the top byte is 0) - pad to the curve size
  return ((ord(substr($ec['y'], -1)) & 1) ? "\x03" : "\x02") . str_pad($ec['x'], $len, "\0", STR_PAD_LEFT);
}

function t14_pem_pub($type, $point) {       // compressed point -> SubjectPublicKeyInfo PEM
  global $t14_curves;
  $der = t14_der(0x30, t14_der(0x30, hex2bin("06072a8648ce3d0201") . hex2bin($t14_curves[$type][1])) . t14_der(0x03, "\x00" . $point));
  return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
}

function t14_nist_pub($type, $okm) {        // OKM -> d = (c mod (n - 1)) + 1 -> compressed public key
  global $t14_curves;
  list($name, $oid, $L, $n_hex) = $t14_curves[$type];
  $c = '0';
  foreach (str_split($okm) as $ch) $c = bcadd(bcmul($c, '256'), (string)ord($ch));
  $n = '0';
  foreach (str_split(hex2bin($n_hex)) as $ch) $n = bcadd(bcmul($n, '256'), (string)ord($ch));
  $d = bcadd(bcmod($c, bcsub($n, '1')), '1');
  $d_bin = '';
  for ($i = 0; $i < $L; $i++) { $d_bin = chr((int)bcmod($d, '256')) . $d_bin; $d = bcdiv($d, '256', 0); }
  // RFC 5915 ECPrivateKey without the public key - OpenSSL computes it on load
  $der = t14_der(0x30, "\x02\x01\x01" . t14_der(0x04, $d_bin) . t14_der(0xa0, hex2bin($oid)));
  $key = openssl_pkey_get_private("-----BEGIN EC PRIVATE KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END EC PRIVATE KEY-----\n");
  if ($key === false) return false;
  return t14_compress(openssl_pkey_get_details($key)['ec'], $L);
}

function t14_create($cfg_domain, $token, $type, $label) {   // ECDH main key on the HEM -> array(kid, raw pubkey)
  $post_data = json_encode(array('label' => $label, 'type' => $type, 'mode' => "ECDH", 'descr' => base64_encode("CCTEST:$label"), 'return_pubkey' => true));
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/create", $ret_val, $post_data, $token);
  if ( ($ret_stat != 200) || !isset($ret_val['pubkey']) ) return false;
  return array($ret_val['kid'], base64_decode($ret_val['pubkey']));
}

function t14_derive($cfg_domain, $token, $kid, $type, $peer_pub, $salt, $label) {   // -> reply array or HTTP status
  $arg = array('kid' => $kid, 'label' => $label, 'type' => $type, 'pubkey' => base64_encode($peer_pub), 'descr' => base64_encode("CCTEST:$label"), 'return_pubkey' => true);
  if ($salt !== '') $arg['hkdf_salt'] = base64_encode($salt);
  $post_data = json_encode($arg);
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/derive", $ret_val, $post_data, $token);
  return ($ret_stat == 200) ? $ret_val : $ret_stat;
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
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/version", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
$test_cfg['hwv'] = $ret_val['hwv'];                         //   or follow on with processing
$test_cfg['blv'] = @$ret_val['blv'];
$test_cfg['fwv'] = $ret_val['fwv'];
$test_cfg['conf'] = "ENCEDO PPA";
if ( strstr($ret_val['hwv'], "EPA") ) $test_cfg['conf'] = "ENCEDO EPA";
// c) local crypto available (openssl EC + bcmath + sodium)
if ( !function_exists("openssl_pkey_derive") || !function_exists("bcmod") || !function_exists("sodium_crypto_scalarmult") ) {
  echo "ERROR: PHP needs the openssl, bcmath and sodium extensions\n";
  goto print_and_exit;
}
// d) set RTC clock - code from T-1.3, token
$ret = helper_checkin($cfg_domain);
if ($ret == false) goto print_and_exit;                     // exit on error
$token_keygen = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:gen");
if ($token_keygen == false) goto print_and_exit;            // exit on error
// e) NIST main keys: every NIST target type from every NIST main key, without and with hkdf_salt
$run = bin2hex(openssl_random_pseudo_bytes(3));             // keeps labels unique between runs
$checked = 0;
foreach ($t14_curves as $main_type => $main_curve) {
  $main = t14_create($cfg_domain, $token_keygen, $main_type, "T-14.1 $main_type $run");
  if ($main == false) goto print_and_exit;                  // expected is 200 with pubkey
  list($main_kid, $main_pub) = $main;
  // local peer key pair on the same curve, Z = ECDH(local private, HEM public)
  $peer = openssl_pkey_new(array_merge($t14_keyargs, array('curve_name' => $main_curve[0])));
  if ($peer === false) { echo "ERROR: openssl_pkey_new($main_curve[0]) failed\n"; goto print_and_exit; }
  $peer_pub = t14_compress(openssl_pkey_get_details($peer)['ec'], $main_curve[2]);
  $z = openssl_pkey_derive(t14_pem_pub($main_type, $main_pub), $peer);
  if ( ($z === false) || (strlen($z) != $main_curve[2]) ) { echo "ERROR: local ECDH on $main_type failed\n"; goto print_and_exit; }
  foreach (array('', openssl_random_pseudo_bytes(16)) as $salt) {
    foreach ($t14_curves as $type => $curve) {
      $label = "T-14.1 $type<$main_type " . ($salt === '' ? "nosalt" : "salt") . " $run";
      $ret_val = t14_derive($cfg_domain, $token_keygen, $main_kid, $type, $peer_pub, $salt, $label);
      if ( !is_array($ret_val) ) { echo "ERROR: derive $label: HTTP $ret_val\n"; goto print_and_exit; }
      $okm = hash_hkdf('sha512', $z, $curve[2] + 8, "encedo-derive:v1:" . strtolower($type), $salt);
      $expected = t14_nist_pub($type, $okm);
      if ( ($expected === false) || ($ret_val['pubkey'] !== base64_encode($expected)) ) {
        echo "ERROR: $label: HEM pubkey " . $ret_val['pubkey'] . ", local " . ($expected === false ? "-" : base64_encode($expected)) . "\n";
        goto print_and_exit;
      }
      $checked++;
    }
  }
}
if ($checked != 2 * count($t14_curves) * count($t14_curves)) goto print_and_exit;
// f) set result
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
// a) CURVE25519 main key on the HEM, local X25519 peer (sodium), Z = X25519(local private, HEM public)
$main = t14_create($cfg_domain, $token_keygen, "CURVE25519", "T-14.2 CURVE25519 $run");
if ($main == false) goto print_and_exit;                    // expected is 200 with pubkey
list($main_kid, $main_pub) = $main;
$peer_priv = openssl_random_pseudo_bytes(32);
$peer_pub = sodium_crypto_scalarmult_base($peer_priv);
$z = sodium_crypto_scalarmult($peer_priv, $main_pub);
// b) CURVE25519 and ED25519 targets (OKM = private key / seed) and NIST targets from the X25519 secret
foreach (array('', openssl_random_pseudo_bytes(16)) as $salt) {
  foreach (array_merge(array("CURVE25519" => 32, "ED25519" => 32), array_fill_keys(array_keys($t14_curves), 0)) as $type => $size) {
    $label = "T-14.2 $type<CURVE25519 " . ($salt === '' ? "nosalt" : "salt") . " $run";
    $ret_val = t14_derive($cfg_domain, $token_keygen, $main_kid, $type, $peer_pub, $salt, $label);
    if ( !is_array($ret_val) ) { echo "ERROR: derive $label: HTTP $ret_val\n"; goto print_and_exit; }
    $info = "encedo-derive:v1:" . strtolower($type);
    if ($type == "CURVE25519") {
      $expected = sodium_crypto_scalarmult_base(hash_hkdf('sha512', $z, 32, $info, $salt));                                   // RFC 7748 clamping inside
    } else if ($type == "ED25519") {
      $expected = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(hash_hkdf('sha512', $z, 32, $info, $salt)));   // OKM is the RFC 8032 seed
    } else {
      $expected = t14_nist_pub($type, hash_hkdf('sha512', $z, $t14_curves[$type][2] + 8, $info, $salt));
    }
    if ( ($expected === false) || ($ret_val['pubkey'] !== base64_encode($expected)) ) {
      echo "ERROR: $label: HEM pubkey " . $ret_val['pubkey'] . ", local " . ($expected === false ? "-" : base64_encode($expected)) . "\n";
      goto print_and_exit;
    }
  }
}
// c) set result
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
// a) symmetric keys: derived on the HEM from a P-256 main key, used on the HEM, recomputed locally (OKM is the key)
$main = t14_create($cfg_domain, $token_keygen, "SECP256R1", "T-14.3 SECP256R1 $run");
if ($main == false) goto print_and_exit;                    // expected is 200 with pubkey
list($main_kid, $main_pub) = $main;
$peer = openssl_pkey_new(array_merge($t14_keyargs, array('curve_name' => "prime256v1")));
if ($peer === false) goto print_and_exit;
$peer_pub = t14_compress(openssl_pkey_get_details($peer)['ec'], 32);
$z = openssl_pkey_derive(t14_pem_pub("SECP256R1", $main_pub), $peer);
if ($z === false) goto print_and_exit;
$salt = openssl_random_pseudo_bytes(16);
$sym_types = array(   // HEM type => key size, local check (HMAC hash name or AES CBC cipher; DEV-481 B7: was ECB, off in the build)
  "SHA2-256" => array(32, "sha256"),   "SHA2-384" => array(48, "sha384"),   "SHA2-512" => array(64, "sha512"),
  "SHA3-256" => array(32, "sha3-256"), "SHA3-384" => array(48, "sha3-384"), "SHA3-512" => array(64, "sha3-512"),
  "AES128"   => array(16, "aes-128-cbc"), "AES192" => array(24, "aes-192-cbc"), "AES256" => array(32, "aes-256-cbc"),
);
$msg = openssl_random_pseudo_bytes(64);                       // multiple of the AES block size
foreach ($sym_types as $type => $sym) {
  $label = "T-14.3 $type<SECP256R1 $run";
  $ret_val = t14_derive($cfg_domain, $token_keygen, $main_kid, $type, $peer_pub, $salt, $label);
  if ( !is_array($ret_val) ) { echo "ERROR: derive $label: HTTP $ret_val\n"; goto print_and_exit; }
  $kid = $ret_val['kid'];
  $key = hash_hkdf('sha512', $z, $sym[0], "encedo-derive:v1:" . strtolower($type), $salt);
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid");
  if ($token == false) goto print_and_exit;                  // exit on error
  if (strpos($type, "AES") === 0) {
    $post_data = json_encode(array('kid' => $kid, 'msg' => base64_encode($msg), 'alg' => "$type-CBC"));   // DEV-481 (B7): CBC (was ECB)
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/encrypt", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;              // expected is 200 on success
    $hem = $ret_val['ciphertext'];
    $local = base64_encode(openssl_encrypt($msg, $sym[1], $key, OPENSSL_RAW_DATA, base64_decode($ret_val['iv'])));   // the IV made by HEM, PKCS#7 on both sides
  } else {
    $post_data = json_encode(array('kid' => $kid, 'msg' => base64_encode($msg)));
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/hash", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;              // expected is 200 on success
    $hem = $ret_val['mac'];
    $local = base64_encode(hash_hmac($sym[1], $msg, $key, true));
  }
  if ($hem !== $local) {
    echo "ERROR: $label: HEM $hem, local $local\n";
    goto print_and_exit;
  }
}
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
// DEV-481 (B5): HMAC SHA2 parents derived over ECDH from the 14.3 main key (known here), then
// a) POST /api/crypto/kdf HKDF / SP800-108 recomputed locally, bad input -> 400
// b) keymgmt/derive with the HMAC parent and no peer: child = HKDF-SHA512(parent, hkdf_salt, "encedo-derive:v1:<type>")
foreach (array("SHA2-256" => array(32, "sha256"), "SHA2-512" => array(64, "sha512")) as $ptype => $p) {
  $salt = openssl_random_pseudo_bytes(16);
  $label = "T-14.4 $ptype<SECP256R1 $run";
  $ret_val = t14_derive($cfg_domain, $token_keygen, $main_kid, $ptype, $peer_pub, $salt, $label);
  if ( !is_array($ret_val) ) { echo "ERROR: derive $label: HTTP $ret_val\n"; goto print_and_exit; }
  $parent_kid = $ret_val['kid'];
  $parent = hash_hkdf('sha512', $z, $p[0], "encedo-derive:v1:" . strtolower($ptype), $salt);
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$parent_kid");
  if ($token == false) goto print_and_exit;                  // exit on error
  // a) crypto/kdf
  foreach (array(16, 33, 128) as $len) {
    $kdf_salt = openssl_random_pseudo_bytes(20);
    $info = "tenant:$len:$run";
    $post_data = json_encode(array('kid' => $parent_kid, 'alg' => "HKDF", 'salt' => base64_encode($kdf_salt), 'info' => base64_encode($info), 'len' => $len));
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/kdf", $ret_val, $post_data, $token);
    if ( ($ret_stat != 200) || (base64_decode($ret_val['okm']) !== hash_hkdf($p[1], $parent, $len, $info, $kdf_salt)) ) { echo "ERROR: kdf HKDF $ptype len $len: HTTP $ret_stat\n"; goto print_and_exit; }
    $local = '';                                              // SP 800-108 counter mode: K(i) = HMAC(key, [i]32 || info || [L]32), L in bits
    for ($i = 1; strlen($local) < $len; $i++) $local .= hash_hmac($p[1], pack('N', $i) . "label\x00" . $info . pack('N', $len * 8), $parent, true);
    $post_data = json_encode(array('kid' => $parent_kid, 'alg' => "SP800-108", 'info' => base64_encode("label\x00" . $info), 'len' => $len));
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/kdf", $ret_val, $post_data, $token);
    if ( ($ret_stat != 200) || (base64_decode($ret_val['okm']) !== substr($local, 0, $len)) ) { echo "ERROR: kdf SP800-108 $ptype len $len: HTTP $ret_stat\n"; goto print_and_exit; }
  }
  foreach (array(array('alg' => "HKDF", 'len' => 15), array('alg' => "HKDF", 'len' => 129), array('alg' => "SP800-108", 'salt' => base64_encode("x"), 'len' => 32),
                 array('alg' => "HKDF", 'info' => base64_encode("encedo-x"), 'len' => 32), array('alg' => "x", 'len' => 32)) as $bad) {
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/kdf", $ret_val, json_encode(array_merge(array('kid' => $parent_kid), $bad)), $token);
    if ( $ret_stat != 400 ) { echo "ERROR: kdf " . json_encode($bad) . ": HTTP $ret_stat (400 expected)\n"; goto print_and_exit; }
  }
  // b) derive from the HMAC parent
  $msg = openssl_random_pseudo_bytes(64);
  foreach (array("AES256" => 32, "SHA2-512" => 64) as $type => $klen) {
    $child_salt = openssl_random_pseudo_bytes(16);
    $label = "T-14.4 $type<$ptype $run";
    $post_data = json_encode(array('kid' => $parent_kid, 'label' => $label, 'type' => $type, 'hkdf_salt' => base64_encode($child_salt), 'descr' => base64_encode("CCTEST:$label")));
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/derive", $ret_val, $post_data, $token_keygen);
    if ( $ret_stat != 200 ) { echo "ERROR: derive $label: HTTP $ret_stat\n"; goto print_and_exit; }
    $child_kid = $ret_val['kid'];
    $child = hash_hkdf('sha512', $parent, $klen, "encedo-derive:v1:" . strtolower($type), $child_salt);
    $token_child = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$child_kid");
    if ($token_child == false) goto print_and_exit;          // exit on error
    $ret_val = false;
    if ($type == "AES256") {
      $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/encrypt", $ret_val, json_encode(array('kid' => $child_kid, 'msg' => base64_encode($msg), 'alg' => "AES256-CBC")), $token_child);
      $ok = ($ret_stat == 200) && (base64_decode($ret_val['ciphertext']) === openssl_encrypt($msg, "aes-256-cbc", $child, OPENSSL_RAW_DATA, base64_decode($ret_val['iv'])));
    } else {
      $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/hash", $ret_val, json_encode(array('kid' => $child_kid, 'msg' => base64_encode($msg))), $token_child);
      $ok = ($ret_stat == 200) && (base64_decode($ret_val['mac']) === hash_hmac('sha512', $msg, $child, true));
    }
    if (!$ok) { echo "ERROR: $label: HEM result differs from the local one (HTTP $ret_stat)\n"; goto print_and_exit; }
  }
}
// c) derive without a peer from a key that is not HMAC SHA2 (the EC main key) -> 406
$post_data = json_encode(array('kid' => $main_kid, 'label' => "T-14.4 AES256<SECP256R1 nopeer $run", 'type' => "AES256", 'descr' => base64_encode("CCTEST:T-14.4")));
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/derive", $ret_val, $post_data, $token_keygen);
if ( $ret_stat != 406 ) { echo "ERROR: derive without a peer from an EC key: HTTP $ret_stat (406 expected)\n"; goto print_and_exit; }
// d) set result
$test_cfg['subtests'][4] = 'OK';                              // mark this subtest as OK
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
