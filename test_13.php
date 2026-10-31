<?php

include "libs/lib.php";
include "config.php";


// test name, descr & number of subtests
$test_name = "T-13";
$test_descr = "Attestation: JWT, key block, proof of possession";
$test_subtest_cnt = 6;


// initialize the execution env
init_env();
$test_cfg = init_test($test_name, $test_descr, $test_subtest_cnt, $cfg_tester);
if ( $cfg_debug ) var_dump( $cfg_domain );
$test_cfg['elapsed'] = hrtime(true);

// Windows PHP builds do not find openssl.cnf on their own - EC key generation fails without it
$t13_keyargs = array('private_key_type' => OPENSSL_KEYTYPE_EC);
$cnf = dirname(PHP_BINARY) . "\\extras\\ssl\\openssl.cnf";
if ( (getenv("OPENSSL_CONF") === false) && (PHP_OS_FAMILY == "Windows") && file_exists($cnf) ) {
  $t13_keyargs['config'] = $cnf;
}

echo "Processing...\n";


/////////////////////////////////////////////////////////////////////
// Local helpers (this test only)    ////////////////////////////////
/////////////////////////////////////////////////////////////////////
// FW 1.3.0 attestation (DEV-423, api_system.c attestation_jwt_sign / hem_canon_* / hem_pop_*), same as attest_verifier/attest_verify.php:
//   JWT ES256 signed by the ATECC608 attestation key, header: alg, typ "encedo-attest+jwt", kid = hex SHA-1(04||x||y), jwk (P-256)
//   PoP canonical message: length-prefixed (uint16 BE) fields
//     sig : "encedo-attest-pop:v1:sig"  | aud | pubkey | nonce                          (DEV-423: one field order, was aud | nonce | pubkey)
//     ecdh: "encedo-attest-pop:v1:ecdh" | aud | pubkey || nonce | verifier_eph_pub      (HKDF info = first 3 fields)
//     kem : "encedo-attest-pop:v1:kem"  | aud | pubkey || nonce | SHA-256(ciphertext)   (HKDF info = first 3 fields)
//   mac = HMAC-SHA256(key = HKDF-SHA256(ikm = shared secret, salt = nonce, info, 32), canonical)
// ML-DSA / ML-KEM need the OpenSSL >= 3.5 command line tool (the PHP openssl extension does not support them)
// DEV-423: no verifier_eph_pub_alg / ciphertext_alg (the key fixes the curve / level), no device.fws / bls, symmetric keys attested
// without PoP, PoP on a public-key-only key or a symmetric key -> 400
$t13_oid = array(  // HEM type => SubjectPublicKeyInfo algorithm (DER)
  "SECP256R1" => "06072a8648ce3d020106082a8648ce3d030107", "SECP384R1" => "06072a8648ce3d020106052b81040022",
  "SECP521R1" => "06072a8648ce3d020106052b81040023", "SECP256K1" => "06072a8648ce3d020106052b8104000a",
  "ED25519" => "06032b6570", "ED448" => "06032b6571", "CURVE25519" => "06032b656e", "CURVE448" => "06032b656f",
  "MLDSA44" => "0609608648016503040311", "MLDSA65" => "0609608648016503040312", "MLDSA87" => "0609608648016503040313",
  "MLKEM512" => "0609608648016503040401", "MLKEM768" => "0609608648016503040402", "MLKEM1024" => "0609608648016503040403",
);

function t13_der($tag, $body) {             // DER TLV, lengths up to 65535
  $len = strlen($body);
  if ($len < 0x80) return chr($tag) . chr($len) . $body;
  if ($len < 0x100) return chr($tag) . "\x81" . chr($len) . $body;
  return chr($tag) . "\x82" . chr($len >> 8) . chr($len & 0xff) . $body;
}

function t13_pem_pub($type, $raw) {         // raw public key (NIST: SEC1 point) -> SubjectPublicKeyInfo PEM
  global $t13_oid;
  $der = t13_der(0x30, t13_der(0x30, hex2bin($t13_oid[$type])) . t13_der(0x03, "\x00" . $raw));
  return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
}

function t13_rs2der($raw) {                 // ECDSA raw r||s -> DER
  $out = '';
  foreach (str_split($raw, intdiv(strlen($raw), 2)) as $i) {
    $i = ltrim($i, "\0");
    if (($i === '') || (ord($i[0]) & 0x80)) $i = "\0" . $i;
    $out .= t13_der(0x02, $i);
  }
  return t13_der(0x30, $out);
}

function t13_b64url_dec($s) {
  return base64_decode(strtr($s, '-_', '+/') . str_repeat('=', (4 - strlen($s) % 4) % 4));
}

function t13_cn($d) { return pack('n', strlen($d)) . $d; }

function t13_ossl($args) {                  // OpenSSL CLI (>= 3.5); returns true on exit code 0
  $bin = getenv("ENCEDO_OPENSSL") ? getenv("ENCEDO_OPENSSL") : "openssl";
  $cmd = escapeshellarg($bin);
  foreach ($args as $a) $cmd .= " " . escapeshellarg($a);
  exec($cmd . " 2>&1", $out, $rc);
  return ($rc == 0);
}

function t13_tmp($content) {
  $f = tempnam(sys_get_temp_dir(), "t13");
  file_put_contents($f, $content);
  return $f;
}

function t13_request($domain, $token, $req, &$jwt) {   // POST attestation; returns HTTP status, $jwt = token on 200
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $domain, "/api/system/config/attestation", $ret_val, json_encode($req, JSON_UNESCAPED_SLASHES), $token);
  $jwt = ( ($ret_stat == 200) && isset($ret_val['attestation']) ) ? $ret_val['attestation'] : false;
  return $ret_stat;
}

// checks header, device signature and claims; returns the decoded body or an error string
function t13_check_jwt($jwt, $aud, $nonce_b64) {
  $p = explode('.', $jwt);
  if (count($p) != 3) return "JWT is not compact serialization";
  $hdr = json_decode(t13_b64url_dec($p[0]), true);
  $body = json_decode(t13_b64url_dec($p[1]), true);
  $sig = t13_b64url_dec($p[2]);
  if ( !is_array($hdr) || !is_array($body) ) return "header/body not JSON";
  if ( (@$hdr['alg'] !== "ES256") || (@$hdr['typ'] !== "encedo-attest+jwt") ) return "header alg/typ " . json_encode($hdr);
  $jwk = @$hdr['jwk'];
  $x = t13_b64url_dec(@$jwk['x']);
  $y = t13_b64url_dec(@$jwk['y']);
  if ( (@$jwk['kty'] !== "EC") || (@$jwk['crv'] !== "P-256") || (strlen($x) != 32) || (strlen($y) != 32) ) return "header jwk " . json_encode($jwk);
  $point = "\x04" . $x . $y;
  if ( strtolower(@$hdr['kid']) !== sha1($point) ) return "header kid is not SHA-1(04||x||y) of jwk";
  if ( (strlen($sig) != 64) || (openssl_verify($p[0] . "." . $p[1], t13_rs2der($sig), t13_pem_pub("SECP256R1", $point), OPENSSL_ALGO_SHA256) !== 1) ) return "JWT signature (ES256) does not verify";
  if ( (@$body['aud'] !== $aud) || (@$body['nonce'] !== $nonce_b64) ) return "aud/nonce differ from the request";
  if ( !isset($body['iat'], $body['exp']) || ($body['exp'] <= $body['iat']) ) return "iat/exp";
  if ( !preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', @$body['jti']) ) return "jti is not UUID v4";
  if ( !isset($body['device']['hwv'], $body['device']['fwv']) ) return "device block";
  return $body;
}

// PoP MAC as computed by the verifier (ECDH-MAC and KEM-MAC)
function t13_pop_mac($pfx, $ss, $aud, $nonce, $pub, $last) {
  $info = t13_cn($pfx) . t13_cn($aud) . t13_cn($pub);
  return hash_hmac('sha256', $info . t13_cn($nonce) . t13_cn($last), hash_hkdf('sha256', $ss, 32, $info, $nonce), true);
}

function t13_create($domain, $token, $type, $mode, $label) {   // new key; returns array(kid, public key raw) or false
  $arg = array('label' => $label, 'type' => $type, 'descr' => base64_encode("CCTEST:" . $label));
  if ($mode) $arg['mode'] = $mode;
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $domain, "/api/keymgmt/create", $ret_val, json_encode($arg), $token);
  if ( ($ret_stat != 200) || !isset($ret_val['kid']) ) { echo "ERROR: create $type: HTTP $ret_stat\n"; return false; }
  $kid = $ret_val['kid'];
  $ret_val = false;
  $dummy_val = false;
  $ret_stat = http_transaction("https", "GET", $domain, "/api/keymgmt/get/$kid", $ret_val, $dummy_val, $token);
  if ( ($ret_stat != 200) || !isset($ret_val['pubkey']) ) { echo "ERROR: get $type: HTTP $ret_stat\n"; return false; }
  return array($kid, base64_decode($ret_val['pubkey']));
}

// DEV-423 rework: the full key matrix - name => array(type, mode, PoP methods that fit the key, expected modes)
$t13_matrix = array(
  "SECP256R1-ExDSA"   => array("SECP256R1",  "ExDSA",      array("sig"),         array("ExDSA")),
  "SECP384R1-ExDSA"   => array("SECP384R1",  "ExDSA",      array("sig"),         array("ExDSA")),
  "SECP521R1-ExDSA"   => array("SECP521R1",  "ExDSA",      array("sig"),         array("ExDSA")),
  "SECP256K1-ExDSA"   => array("SECP256K1",  "ExDSA",      array("sig"),         array("ExDSA")),
  "SECP256R1-ECDH"    => array("SECP256R1",  "ECDH",       array("ecdh"),        array("ECDH")),
  "SECP384R1-ECDH"    => array("SECP384R1",  "ECDH",       array("ecdh"),        array("ECDH")),
  "SECP521R1-ECDH"    => array("SECP521R1",  "ECDH",       array("ecdh"),        array("ECDH")),
  "SECP256K1-ECDH"    => array("SECP256K1",  "ECDH",       array("ecdh"),        array("ECDH")),
  "SECP256R1-both"    => array("SECP256R1",  "ECDH,ExDSA", array("sig", "ecdh"), array("ExDSA", "ECDH")),
  "SECP384R1-both"    => array("SECP384R1",  "ECDH,ExDSA", array("sig", "ecdh"), array("ExDSA", "ECDH")),
  "ED25519"           => array("ED25519",    "",           array("sig"),         array("ExDSA")),
  "ED25519-ECDH"      => array("ED25519",    "ECDH",       array("sig"),         array("ExDSA", "ECDH")),   // signature PoP only (one secret)
  "ED448"             => array("ED448",      "",           array("sig"),         array("ExDSA")),
  "CURVE25519"        => array("CURVE25519", "",           array("ecdh"),        array("ECDH")),
  "CURVE448"          => array("CURVE448",   "",           array("ecdh"),        array("ECDH")),
  "MLDSA44"           => array("MLDSA44",    "",           array("sig"),         array("MLDSA")),
  "MLDSA65"           => array("MLDSA65",    "",           array("sig"),         array("MLDSA")),
  "MLDSA87"           => array("MLDSA87",    "",           array("sig"),         array("MLDSA")),
  "MLKEM512"          => array("MLKEM512",   "",           array("kem"),         array("MLKEM")),
  "MLKEM768"          => array("MLKEM768",   "",           array("kem"),         array("MLKEM")),
  "MLKEM1024"         => array("MLKEM1024",  "",           array("kem"),         array("MLKEM")),
);
$t13_symmetric = array("SHA2-256" => "HMAC", "SHA2-384" => "HMAC", "SHA2-512" => "HMAC", "SHA3-256" => "HMAC", "SHA3-384" => "HMAC", "SHA3-512" => "HMAC",
                       "AES128" => "AES", "AES192" => "AES", "AES256" => "AES");
$t13_ec = array(  // NIST curve: PHP curve name, coordinate size, ECDSA hash of the signature PoP
  "SECP256R1" => array("prime256v1", 32, OPENSSL_ALGO_SHA256), "SECP384R1" => array("secp384r1", 48, OPENSSL_ALGO_SHA384),
  "SECP521R1" => array("secp521r1", 66, OPENSSL_ALGO_SHA512), "SECP256K1" => array("secp256k1", 32, OPENSSL_ALGO_SHA256),
);

function t13_create_any($domain, $token, $type, $mode, $label) {   // any key type; returns array(kid, public key raw or "")
  $arg = array('label' => $label, 'type' => $type, 'descr' => base64_encode("CCTEST:" . $label));
  if ($mode) $arg['mode'] = $mode;
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $domain, "/api/keymgmt/create", $ret_val, json_encode($arg), $token);
  if ( ($ret_stat != 200) || !isset($ret_val['kid']) ) { echo "ERROR: create $type: HTTP $ret_stat\n"; return false; }
  $kid = $ret_val['kid'];
  $ret_val = false;
  $dummy_val = false;
  $ret_stat = http_transaction("https", "GET", $domain, "/api/keymgmt/get/$kid", $ret_val, $dummy_val, $token);
  if ( $ret_stat != 200 ) { echo "ERROR: get $type: HTTP $ret_stat\n"; return false; }
  return array($kid, isset($ret_val['pubkey']) ? base64_decode($ret_val['pubkey']) : "");
}

function t13_sig_ok($type, $pub, $msg, $sig) {   // local verification of a signature PoP
  global $t13_ec;
  if ( isset($t13_ec[$type]) ) return (strlen($sig) == 2 * $t13_ec[$type][1]) && (openssl_verify($msg, t13_rs2der($sig), t13_pem_pub($type, $pub), $t13_ec[$type][2]) === 1);
  if ( $type == "ED25519" ) return sodium_crypto_sign_verify_detached($sig, $msg, $pub);
  return t13_ossl(array("pkeyutl", "-verify", "-pubin", "-inkey", t13_tmp(t13_pem_pub($type, $pub)), "-rawin", "-in", t13_tmp($msg), "-sigfile", t13_tmp($sig)));   // ED448, ML-DSA
}

function t13_eph($type, $pub) {   // verifier ephemeral key for ECDH-MAC: returns array(eph_pub in the request form, shared secret) or false
  global $t13_ec, $t13_keyargs;
  if ( isset($t13_ec[$type]) ) {
    $eph = openssl_pkey_new(array_merge($t13_keyargs, array('curve_name' => $t13_ec[$type][0])));
    if ($eph === false) return false;
    $ec = openssl_pkey_get_details($eph)['ec'];
    $eph_pub = ((ord(substr($ec['y'], -1)) & 1) ? "\x03" : "\x02") . str_pad($ec['x'], $t13_ec[$type][1], "\0", STR_PAD_LEFT);
    return array($eph_pub, openssl_pkey_derive(t13_pem_pub($type, $pub), $eph));
  }
  if ( $type == "CURVE25519" ) {
    $priv = openssl_random_pseudo_bytes(32);
    return array(sodium_crypto_scalarmult_base($priv), sodium_crypto_scalarmult($priv, $pub));
  }
  if ( $type == "CURVE448" ) {   // OpenSSL CLI: X448 key, raw public key = last 56 B of the SPKI, derive with the device key
    $f_priv = t13_tmp(""); $f_pub = t13_tmp(""); $f_ss = t13_tmp("");
    if ( !t13_ossl(array("genpkey", "-algorithm", "X448", "-out", $f_priv)) ) return false;
    if ( !t13_ossl(array("pkey", "-in", $f_priv, "-pubout", "-outform", "DER", "-out", $f_pub)) ) return false;
    if ( !t13_ossl(array("pkeyutl", "-derive", "-inkey", $f_priv, "-peerkey", t13_tmp(t13_pem_pub($type, $pub)), "-out", $f_ss)) ) return false;
    return array(substr(file_get_contents($f_pub), -56), file_get_contents($f_ss));
  }
  return false;
}

function t13_encap($type, $pub) {   // ML-KEM encapsulation (OpenSSL CLI): returns array(ciphertext, shared secret) or false
  $f_ct = t13_tmp(""); $f_ss = t13_tmp("");
  if ( !t13_ossl(array("pkeyutl", "-encap", "-pubin", "-inkey", t13_tmp(t13_pem_pub($type, $pub)), "-out", $f_ct, "-secret", $f_ss)) ) return false;
  return array(file_get_contents($f_ct), file_get_contents($f_ss));
}

function t13_key_token($domain, $password, $kid) { return helper_authorize($domain, $password, "keymgmt:use:$kid"); }


/////////////////////////////////////////////////////////////////////
// Subtest: 1        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST1:
echo "  subtest-1\n";
$test_cfg['subtests'][1] = 'ERROR';                         // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) get TOE status - discover correct domain, device must be initialised
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
// detect, get version details etc
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/version", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
$test_cfg['hwv'] = $ret_val['hwv'];                         //   or follow on with processing
$test_cfg['blv'] = @$ret_val['blv'];
$test_cfg['fwv'] = $ret_val['fwv'];
$test_cfg['conf'] = "ENCEDO PPA";
if ( strstr($ret_val['hwv'], "EPA") ) $test_cfg['conf'] = "ENCEDO EPA";
$t13_version = $ret_val;                                    // DEV-469: fwc / blc compared with the attestation fw_cid / bl_cid
$ret = helper_checkin($cfg_domain);
if ($ret == false) goto print_and_exit;                     // exit on error
// b) device attestation (no key): token of any scope, JWT checks, no key and pop block
$token_any = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:list");
if ($token_any == false) goto print_and_exit;               // exit on error
$aud = "encedo-cctest-t13";
$nonce = base64_encode(openssl_random_pseudo_bytes(32));
$ret_stat = t13_request($cfg_domain, $token_any, array('nonce' => $nonce, 'aud' => $aud), $jwt);
if ( $ret_stat != 200 ) { echo "ERROR: device attestation: HTTP $ret_stat\n"; goto print_and_exit; }
$body = t13_check_jwt($jwt, $aud, $nonce);
if ( !is_array($body) ) { echo "ERROR: device attestation: $body\n"; goto print_and_exit; }
if ( isset($body['key']) || isset($body['pop']) ) { echo "ERROR: device attestation has a key/pop block\n"; goto print_and_exit; }
if ( isset($body['device']['fws']) || isset($body['device']['bls']) || !isset($body['device']['policy']) ) { echo "ERROR: device block (DEV-423: no fws / bls, DEV-447: policy) " . json_encode($body['device']) . "\n"; goto print_and_exit; }
// DEV-469: the release CIDs (released builds only) are CIDv1 base32, the same as fwc / blc in /api/system/version
foreach (array('fw_cid' => 'fwc', 'bl_cid' => 'blc') as $f => $v) {
  if ( @$body['device'][$f] !== @$t13_version[$v] ) { echo "ERROR: device attestation $f differs from version $v\n"; goto print_and_exit; }
  if ( isset($body['device'][$f]) && !preg_match('/^b[a-z2-7]{58}$/', $body['device'][$f]) ) { echo "ERROR: $f is not a CIDv1 base32: " . $body['device'][$f] . "\n"; goto print_and_exit; }
}
$skid = sha1("\x04" . t13_b64url_dec(json_decode(t13_b64url_dec(explode('.', $jwt)[0]), true)['jwk']['x']) . t13_b64url_dec(json_decode(t13_b64url_dec(explode('.', $jwt)[0]), true)['jwk']['y']));
// c) the attestation key is the same in the next token, jti differs
$jti = $body['jti'];
$nonce = base64_encode(openssl_random_pseudo_bytes(32));
$ret_stat = t13_request($cfg_domain, $token_any, array('nonce' => $nonce, 'aud' => $aud), $jwt);
if ( $ret_stat != 200 ) goto print_and_exit;
$body = t13_check_jwt($jwt, $aud, $nonce);
if ( !is_array($body) ) { echo "ERROR: device attestation 2: $body\n"; goto print_and_exit; }
if ( $body['jti'] === $jti ) { echo "ERROR: jti repeated\n"; goto print_and_exit; }
if ( strtolower(json_decode(t13_b64url_dec(explode('.', $jwt)[0]), true)['kid']) !== $skid ) { echo "ERROR: attestation key changed\n"; goto print_and_exit; }
// d) set result
$test_cfg['subtests'][1] = 'OK';                            // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 2        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST2:
echo "  subtest-2\n";
$test_cfg['subtests'][2] = 'ERROR';                         // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) request validation: nonce 32..64 B, strict base64 (std alphabet, padding, canonical, no whitespace), aud printable up to 64 chars, both required
$cases = array(
  array(400, array('nonce' => base64_encode(str_repeat("n", 31)), 'aud' => $aud)),
  array(200, array('nonce' => base64_encode(str_repeat("n", 32)), 'aud' => $aud)),
  array(200, array('nonce' => base64_encode(str_repeat("n", 64)), 'aud' => $aud)),
  array(400, array('nonce' => base64_encode(str_repeat("n", 65)), 'aud' => $aud)),
  array(400, array('nonce' => "not base64!", 'aud' => $aud)),
  array(400, array('nonce' => strtr(base64_encode(str_repeat("\xfb\xff", 16)), '+/', '-_'), 'aud' => $aud)),   // base64url alphabet (std only)
  array(400, array('nonce' => rtrim(base64_encode(str_repeat("n", 32)), '='), 'aud' => $aud)),               // padding missing (len % 4)
  array(400, array('nonce' => substr(base64_encode(str_repeat("n", 32)), 0, -2) . "5=", 'aud' => $aud)),     // non-canonical: unused bits of the last char set
  array(400, array('nonce' => chunk_split(base64_encode(str_repeat("n", 48)), 16, "\n"), 'aud' => $aud)),    // whitespace inside (strict)
  array(400, array('aud' => $aud)),
  array(400, array('nonce' => base64_encode(str_repeat("n", 32)))),
  array(200, array('nonce' => base64_encode(str_repeat("n", 32)), 'aud' => str_repeat("a", 64))),
  array(400, array('nonce' => base64_encode(str_repeat("n", 32)), 'aud' => str_repeat("a", 65))),
  array(400, array('nonce' => base64_encode(str_repeat("n", 32)), 'aud' => $aud, 'kid' => str_repeat("g", 32))),   // KID not hex
);
foreach ($cases as $c) {
  $ret_stat = t13_request($cfg_domain, $token_any, $c[1], $jwt);
  if ( $ret_stat != $c[0] ) { echo "ERROR: request " . json_encode($c[1]) . ": HTTP $ret_stat (expected " . $c[0] . ")\n"; goto print_and_exit; }
}
// b) access control: no token -> 401 (initialised device)
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/system/config/attestation", $ret_val, json_encode(array('nonce' => $nonce, 'aud' => $aud)));
if ( $ret_stat != 401 ) { echo "ERROR: attestation without token: HTTP $ret_stat (expected 401)\n"; goto print_and_exit; }
// c) set result
$test_cfg['subtests'][2] = 'OK';                            // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 3        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST3:
echo "  subtest-3\n";
$test_cfg['subtests'][3] = 'ERROR';                         // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) test keys: the full matrix, all symmetric types, public-key-only imports
$token_keygen = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:gen");
$token_imp = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:imp");
if ( ($token_keygen == false) || ($token_imp == false) ) goto print_and_exit;
$run = bin2hex(openssl_random_pseudo_bytes(3));             // keeps labels unique between runs
$keys = array();
foreach ($t13_matrix as $name => $m) {
  $k = t13_create_any($cfg_domain, $token_keygen, $m[0], $m[1], "T-13 $name $run");
  if ( ($k == false) || ($k[1] === "") ) { echo "ERROR: key $name\n"; goto print_and_exit; }
  $keys[$name] = $k;
}
$sym = array();
foreach ($t13_symmetric as $type => $mode) {
  $k = t13_create_any($cfg_domain, $token_keygen, $type, "", "T-13 $type $run");
  if ($k == false) goto print_and_exit;
  $sym[$type] = $k;
}
$imported = array();                                        // public key only: P-256 (ExDSA) and ML-DSA-65, generated here (a key already in the HEM -> 409)
$p256 = openssl_pkey_get_details(openssl_pkey_new(array_merge($t13_keyargs, array('curve_name' => "prime256v1"))))['ec'];
$f_mldsa = t13_tmp(""); $f_mldsa_pub = t13_tmp("");
if ( !t13_ossl(array("genpkey", "-algorithm", "ML-DSA-65", "-out", $f_mldsa)) || !t13_ossl(array("pkey", "-in", $f_mldsa, "-pubout", "-outform", "DER", "-out", $f_mldsa_pub)) ) { echo "ERROR: local ML-DSA-65 key (OpenSSL >= 3.5 CLI needed)\n"; goto print_and_exit; }
$t13_imp_pub = array("SECP256R1" => ((ord(substr($p256['y'], -1)) & 1) ? "\x03" : "\x02") . str_pad($p256['x'], 32, "\0", STR_PAD_LEFT),
                     "MLDSA65" => substr(file_get_contents($f_mldsa_pub), -1952));
foreach (array("SECP256R1" => array("SECP256R1", "ExDSA"), "MLDSA65" => array("MLDSA65", "")) as $from => $t) {
  $keys["imp-$from"] = array("", $t13_imp_pub[$from]);
  $arg = array('type' => $t[0], 'label' => "T-13 imp $from $run", 'pubkey' => base64_encode($t13_imp_pub[$from]));
  if ($t[1]) $arg['mode'] = $t[1];
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/import", $ret_val, json_encode($arg), $token_imp);
  if ( ($ret_stat != 200) || !isset($ret_val['kid']) ) { echo "ERROR: import $from: HTTP $ret_stat\n"; goto print_and_exit; }
  $imported[$from] = array($ret_val['kid'], $t13_imp_pub[$from], $t[0]);
}
// b) key block of every asymmetric key: kid, type, modes, pubkey.primary = keymgmt/get, privatekey true, derived false; no pop
foreach ($t13_matrix as $name => $m) {
  list($kid, $pub) = $keys[$name];
  $token = t13_key_token($cfg_domain, $cfg_passpharse, $kid);
  $nonce = base64_encode(openssl_random_pseudo_bytes(32));
  if ( ($ret_stat = t13_request($cfg_domain, $token, array('nonce' => $nonce, 'aud' => $aud, 'kid' => $kid), $jwt)) != 200 ) { echo "ERROR: key attestation $name: HTTP $ret_stat\n"; goto print_and_exit; }
  $body = t13_check_jwt($jwt, $aud, $nonce);
  if ( !is_array($body) ) { echo "ERROR: key attestation $name: $body\n"; goto print_and_exit; }
  $key = @$body['key'];
  if ( (strtolower(@$key['kid']) !== $kid) || (@$key['type'] !== $m[0]) || (base64_decode(@$key['pubkey']['primary']) !== $pub) ) { echo "ERROR: key block $name: " . json_encode($key) . "\n"; goto print_and_exit; }
  if ( @$key['modes'] !== $m[3] ) { echo "ERROR: key block $name modes " . json_encode(@$key['modes']) . " (expected " . json_encode($m[3]) . ")\n"; goto print_and_exit; }
  if ( (@$key['properties']['privatekey'] !== true) || (@$key['properties']['derived'] !== false) || isset($body['pop']) ) { echo "ERROR: key block $name properties / pop " . json_encode($key) . "\n"; goto print_and_exit; }
}
// c) public-key-only imports: privatekey false, derived true
foreach ($imported as $from => $k) {
  $token = t13_key_token($cfg_domain, $cfg_passpharse, $k[0]);
  $nonce = base64_encode(openssl_random_pseudo_bytes(32));
  if ( ($ret_stat = t13_request($cfg_domain, $token, array('nonce' => $nonce, 'aud' => $aud, 'kid' => $k[0]), $jwt)) != 200 ) { echo "ERROR: import attestation $from: HTTP $ret_stat\n"; goto print_and_exit; }
  $key = @t13_check_jwt($jwt, $aud, $nonce)['key'];
  if ( (@$key['type'] !== $k[2]) || (base64_decode(@$key['pubkey']['primary']) !== $k[1]) || (@$key['properties']['privatekey'] !== false) || (@$key['properties']['derived'] !== true) ) { echo "ERROR: import key block $from: " . json_encode($key) . "\n"; goto print_and_exit; }
}
// d) symmetric keys: type, modes HMAC / AES, derived false, no pubkey / privatekey
foreach ($sym as $type => $k) {
  $token = t13_key_token($cfg_domain, $cfg_passpharse, $k[0]);
  $nonce = base64_encode(openssl_random_pseudo_bytes(32));
  if ( ($ret_stat = t13_request($cfg_domain, $token, array('nonce' => $nonce, 'aud' => $aud, 'kid' => $k[0]), $jwt)) != 200 ) { echo "ERROR: symmetric attestation $type: HTTP $ret_stat\n"; goto print_and_exit; }
  $key = @t13_check_jwt($jwt, $aud, $nonce)['key'];
  if ( (strtolower(@$key['kid']) !== $k[0]) || (@$key['type'] !== $type) || (@$key['modes'] !== array($t13_symmetric[$type])) || isset($key['pubkey']) || isset($key['properties']['privatekey']) || (@$key['properties']['derived'] !== false) ) { echo "ERROR: symmetric key block $type: " . json_encode($key) . "\n"; goto print_and_exit; }
}
// e) label / descr only with include_metadata (asymmetric and symmetric)
foreach (array("ED25519" => $keys["ED25519"][0], "AES256" => $sym["AES256"][0]) as $name => $kid) {
  $token = t13_key_token($cfg_domain, $cfg_passpharse, $kid);
  foreach (array(false, true) as $meta) {
    $nonce = base64_encode(openssl_random_pseudo_bytes(32));
    $req = array('nonce' => $nonce, 'aud' => $aud, 'kid' => $kid);
    if ($meta) $req['include_metadata'] = true;
    if ( t13_request($cfg_domain, $token, $req, $jwt) != 200 ) goto print_and_exit;
    $key = @t13_check_jwt($jwt, $aud, $nonce)['key'];
    if ( $meta != (isset($key['label']) && isset($key['descr'])) ) { echo "ERROR: $name label/descr with include_metadata " . json_encode($meta) . "\n"; goto print_and_exit; }
    if ( $meta && (($key['label'] !== "T-13 $name $run") || (base64_decode($key['descr']) !== "CCTEST:T-13 $name $run")) ) { echo "ERROR: $name label/descr values\n"; goto print_and_exit; }
  }
}
// f) a token of another scope is not enough for a key
if ( ($ret_stat = t13_request($cfg_domain, $token_any, array('nonce' => $nonce, 'aud' => $aud, 'kid' => $keys["ED25519"][0]), $jwt)) != 403 ) { echo "ERROR: key attestation with keymgmt:list token: HTTP $ret_stat (expected 403)\n"; goto print_and_exit; }
// g) set result
$test_cfg['subtests'][3] = 'OK';                            // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 4        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST4:
echo "  subtest-4\n";
$test_cfg['subtests'][4] = 'ERROR';                         // mark this subtest default as ERROR - initialization as subtest is ongoing
if ( !isset($keys) ) goto print_and_exit;                   // keys from subtest 3
// a) every PoP method that fits a key, verified locally (formats: see the helpers above)
foreach ($t13_matrix as $name => $m) {
  list($kid, $pub) = $keys[$name];
  $type = $m[0];
  $token = t13_key_token($cfg_domain, $cfg_passpharse, $kid);
  foreach ($m[2] as $method) {
    $nonce_raw = openssl_random_pseudo_bytes(32);
    $req = array('nonce' => base64_encode($nonce_raw), 'aud' => $aud, 'kid' => $kid);
    if ($method == "sig") {
      $req['pop_args'] = new stdClass();
    } else if ($method == "ecdh") {
      $e = t13_eph($type, $pub);
      if ($e === false) { echo "ERROR: local ephemeral key for $name\n"; goto print_and_exit; }
      $req['pop_args'] = array('verifier_eph_pub' => base64_encode($e[0]));
    } else {
      $e = t13_encap($type, $pub);
      if ($e === false) { echo "ERROR: local ML-KEM encapsulation for $name (OpenSSL >= 3.5 CLI needed)\n"; goto print_and_exit; }
      $req['pop_args'] = array('ciphertext' => base64_encode($e[0]));
    }
    if ( ($ret_stat = t13_request($cfg_domain, $token, $req, $jwt)) != 200 ) { echo "ERROR: PoP $method $name: HTTP $ret_stat\n"; goto print_and_exit; }
    $body = t13_check_jwt($jwt, $aud, base64_encode($nonce_raw));
    if ( !is_array($body) ) { echo "ERROR: PoP $method $name: $body\n"; goto print_and_exit; }
    if ($method == "sig") {
      $msg = t13_cn("encedo-attest-pop:v1:sig") . t13_cn($aud) . t13_cn($pub) . t13_cn($nonce_raw);   // DEV-423: prefix | aud | pubkey | nonce
      if ( !t13_sig_ok($type, $pub, $msg, base64_decode(@$body['pop']['signature'])) ) { echo "ERROR: PoP sig $name: signature does not verify\n"; goto print_and_exit; }
    } else if ($method == "ecdh") {
      if ( base64_decode(@$body['pop']['mac']) !== t13_pop_mac("encedo-attest-pop:v1:ecdh", $e[1], $aud, $nonce_raw, $pub, $e[0]) ) { echo "ERROR: PoP ECDH $name: mac differs\n"; goto print_and_exit; }
    } else {
      if ( base64_decode(@$body['pop']['mac']) !== t13_pop_mac("encedo-attest-pop:v1:kem", $e[1], $aud, $nonce_raw, $pub, hash('sha256', $e[0], true)) ) { echo "ERROR: PoP KEM $name: mac differs\n"; goto print_and_exit; }
    }
  }
}
// b) set result
$test_cfg['subtests'][4] = 'OK';                            // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 5        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST5:
echo "  subtest-5\n";
$test_cfg['subtests'][5] = 'ERROR';                         // mark this subtest default as ERROR - initialization as subtest is ongoing
if ( !isset($keys) ) goto print_and_exit;                   // keys from subtest 3
// a) strict PoP: pop_args that do not fit the key -> 400, never a token without pop
$x25519_pub = base64_encode(sodium_crypto_scalarmult_base(openssl_random_pseudo_bytes(32)));
$args = array("sig" => new stdClass(), "ecdh" => array('verifier_eph_pub' => $x25519_pub), "kem" => array('ciphertext' => base64_encode(str_repeat("c", 1088))));
$cases = array();
foreach ($t13_matrix as $name => $m) {
  foreach ($args as $method => $a) if ( !in_array($method, $m[2]) ) $cases[] = array($keys[$name][0], $a, "$name: $method");
}
$cases[] = array(null, new stdClass(), "pop_args without kid");
$cases[] = array($keys["SECP256R1-ECDH"][0], array('verifier_eph_pub' => base64_encode(str_repeat("\x02", 32))), "SECP256R1-ECDH: eph pub 32 B (33 B expected)");
$cases[] = array($keys["CURVE448"][0], array('verifier_eph_pub' => $x25519_pub), "CURVE448: eph pub 32 B (56 B expected)");
$cases[] = array($keys["MLKEM768"][0], array('ciphertext' => base64_encode(str_repeat("c", 1087))), "MLKEM768: ciphertext 1087 B");
$cases[] = array($keys["MLKEM512"][0], array('ciphertext' => base64_encode(str_repeat("c", 1088))), "MLKEM512: ciphertext 1088 B (768 expected)");
foreach ($imported as $from => $k) $cases[] = array($k[0], new stdClass(), "public key only ($from): signature PoP");
foreach ($sym as $type => $k) $cases[] = array($k[0], new stdClass(), "symmetric $type: PoP");
foreach ($cases as $c) {
  $req = array('nonce' => base64_encode(openssl_random_pseudo_bytes(32)), 'aud' => $aud, 'pop_args' => $c[1]);
  $token = $token_any;
  if ($c[0] !== null) {
    $req['kid'] = $c[0];
    $token = t13_key_token($cfg_domain, $cfg_passpharse, $c[0]);
  }
  if ( ($ret_stat = t13_request($cfg_domain, $token, $req, $jwt)) != 400 ) { echo "ERROR: strict PoP " . $c[2] . ": HTTP $ret_stat (expected 400)\n"; goto print_and_exit; }
}
// b) set result
$test_cfg['subtests'][5] = 'OK';                            // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 6        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST6:
echo "  subtest-6\n";
$test_cfg['subtests'][6] = 'ERROR';                         // mark this subtest default as ERROR - initialization as subtest is ongoing
// DEV-474: GET /api/system/config/attestation[/<nonce_base64url>] - genuine token bound to the caller's nonce:
//   without the segment: <SKID>.<TS>.<SIG> (SIG over SHA-256 of the decimal TS text) - unchanged
//   with it: <nonce>.<SKID>.<TS>.<SIG>, SIG = ECDSA P-256 (DER, base64) over SHA-256("<nonce>.<SKID>.<TS>"), device key of the certificate
$token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:list");
if ($token == false) goto print_and_exit;
$not_used = false;
// a) without a nonce: three parts, device certificate present
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/config/attestation", $ret_val, $not_used, $token);
if ( ($ret_stat != 200) || !isset($ret_val['crt']) || !isset($ret_val['genuine']) ) { echo "ERROR: GET attestation: HTTP $ret_stat\n"; goto print_and_exit; }
$crt_pem = "-----BEGIN CERTIFICATE-----\n" . chunk_split($ret_val['crt'], 64, "\n") . "-----END CERTIFICATE-----\n";
$dev_pub = openssl_pkey_get_public($crt_pem);
if ($dev_pub === false) { echo "ERROR: device certificate does not parse\n"; goto print_and_exit; }
$ec = openssl_pkey_get_details($dev_pub)['ec'];
$skid = base64_encode(sha1("\x04" . str_pad($ec['x'], 32, "\0", STR_PAD_LEFT) . str_pad($ec['y'], 32, "\0", STR_PAD_LEFT), true));
$p = explode('.', $ret_val['genuine']);
if ( (count($p) != 3) || ($p[0] !== $skid) ) { echo "ERROR: genuine without nonce: " . $ret_val['genuine'] . "\n"; goto print_and_exit; }
if ( openssl_verify(base64_decode($p[1]), base64_decode($p[2]), $dev_pub, OPENSSL_ALGO_SHA256) !== 1 ) { echo "ERROR: genuine without nonce: signature over the TS does not verify\n"; goto print_and_exit; }
// b) with a nonce (32 and 64 B): four parts, nonce first, signature over "<nonce>.<SKID>.<TS>"
foreach (array(32, 64) as $nlen) {
  $nonce = rtrim(strtr(base64_encode(openssl_random_pseudo_bytes($nlen)), '+/', '-_'), '=');
  $ret_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/config/attestation/$nonce", $ret_val, $not_used, $token);
  if ( ($ret_stat != 200) || !isset($ret_val['genuine']) ) { echo "ERROR: GET attestation/<nonce $nlen B>: HTTP $ret_stat\n"; goto print_and_exit; }
  $p = explode('.', $ret_val['genuine']);
  if ( (count($p) != 4) || ($p[0] !== $nonce) || ($p[1] !== $skid) ) { echo "ERROR: genuine with nonce: " . $ret_val['genuine'] . "\n"; goto print_and_exit; }
  if ( intval(base64_decode($p[2])) < time() - 600 ) { echo "ERROR: genuine with nonce: TS " . base64_decode($p[2]) . "\n"; goto print_and_exit; }
  if ( openssl_verify($p[0] . "." . $p[1] . "." . $p[2], base64_decode($p[3]), $dev_pub, OPENSSL_ALGO_SHA256) !== 1 ) { echo "ERROR: genuine with nonce ($nlen B): signature does not verify\n"; goto print_and_exit; }
  // the signature binds the nonce: another nonce with the same SKID / TS / SIG does not verify
  if ( openssl_verify(strrev($p[0]) . "." . $p[1] . "." . $p[2], base64_decode($p[3]), $dev_pub, OPENSSL_ALGO_SHA256) === 1 ) { echo "ERROR: genuine signature does not bind the nonce\n"; goto print_and_exit; }
}
// c) bad nonce -> 400: 31 / 65 B, padding, standard alphabet, not base64
$n32 = openssl_random_pseudo_bytes(32);
foreach (array("31 B" => rtrim(strtr(base64_encode(openssl_random_pseudo_bytes(31)), '+/', '-_'), '='),
               "65 B" => rtrim(strtr(base64_encode(openssl_random_pseudo_bytes(65)), '+/', '-_'), '='),
               "padding" => strtr(base64_encode(openssl_random_pseudo_bytes(32)), '+/', '-_'),
               "std alphabet" => rtrim(base64_encode(str_repeat("\xfb\xff", 16)), '='),
               "not base64" => str_repeat("*", 43),
               "empty" => "") as $what => $nonce) {
  $ret_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/config/attestation/$nonce", $ret_val, $not_used, $token);
  if ( $ret_stat != 400 ) { echo "ERROR: GET attestation/<nonce $what>: HTTP $ret_stat (expected 400)\n"; goto print_and_exit; }
}
// d) set result
$test_cfg['subtests'][6] = 'OK';                            // mark this subtest as OK
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
