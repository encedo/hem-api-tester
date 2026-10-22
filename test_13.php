<?php

include "libs/lib.php";
include "config.php";


// test name, descr & number of subtests
$test_name = "T-13";
$test_descr = "Attestation (POST /api/system/config/attestation): JWT, key block, proof of possession";
$test_subtest_cnt = 5;


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
//     sig : "encedo-attest-pop:v1:sig"  | aud | nonce | pubkey
//     ecdh: "encedo-attest-pop:v1:ecdh" | aud | pubkey || nonce | verifier_eph_pub      (HKDF info = first 3 fields)
//     kem : "encedo-attest-pop:v1:kem"  | aud | pubkey || nonce | SHA-256(ciphertext)   (HKDF info = first 3 fields)
//   mac = HMAC-SHA256(key = HKDF-SHA256(ikm = shared secret, salt = nonce, info, 32), canonical)
// ML-DSA / ML-KEM need the OpenSSL >= 3.5 command line tool (the PHP openssl extension does not support them)
$t13_oid = array(  // HEM type => SubjectPublicKeyInfo algorithm (DER)
  "SECP256R1" => "06072a8648ce3d020106082a8648ce3d030107",
  "MLDSA65"   => "0609608648016503040312",
  "MLKEM768"  => "0609608648016503040402",
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
if ( isset($ret_val['hostname']) ) {                       // remap domain name to the correct one
  $cfg_domain = $ret_val['hostname'];
}
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
// a) request validation: nonce 16..64 B, aud printable up to 64 chars, both required
$cases = array(
  array(400, array('nonce' => base64_encode(str_repeat("n", 15)), 'aud' => $aud)),
  array(200, array('nonce' => base64_encode(str_repeat("n", 16)), 'aud' => $aud)),
  array(200, array('nonce' => base64_encode(str_repeat("n", 64)), 'aud' => $aud)),
  array(400, array('nonce' => base64_encode(str_repeat("n", 65)), 'aud' => $aud)),
  array(400, array('nonce' => "not base64!", 'aud' => $aud)),
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
// a) test keys: one per PoP method
$token_keygen = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:gen");
if ($token_keygen == false) goto print_and_exit;            // exit on error
$run = bin2hex(openssl_random_pseudo_bytes(3));             // keeps labels unique between runs
$keys = array();
foreach (array("ED25519" => "", "SECP256R1" => "ExDSA", "MLDSA65" => "", "CURVE25519" => "", "SECP256R1-ECDH" => "ECDH", "MLKEM768" => "") as $name => $mode) {
  $type = explode("-", $name)[0];
  $k = t13_create($cfg_domain, $token_keygen, $type, $mode, "T-13 $name $run");
  if ($k == false) goto print_and_exit;
  $keys[$name] = $k;
}
// b) key block: kid and public key; label/descr only with include_metadata; the key access scope is required
foreach (array(false, true) as $meta) {
  list($kid, $pub) = $keys["ED25519"];
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid");
  if ($token == false) goto print_and_exit;
  $nonce = base64_encode(openssl_random_pseudo_bytes(32));
  $req = array('nonce' => $nonce, 'aud' => $aud, 'kid' => $kid);
  if ($meta) $req['include_metadata'] = true;
  $ret_stat = t13_request($cfg_domain, $token, $req, $jwt);
  if ( $ret_stat != 200 ) { echo "ERROR: key attestation (metadata " . json_encode($meta) . "): HTTP $ret_stat\n"; goto print_and_exit; }
  $body = t13_check_jwt($jwt, $aud, $nonce);
  if ( !is_array($body) ) { echo "ERROR: key attestation: $body\n"; goto print_and_exit; }
  $key = @$body['key'];
  if ( !is_array($key) || (strtolower(@$key['kid']) !== $kid) || (base64_decode(@$key['pubkey']['primary']) !== $pub) ) { echo "ERROR: key block " . json_encode($key) . "\n"; goto print_and_exit; }
  if ( isset($body['pop']) ) { echo "ERROR: pop without pop_args\n"; goto print_and_exit; }
  if ( $meta != (isset($key['label']) && isset($key['descr'])) ) { echo "ERROR: label/descr with include_metadata " . json_encode($meta) . ": " . json_encode($key) . "\n"; goto print_and_exit; }
  if ( $meta && (($key['label'] !== "T-13 ED25519 $run") || (base64_decode($key['descr']) !== "CCTEST:T-13 ED25519 $run")) ) { echo "ERROR: label/descr values: " . json_encode($key) . "\n"; goto print_and_exit; }
}
// c) a token of another scope is not enough for a key
$ret_stat = t13_request($cfg_domain, $token_any, array('nonce' => $nonce, 'aud' => $aud, 'kid' => $keys["ED25519"][0]), $jwt);
if ( $ret_stat != 403 ) { echo "ERROR: key attestation with keymgmt:list token: HTTP $ret_stat (expected 403)\n"; goto print_and_exit; }
// d) set result
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
// a) PoP by signature (pop_args = {}): ED25519, ECDSA P-256, ML-DSA-65
foreach (array("ED25519", "SECP256R1", "MLDSA65") as $name) {
  list($kid, $pub) = $keys[$name];
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid");
  if ($token == false) goto print_and_exit;
  $nonce_raw = openssl_random_pseudo_bytes(32);
  $ret_stat = t13_request($cfg_domain, $token, array('nonce' => base64_encode($nonce_raw), 'aud' => $aud, 'kid' => $kid, 'pop_args' => new stdClass()), $jwt);
  if ( $ret_stat != 200 ) { echo "ERROR: PoP sig $name: HTTP $ret_stat\n"; goto print_and_exit; }
  $body = t13_check_jwt($jwt, $aud, base64_encode($nonce_raw));
  if ( !is_array($body) ) { echo "ERROR: PoP sig $name: $body\n"; goto print_and_exit; }
  $sig = base64_decode(@$body['pop']['signature']);
  $msg = t13_cn("encedo-attest-pop:v1:sig") . t13_cn($aud) . t13_cn($nonce_raw) . t13_cn($pub);
  if ($name == "ED25519") $ok = sodium_crypto_sign_verify_detached($sig, $msg, $pub);
  else if ($name == "SECP256R1") $ok = (openssl_verify($msg, t13_rs2der($sig), t13_pem_pub($name, $pub), OPENSSL_ALGO_SHA256) === 1);
  else $ok = t13_ossl(array("pkeyutl", "-verify", "-pubin", "-inkey", t13_tmp(t13_pem_pub($name, $pub)), "-rawin", "-in", t13_tmp($msg), "-sigfile", t13_tmp($sig)));
  if ( !$ok ) { echo "ERROR: PoP sig $name: signature does not verify\n"; goto print_and_exit; }
}
// b) PoP by ECDH-MAC: CURVE25519 and P-256 ECDH-only, verifier ephemeral key made here
foreach (array("CURVE25519", "SECP256R1-ECDH") as $name) {
  list($kid, $pub) = $keys[$name];
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid");
  if ($token == false) goto print_and_exit;
  if ($name == "CURVE25519") {
    $eph_priv = openssl_random_pseudo_bytes(32);
    $eph_pub = sodium_crypto_scalarmult_base($eph_priv);
    $ss = sodium_crypto_scalarmult($eph_priv, $pub);
    $alg = "CURVE25519";
  } else {
    $eph = openssl_pkey_new(array_merge($t13_keyargs, array('curve_name' => "prime256v1")));
    $ec = openssl_pkey_get_details($eph)['ec'];
    $eph_pub = ((ord(substr($ec['y'], -1)) & 1) ? "\x03" : "\x02") . str_pad($ec['x'], 32, "\0", STR_PAD_LEFT);
    $ss = openssl_pkey_derive(t13_pem_pub("SECP256R1", $pub), $eph);
    $alg = "SECP256R1";
  }
  $nonce_raw = openssl_random_pseudo_bytes(32);
  $ret_stat = t13_request($cfg_domain, $token, array('nonce' => base64_encode($nonce_raw), 'aud' => $aud, 'kid' => $kid, 'pop_args' => array('verifier_eph_pub' => base64_encode($eph_pub), 'verifier_eph_pub_alg' => $alg)), $jwt);
  if ( $ret_stat != 200 ) { echo "ERROR: PoP ECDH $name: HTTP $ret_stat\n"; goto print_and_exit; }
  $body = t13_check_jwt($jwt, $aud, base64_encode($nonce_raw));
  if ( !is_array($body) ) { echo "ERROR: PoP ECDH $name: $body\n"; goto print_and_exit; }
  if ( base64_decode(@$body['pop']['mac']) !== t13_pop_mac("encedo-attest-pop:v1:ecdh", $ss, $aud, $nonce_raw, $pub, $eph_pub) ) { echo "ERROR: PoP ECDH $name: mac differs\n"; goto print_and_exit; }
}
// c) PoP by KEM-MAC: ML-KEM-768, encapsulation here with the key's public key
list($kid, $pub) = $keys["MLKEM768"];
$token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid");
if ($token == false) goto print_and_exit;
$f_ct = t13_tmp("");
$f_ss = t13_tmp("");
if ( !t13_ossl(array("pkeyutl", "-encap", "-pubin", "-inkey", t13_tmp(t13_pem_pub("MLKEM768", $pub)), "-out", $f_ct, "-secret", $f_ss)) ) { echo "ERROR: local ML-KEM encapsulation (OpenSSL >= 3.5 CLI needed)\n"; goto print_and_exit; }
$ct = file_get_contents($f_ct);
$ss = file_get_contents($f_ss);
$nonce_raw = openssl_random_pseudo_bytes(32);
$ret_stat = t13_request($cfg_domain, $token, array('nonce' => base64_encode($nonce_raw), 'aud' => $aud, 'kid' => $kid, 'pop_args' => array('ciphertext' => base64_encode($ct), 'ciphertext_alg' => "MLKEM768")), $jwt);
if ( $ret_stat != 200 ) { echo "ERROR: PoP KEM: HTTP $ret_stat\n"; goto print_and_exit; }
$body = t13_check_jwt($jwt, $aud, base64_encode($nonce_raw));
if ( !is_array($body) ) { echo "ERROR: PoP KEM: $body\n"; goto print_and_exit; }
if ( base64_decode(@$body['pop']['mac']) !== t13_pop_mac("encedo-attest-pop:v1:kem", $ss, $aud, $nonce_raw, $pub, hash('sha256', $ct, true)) ) { echo "ERROR: PoP KEM: mac differs\n"; goto print_and_exit; }
// d) set result
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
// a) strict PoP: pop_args that do not fit the key (or no kid) -> 400, never a token without pop
$x25519_pub = base64_encode(sodium_crypto_scalarmult_base(openssl_random_pseudo_bytes(32)));
$cases = array(
  array("ED25519",        array()),                                                                               // no kid
  array("CURVE25519",     new stdClass()),                                                                        // {} for an ECDH-only key
  array("SECP256R1-ECDH", new stdClass()),
  array("CURVE25519",     array('ciphertext' => base64_encode(str_repeat("c", 1088)), 'ciphertext_alg' => "MLKEM768")),
  array("MLDSA65",        array('verifier_eph_pub' => $x25519_pub, 'verifier_eph_pub_alg' => "CURVE25519")),
  array("MLKEM768",       new stdClass()),
  array("CURVE25519",     array('verifier_eph_pub' => $x25519_pub, 'verifier_eph_pub_alg' => "CURVE448")),    // wrong alg
  array("MLKEM768",       array('ciphertext' => base64_encode(str_repeat("c", 1087)), 'ciphertext_alg' => "MLKEM768")),   // wrong length
);
foreach ($cases as $i => $c) {
  list($kid, $pub) = $keys[$c[0]];
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid");
  if ($token == false) goto print_and_exit;
  $req = array('nonce' => base64_encode(openssl_random_pseudo_bytes(32)), 'aud' => $aud, 'pop_args' => $c[1]);
  if ($i > 0) $req['kid'] = $kid;
  $ret_stat = t13_request($cfg_domain, $token, $req, $jwt);
  if ( $ret_stat != 400 ) { echo "ERROR: strict PoP case $i (" . $c[0] . "): HTTP $ret_stat (expected 400)\n"; goto print_and_exit; }
}
// b) set result
$test_cfg['subtests'][5] = 'OK';                            // mark this subtest as OK
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
