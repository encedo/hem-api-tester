<?php
/////////////////////////////////////////////////////////////////////
// hpke.php - host side HPKE (RFC 9180), Base mode only, reference for the HEM HPKE API tests
// Written from RFC 9180, draft-connolly-cfrg-xwing-kem-11 and draft-ietf-hpke-pq-05 only (no device code).
// Self test against the official vectors: php tools/hpke_selftest.php
//
// KEM  0x0010 DHKEM(P-256, HKDF-SHA256)   0x0011 DHKEM(P-384, HKDF-SHA384)   0x0012 DHKEM(P-521, HKDF-SHA512)
//      0x0020 DHKEM(X25519, HKDF-SHA256)  0x0021 DHKEM(X448, HKDF-SHA512)
//      0x0040 ML-KEM-512  0x0041 ML-KEM-768  0x0042 ML-KEM-1024  0x647A X-Wing (ML-KEM-768 + X25519)
// KDF  0x0001 HKDF-SHA256  0x0002 HKDF-SHA384  0x0003 HKDF-SHA512
// AEAD 0x0001 AES-128-GCM  0x0002 AES-256-GCM  0x0003 ChaCha20-Poly1305  0xFFFF export only
//
// All keys / data are raw byte strings. Keys are in the RFC serialized form:
//   pk: NIST 0x04 || X || Y, X25519/X448 raw, ML-KEM encapsulation key, X-Wing pk_M (1184) || pk_X (32)
//   sk: NIST big-endian scalar (32/48/66 B), X25519/X448 raw, ML-KEM 64 B seed d || z, X-Wing 32 B seed
// NIST curves / X448 via ext openssl (raw key import, no openssl.cnf needed), X25519 via ext sodium,
// ML-KEM and SHAKE256 via the OpenSSL CLI >= 3.5 (env ENCEDO_OPENSSL, else "openssl").
//
// API (every function returns false on any error):
//   hpke_keygen($kem)                                               -> array('sk', 'pk')
//   hpke_derive_keypair($kem, $ikm)                                 -> array('sk', 'pk')    DeriveKeyPair (RFC 9180 7.1.3 / hpke-pq)
//   hpke_pk($kem, $sk)                                              -> pk of a private key
//   hpke_seal($kem, $kdf, $aead, $pkR, $info, $aad, $pt)            -> array('enc', 'ct')   single shot, seq 0
//   hpke_open($kem, $kdf, $aead, $skR, $enc, $info, $aad, $ct)      -> pt
//   hpke_export_s($kem, $kdf, $pkR, $info, $exp_ctx, $L)            -> array('enc', 'secret')   AEAD 0xFFFF
//   hpke_export_r($kem, $kdf, $skR, $enc, $info, $exp_ctx, $L)      -> secret                   AEAD 0xFFFF
// Context level (used by the above; the self test uses it with a fixed ephemeral key):
//   hpke_setup_s($kem, $kdf, $aead, $pkR, $info, $skE = false)      -> ctx: enc, shared_secret, key_schedule_context, secret, key, base_nonce, exporter_secret
//   hpke_setup_r($kem, $kdf, $aead, $skR, $enc, $info)              -> ctx (the same fields)
//   hpke_ctx_seal($ctx, $seq, $aad, $pt) / hpke_ctx_open($ctx, $seq, $aad, $ct) / hpke_ctx_export($ctx, $exp_ctx, $L)
//   hpke_encap($kem, $pkR, $skE = false) -> array('shared_secret', 'enc');  hpke_decap($kem, $enc, $skR) -> shared_secret
//   $skE (testing hook): fixed ephemeral private key for the DHKEMs; the ML-KEM KEMs are always randomized (CLI)
/////////////////////////////////////////////////////////////////////

// KEM parameters; false if not supported
function hpke_kem($kem) {
  $p256 = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
  $p384 = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
  $p521 = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
  switch ($kem) {
    case 0x0010: return array('type' => 'ec', 'curve' => 'prime256v1', 'hash' => 'sha256', 'Nsecret' => 32, 'Nenc' => 65, 'Npk' => 65, 'Nsk' => 32, 'order' => hex2bin($p256), 'mask' => 0xff);
    case 0x0011: return array('type' => 'ec', 'curve' => 'secp384r1', 'hash' => 'sha384', 'Nsecret' => 48, 'Nenc' => 97, 'Npk' => 97, 'Nsk' => 48, 'order' => hex2bin($p384), 'mask' => 0xff);
    case 0x0012: return array('type' => 'ec', 'curve' => 'secp521r1', 'hash' => 'sha512', 'Nsecret' => 64, 'Nenc' => 133, 'Npk' => 133, 'Nsk' => 66, 'order' => hex2bin($p521), 'mask' => 0x01);
    case 0x0020: return array('type' => 'x25519', 'hash' => 'sha256', 'Nsecret' => 32, 'Nenc' => 32, 'Npk' => 32, 'Nsk' => 32);
    case 0x0021: return array('type' => 'x448', 'hash' => 'sha512', 'Nsecret' => 64, 'Nenc' => 56, 'Npk' => 56, 'Nsk' => 56);
    case 0x0040: return array('type' => 'mlkem', 'oid' => 1, 'Nsecret' => 32, 'Nenc' => 768, 'Npk' => 800, 'Nsk' => 64);
    case 0x0041: return array('type' => 'mlkem', 'oid' => 2, 'Nsecret' => 32, 'Nenc' => 1088, 'Npk' => 1184, 'Nsk' => 64);
    case 0x0042: return array('type' => 'mlkem', 'oid' => 3, 'Nsecret' => 32, 'Nenc' => 1568, 'Npk' => 1568, 'Nsk' => 64);
    case 0x647A: return array('type' => 'xwing', 'Nsecret' => 32, 'Nenc' => 1120, 'Npk' => 1216, 'Nsk' => 32);
  }
  return false;
}

// KDF hash name and Nh; false if not supported
function hpke_kdf($kdf) {
  switch ($kdf) {
    case 0x0001: return array('hash' => 'sha256', 'Nh' => 32);
    case 0x0002: return array('hash' => 'sha384', 'Nh' => 48);
    case 0x0003: return array('hash' => 'sha512', 'Nh' => 64);
  }
  return false;
}

// AEAD Nk / Nn (Nt is 16 for all three); false if not supported
function hpke_aead($aead) {
  switch ($aead) {
    case 0x0001: return array('cipher' => 'aes-128-gcm', 'Nk' => 16, 'Nn' => 12);
    case 0x0002: return array('cipher' => 'aes-256-gcm', 'Nk' => 32, 'Nn' => 12);
    case 0x0003: return array('cipher' => 'chacha20-poly1305', 'Nk' => 32, 'Nn' => 12);
    case 0xFFFF: return array('cipher' => 'export-only', 'Nk' => 0, 'Nn' => 0);
  }
  return false;
}

/////////////////////////////////////////////////////////////////////
// Labeled HKDF (RFC 9180 4)

// suite_id of the KEM ("KEM" || kem_id) and of the whole HPKE suite ("HPKE" || kem_id || kdf_id || aead_id)
function hpke_suite_kem($kem) {
  return "KEM" . pack("n", $kem);
}

function hpke_suite($kem, $kdf, $aead) {
  return "HPKE" . pack("nnn", $kem, $kdf, $aead);
}

// HKDF-Expand (RFC 5869); hash_hkdf() has no expand-only mode
function hpke_hkdf_expand($hash, $prk, $info, $L) {
  $nh = strlen(hash($hash, "", true));
  if (($L < 0) || ($L > 255 * $nh)) return false;
  $t = ""; $okm = "";
  for ($i = 1; strlen($okm) < $L; $i++) {
    $t = hash_hmac($hash, $t . $info . chr($i), $prk, true);
    $okm .= $t;
  }
  return substr($okm, 0, $L);
}

// LabeledExtract(salt, label, ikm) = HKDF-Extract(salt, "HPKE-v1" || suite_id || label || ikm)
function hpke_labeled_extract($hash, $suite_id, $salt, $label, $ikm) {
  return hash_hmac($hash, "HPKE-v1" . $suite_id . $label . $ikm, $salt, true);   // empty salt = HMAC key of zero length (same as Nh zero bytes)
}

// LabeledExpand(prk, label, info, L) = HKDF-Expand(prk, I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info, L)
function hpke_labeled_expand($hash, $suite_id, $prk, $label, $info, $L) {
  if (($L < 0) || ($L > 0xffff)) return false;
  return hpke_hkdf_expand($hash, $prk, pack("n", $L) . "HPKE-v1" . $suite_id . $label . $info, $L);
}

/////////////////////////////////////////////////////////////////////
// OpenSSL CLI (ML-KEM, SHAKE256) - exec pattern as t11_ossl (T-11)

// runs the OpenSSL CLI; true on exit code 0
function hpke_ossl($args) {
  $bin = getenv("ENCEDO_OPENSSL") ? getenv("ENCEDO_OPENSSL") : "openssl";
  $cmd = escapeshellarg($bin);
  foreach ($args as $a) $cmd .= " " . escapeshellarg($a);
  exec($cmd . " 2>&1", $out, $rc);
  return ($rc == 0);
}

// temp file with $data (false = empty); the caller unlinks it
function hpke_tmp($data = false) {
  $f = tempnam(sys_get_temp_dir(), "hpk");
  if (($f !== false) && ($data !== false)) file_put_contents($f, $data);
  return $f;
}

// SHAKE256(data, 8 * L) via the CLI
function hpke_shake256($data, $L) {
  $in = hpke_tmp($data);
  $out = hpke_tmp();
  $ok = hpke_ossl(array("dgst", "-shake256", "-xoflen", (string)$L, "-binary", "-out", $out, $in));
  $ret = $ok ? file_get_contents($out) : false;
  @unlink($in);
  @unlink($out);
  return (($ret !== false) && (strlen($ret) == $L)) ? $ret : false;
}

// SHAKE256.LabeledDerive(ikm, label, context, L) of draft-ietf-hpke-pq (suite_id of the KEM)
function hpke_shake256_labeled_derive($suite_id, $ikm, $label, $context, $L) {
  return hpke_shake256($ikm . "HPKE-v1" . $suite_id . pack("n", strlen($label)) . $label . pack("n", $L) . $context, $L);
}

/////////////////////////////////////////////////////////////////////
// ML-KEM (FIPS 203) via the CLI; private key = 64 B seed d || z (PKCS#8 seed-only form of draft-ietf-lamps-kyber-certificates)

// DER length octets
function hpke_der_len($n) {
  if ($n < 0x80) return chr($n);
  if ($n < 0x100) return "\x81" . chr($n);
  return "\x82" . pack("n", $n);
}

// AlgorithmIdentifier of ML-KEM-512/768/1024 (OID 2.16.840.1.101.3.4.4.1/2/3, no parameters)
function hpke_mlkem_algid($p) {
  return "\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x04" . chr($p['oid']);
}

// PKCS#8 of the seed: SEQ { 0, algid, OCTET STRING { [0] seed } }
function hpke_mlkem_sk_der($p, $seed) {
  $body = "\x02\x01\x00" . hpke_mlkem_algid($p) . "\x04\x42\x80\x40" . $seed;
  return "\x30" . hpke_der_len(strlen($body)) . $body;
}

// SubjectPublicKeyInfo of a raw encapsulation key
function hpke_mlkem_pk_der($p, $pk) {
  $bits = "\x03" . hpke_der_len(strlen($pk) + 1) . "\x00" . $pk;
  $body = hpke_mlkem_algid($p) . $bits;
  return "\x30" . hpke_der_len(strlen($body)) . $body;
}

// encapsulation key of a seed (ML-KEM.KeyGen_internal(d, z))
function hpke_mlkem_pk($p, $seed) {
  if (strlen($seed) != 64) return false;
  $in = hpke_tmp(hpke_mlkem_sk_der($p, $seed));
  $out = hpke_tmp();
  $ok = hpke_ossl(array("pkey", "-inform", "DER", "-in", $in, "-pubout", "-outform", "DER", "-out", $out));
  $der = $ok ? file_get_contents($out) : false;
  @unlink($in);
  @unlink($out);
  if (($der === false) || (strlen($der) <= $p['Npk'])) return false;
  $pk = substr($der, -$p['Npk']);
  return ($der === hpke_mlkem_pk_der($p, $pk)) ? $pk : false;   // must be exactly our SPKI encoding
}

// ML-KEM.Encaps(pk) -> array('shared_secret', 'enc'); the CLI does the FIPS 203 encapsulation key check
function hpke_mlkem_encap($p, $pk) {
  if (strlen($pk) != $p['Npk']) return false;
  $in = hpke_tmp(hpke_mlkem_pk_der($p, $pk));
  $ct = hpke_tmp();
  $ss = hpke_tmp();
  $ok = hpke_ossl(array("pkeyutl", "-encap", "-pubin", "-inkey", $in, "-keyform", "DER", "-out", $ct, "-secret", $ss));
  $ret = $ok ? array('shared_secret' => file_get_contents($ss), 'enc' => file_get_contents($ct)) : false;
  @unlink($in);
  @unlink($ct);
  @unlink($ss);
  if (($ret === false) || (strlen($ret['shared_secret']) != 32) || (strlen($ret['enc']) != $p['Nenc'])) return false;
  return $ret;
}

// ML-KEM.Decaps(seed, ct) -> shared secret (implicit rejection: a bad ct gives a random looking secret)
function hpke_mlkem_decap($p, $seed, $ct) {
  if ((strlen($seed) != 64) || (strlen($ct) != $p['Nenc'])) return false;
  $in = hpke_tmp(hpke_mlkem_sk_der($p, $seed));
  $c = hpke_tmp($ct);
  $ss = hpke_tmp();
  $ok = hpke_ossl(array("pkeyutl", "-decap", "-inkey", $in, "-keyform", "DER", "-in", $c, "-secret", $ss));
  $ret = $ok ? file_get_contents($ss) : false;
  @unlink($in);
  @unlink($c);
  @unlink($ss);
  return (($ret !== false) && (strlen($ret) == 32)) ? $ret : false;
}

/////////////////////////////////////////////////////////////////////
// DH primitives

// X25519 via sodium; false on an all-zero output (sodium throws)
function hpke_x25519($sk, $pk) {
  if ((strlen($sk) != 32) || (strlen($pk) != 32)) return false;
  try {
    $dh = sodium_crypto_scalarmult($sk, $pk);
  } catch (Exception $e) {
    return false;
  }
  return hash_equals(str_repeat("\0", 32), $dh) ? false : $dh;
}

// drop errors left in the OpenSSL queue by a failed ext openssl call
function hpke_ossl_clear() {
  while (openssl_error_string() !== false);
}

// ext openssl private key from the serialized sk
function hpke_ossl_sk($p, $sk) {
  if ($p['type'] == 'ec') $k = @openssl_pkey_new(array('ec' => array('curve_name' => $p['curve'], 'd' => $sk)));
  else $k = @openssl_pkey_new(array('x448' => array('priv_key' => $sk)));
  hpke_ossl_clear();
  return $k;
}

// ext openssl public key from the serialized pk (NIST: uncompressed point, on-curve check by OpenSSL)
function hpke_ossl_pk($p, $pk) {
  if (strlen($pk) != $p['Npk']) return false;
  if ($p['type'] == 'ec') {
    if ($pk[0] !== "\x04") return false;
    $n = ($p['Npk'] - 1) / 2;
    $k = @openssl_pkey_new(array('ec' => array('curve_name' => $p['curve'], 'x' => substr($pk, 1, $n), 'y' => substr($pk, 1 + $n, $n))));
  } else $k = @openssl_pkey_new(array('x448' => array('pub_key' => $pk)));
  hpke_ossl_clear();
  return $k;
}

// DH(sk, pk): NIST x-coordinate (32/48/66 B), X25519/X448 raw; false on an invalid key or an all-zero output
function hpke_dh($p, $sk, $pk) {
  if ($p['type'] == 'x25519') return hpke_x25519($sk, $pk);
  if ((strlen($sk) != $p['Nsk']) || (strlen($pk) != $p['Npk'])) return false;
  $k = hpke_ossl_sk($p, $sk);
  $peer = hpke_ossl_pk($p, $pk);
  if (($k === false) || ($peer === false)) return false;
  $dh = @openssl_pkey_derive($peer, $k);
  hpke_ossl_clear();
  $ndh = ($p['type'] == 'ec') ? $p['Nsk'] : $p['Npk'];
  if (($dh === false) || (strlen($dh) != $ndh)) return false;
  return hash_equals(str_repeat("\0", $ndh), $dh) ? false : $dh;
}

/////////////////////////////////////////////////////////////////////
// Keys

// X-Wing expandDecapsulationKey: array('seed_M' (d || z for ML-KEM-768), 'sk_X', 'pk_X')
function hpke_xwing_expand($sk) {
  if (strlen($sk) != 32) return false;
  $e = hpke_shake256($sk, 96);
  if ($e === false) return false;
  $skx = substr($e, 64, 32);
  return array('seed_M' => substr($e, 0, 64), 'sk_X' => $skx, 'pk_X' => sodium_crypto_scalarmult_base($skx));
}

// public key of a serialized private key
function hpke_pk($kem, $sk) {
  $p = hpke_kem($kem);
  if (($p === false) || !is_string($sk) || (strlen($sk) != $p['Nsk'])) return false;
  switch ($p['type']) {
    case 'x25519':
      return sodium_crypto_scalarmult_base($sk);
    case 'mlkem':
      return hpke_mlkem_pk($p, $sk);
    case 'xwing':
      $x = hpke_xwing_expand($sk);
      if ($x === false) return false;
      $pkm = hpke_mlkem_pk(hpke_kem(0x0041), $x['seed_M']);
      return ($pkm === false) ? false : $pkm . $x['pk_X'];
  }
  if (($p['type'] == 'ec') && (($sk === str_repeat("\0", $p['Nsk'])) || (strcmp($sk, $p['order']) >= 0))) return false;   // 0 < sk < n
  $k = hpke_ossl_sk($p, $sk);
  if ($k === false) return false;
  $d = openssl_pkey_get_details($k);
  if ($p['type'] == 'x448') return $d['x448']['pub_key'];
  $n = $p['Nsk'];
  return "\x04" . str_pad($d['ec']['x'], $n, "\0", STR_PAD_LEFT) . str_pad($d['ec']['y'], $n, "\0", STR_PAD_LEFT);
}

// DeriveKeyPair(ikm): RFC 9180 7.1.3 for the DHKEMs, draft-ietf-hpke-pq (SHAKE256.LabeledDerive) for ML-KEM / X-Wing
function hpke_derive_keypair($kem, $ikm) {
  $p = hpke_kem($kem);
  if (($p === false) || !is_string($ikm)) return false;
  $sid = hpke_suite_kem($kem);
  if (($p['type'] == 'mlkem') || ($p['type'] == 'xwing')) {
    $sk = hpke_shake256_labeled_derive($sid, $ikm, "DeriveKeyPair", "", $p['Nsk']);
  } else {
    $prk = hpke_labeled_extract($p['hash'], $sid, "", "dkp_prk", $ikm);
    if ($p['type'] != 'ec') $sk = hpke_labeled_expand($p['hash'], $sid, $prk, "sk", "", $p['Nsk']);
    else {
      for ($c = 0, $sk = false; ($sk === false) && ($c < 256); $c++) {   // rejection sampling: 0 < sk < order
        $b = hpke_labeled_expand($p['hash'], $sid, $prk, "candidate", chr($c), $p['Nsk']);
        $b[0] = chr(ord($b[0]) & $p['mask']);
        if (($b !== str_repeat("\0", $p['Nsk'])) && (strcmp($b, $p['order']) < 0)) $sk = $b;
      }
    }
  }
  if ($sk === false) return false;
  $pk = hpke_pk($kem, $sk);
  return ($pk === false) ? false : array('sk' => $sk, 'pk' => $pk);
}

// new random recipient key pair (DeriveKeyPair of Nsk random bytes for the DHKEMs, random seed for ML-KEM / X-Wing)
function hpke_keygen($kem) {
  $p = hpke_kem($kem);
  if ($p === false) return false;
  if (($p['type'] == 'mlkem') || ($p['type'] == 'xwing')) {
    $sk = random_bytes($p['Nsk']);
    $pk = hpke_pk($kem, $sk);
    return ($pk === false) ? false : array('sk' => $sk, 'pk' => $pk);
  }
  return hpke_derive_keypair($kem, random_bytes($p['Nsk']));
}

/////////////////////////////////////////////////////////////////////
// KEM Encap / Decap

// DHKEM ExtractAndExpand(dh, kem_context)
function hpke_dhkem_ss($kem, $p, $dh, $kem_context) {
  $sid = hpke_suite_kem($kem);
  $prk = hpke_labeled_extract($p['hash'], $sid, "", "eae_prk", $dh);
  return hpke_labeled_expand($p['hash'], $sid, $prk, "shared_secret", $kem_context, $p['Nsecret']);
}

// X-Wing Combiner: SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
function hpke_xwing_combiner($ss_m, $ss_x, $ct_x, $pk_x) {
  return hash("sha3-256", $ss_m . $ss_x . $ct_x . $pk_x . "\x5c\x2e\x2f\x2f\x5e\x5c", true);   // XWingLabel "\.//^\"
}

// Encap(pkR) -> array('shared_secret', 'enc'); $skE = fixed ephemeral private key (DHKEM / X-Wing X25519 part, testing only)
function hpke_encap($kem, $pkR, $skE = false) {
  $p = hpke_kem($kem);
  if (($p === false) || !is_string($pkR) || (strlen($pkR) != $p['Npk'])) return false;
  if ($p['type'] == 'mlkem') return ($skE === false) ? hpke_mlkem_encap($p, $pkR) : false;
  if ($p['type'] == 'xwing') {
    $pkx = substr($pkR, 1184, 32);
    $ekx = ($skE === false) ? random_bytes(32) : $skE;
    $ctx = sodium_crypto_scalarmult_base($ekx);
    $ssx = hpke_x25519($ekx, $pkx);
    $m = hpke_mlkem_encap(hpke_kem(0x0041), substr($pkR, 0, 1184));
    if (($ssx === false) || ($m === false)) return false;
    return array('shared_secret' => hpke_xwing_combiner($m['shared_secret'], $ssx, $ctx, $pkx), 'enc' => $m['enc'] . $ctx);
  }
  if ($skE === false) {
    $e = hpke_keygen($kem);
    if ($e === false) return false;
    $skE = $e['sk'];
  }
  $pkE = hpke_pk($kem, $skE);
  $dh = hpke_dh($p, $skE, $pkR);
  if (($pkE === false) || ($dh === false)) return false;
  return array('shared_secret' => hpke_dhkem_ss($kem, $p, $dh, $pkE . $pkR), 'enc' => $pkE);
}

// Decap(enc, skR) -> shared_secret
function hpke_decap($kem, $enc, $skR) {
  $p = hpke_kem($kem);
  if (($p === false) || !is_string($enc) || (strlen($enc) != $p['Nenc']) || !is_string($skR) || (strlen($skR) != $p['Nsk'])) return false;
  if ($p['type'] == 'mlkem') return hpke_mlkem_decap($p, $skR, $enc);
  if ($p['type'] == 'xwing') {
    $x = hpke_xwing_expand($skR);
    if ($x === false) return false;
    $ctx = substr($enc, 1088, 32);
    $ssm = hpke_mlkem_decap(hpke_kem(0x0041), $x['seed_M'], substr($enc, 0, 1088));
    $ssx = hpke_x25519($x['sk_X'], $ctx);
    if (($ssm === false) || ($ssx === false)) return false;
    return hpke_xwing_combiner($ssm, $ssx, $ctx, $x['pk_X']);
  }
  $pkR = hpke_pk($kem, $skR);
  $dh = hpke_dh($p, $skR, $enc);
  if (($pkR === false) || ($dh === false)) return false;
  return hpke_dhkem_ss($kem, $p, $dh, $enc . $pkR);
}

/////////////////////////////////////////////////////////////////////
// Key schedule (RFC 9180 5.1, mode_base: psk = psk_id = "")

// context from the KEM shared secret; false on an unsupported suite
function hpke_key_schedule($kem, $kdf, $aead, $shared_secret, $info) {
  $f = hpke_kdf($kdf);
  $a = hpke_aead($aead);
  if (($f === false) || ($a === false) || (hpke_kem($kem) === false) || !is_string($info)) return false;
  $h = $f['hash'];
  $sid = hpke_suite($kem, $kdf, $aead);
  $ksc = "\x00" . hpke_labeled_extract($h, $sid, "", "psk_id_hash", "") . hpke_labeled_extract($h, $sid, "", "info_hash", $info);
  $secret = hpke_labeled_extract($h, $sid, $shared_secret, "secret", "");
  return array('kem' => $kem, 'kdf' => $kdf, 'aead' => $aead, 'suite_id' => $sid, 'shared_secret' => $shared_secret,
    'key_schedule_context' => $ksc, 'secret' => $secret,
    'key' => hpke_labeled_expand($h, $sid, $secret, "key", $ksc, $a['Nk']),            // empty for export only
    'base_nonce' => hpke_labeled_expand($h, $sid, $secret, "base_nonce", $ksc, $a['Nn']),
    'exporter_secret' => hpke_labeled_expand($h, $sid, $secret, "exp", $ksc, $f['Nh']));
}

// SetupBaseS: ctx with 'enc'
function hpke_setup_s($kem, $kdf, $aead, $pkR, $info, $skE = false) {
  if ((hpke_kdf($kdf) === false) || (hpke_aead($aead) === false)) return false;
  $e = hpke_encap($kem, $pkR, $skE);
  if ($e === false) return false;
  $ctx = hpke_key_schedule($kem, $kdf, $aead, $e['shared_secret'], $info);
  if ($ctx !== false) $ctx['enc'] = $e['enc'];
  return $ctx;
}

// SetupBaseR
function hpke_setup_r($kem, $kdf, $aead, $skR, $enc, $info) {
  if ((hpke_kdf($kdf) === false) || (hpke_aead($aead) === false)) return false;
  $ss = hpke_decap($kem, $enc, $skR);
  if ($ss === false) return false;
  $ctx = hpke_key_schedule($kem, $kdf, $aead, $ss, $info);
  if ($ctx !== false) $ctx['enc'] = $enc;
  return $ctx;
}

// nonce of message seq: base_nonce XOR I2OSP(seq, Nn)
function hpke_nonce($base_nonce, $seq) {
  return $base_nonce ^ str_pad(pack("J", $seq), strlen($base_nonce), "\0", STR_PAD_LEFT);
}

// AEAD Seal: ct || 16 B tag
function hpke_aead_seal($aead, $key, $nonce, $aad, $pt) {
  $a = hpke_aead($aead);
  if (($a === false) || ($a['Nk'] == 0) || !is_string($pt) || !is_string($aad)) return false;
  if ($aead == 0x0003) return sodium_crypto_aead_chacha20poly1305_ietf_encrypt($pt, $aad, $nonce, $key);
  $tag = "";
  $ct = openssl_encrypt($pt, $a['cipher'], $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad, 16);
  return ($ct === false) ? false : $ct . $tag;
}

// AEAD Open; false on a bad tag
function hpke_aead_open($aead, $key, $nonce, $aad, $ct) {
  $a = hpke_aead($aead);
  if (($a === false) || ($a['Nk'] == 0) || !is_string($ct) || (strlen($ct) < 16) || !is_string($aad)) return false;
  if ($aead == 0x0003) {
    try {
      return sodium_crypto_aead_chacha20poly1305_ietf_decrypt($ct, $aad, $nonce, $key);
    } catch (Exception $e) {
      return false;
    }
  }
  return openssl_decrypt(substr($ct, 0, -16), $a['cipher'], $key, OPENSSL_RAW_DATA, $nonce, substr($ct, -16), $aad);
}

// ContextS.Seal / ContextR.Open of message number $seq
function hpke_ctx_seal($ctx, $seq, $aad, $pt) {
  return hpke_aead_seal($ctx['aead'], $ctx['key'], hpke_nonce($ctx['base_nonce'], $seq), $aad, $pt);
}

function hpke_ctx_open($ctx, $seq, $aad, $ct) {
  return hpke_aead_open($ctx['aead'], $ctx['key'], hpke_nonce($ctx['base_nonce'], $seq), $aad, $ct);
}

// Context.Export: LabeledExpand(exporter_secret, "sec", exporter_context, L)
function hpke_ctx_export($ctx, $exp_ctx, $L) {
  $f = hpke_kdf($ctx['kdf']);
  if (!is_string($exp_ctx) || !is_int($L) || ($L < 1) || ($L > 255 * $f['Nh'])) return false;
  return hpke_labeled_expand($f['hash'], $ctx['suite_id'], $ctx['exporter_secret'], "sec", $exp_ctx, $L);
}

/////////////////////////////////////////////////////////////////////
// Single shot API

// SealBase: array('enc', 'ct')
function hpke_seal($kem, $kdf, $aead, $pkR, $info, $aad, $pt) {
  if ($aead == 0xFFFF) return false;
  $ctx = hpke_setup_s($kem, $kdf, $aead, $pkR, $info);
  if ($ctx === false) return false;
  $ct = hpke_ctx_seal($ctx, 0, $aad, $pt);
  return ($ct === false) ? false : array('enc' => $ctx['enc'], 'ct' => $ct);
}

// OpenBase: plaintext
function hpke_open($kem, $kdf, $aead, $skR, $enc, $info, $aad, $ct) {
  if ($aead == 0xFFFF) return false;
  $ctx = hpke_setup_r($kem, $kdf, $aead, $skR, $enc, $info);
  return ($ctx === false) ? false : hpke_ctx_open($ctx, 0, $aad, $ct);
}

// SendExport (export-only AEAD 0xFFFF): array('enc', 'secret')
function hpke_export_s($kem, $kdf, $pkR, $info, $exp_ctx, $L) {
  $ctx = hpke_setup_s($kem, $kdf, 0xFFFF, $pkR, $info);
  if ($ctx === false) return false;
  $s = hpke_ctx_export($ctx, $exp_ctx, $L);
  return ($s === false) ? false : array('enc' => $ctx['enc'], 'secret' => $s);
}

// ReceiveExport (export-only AEAD 0xFFFF): secret
function hpke_export_r($kem, $kdf, $skR, $enc, $info, $exp_ctx, $L) {
  $ctx = hpke_setup_r($kem, $kdf, 0xFFFF, $skR, $enc, $info);
  return ($ctx === false) ? false : hpke_ctx_export($ctx, $exp_ctx, $L);
}
