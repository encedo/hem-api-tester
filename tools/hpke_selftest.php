<?php
// self test of libs/hpke.php against the official vectors (libs/hpke_vectors.json) + random round trips
//   php tools/hpke_selftest.php
// Exit code 0 = all PASS, 1 = a FAIL.
chdir(__DIR__ . "/..");
include "libs/hpke.php";

$t0 = microtime(true);
$vec = json_decode(file_get_contents("libs/hpke_vectors.json"), true);
$fail = 0;

// one result line; $bad = names of the failed checks
function st_report($name, $bad, $info = "") {
  global $fail;
  if (count($bad)) $fail++;
  echo (count($bad) ? "FAIL " : "PASS ") . $name . ($info !== "" ? " ($info)" : "") . (count($bad) ? ": " . implode(", ", $bad) : "") . "\n";
}

// adds $name to $bad if $got !== $want (hex)
function st_eq(&$bad, $name, $got, $want) {
  if (($got === false) || !is_string($got) || (bin2hex($got) !== strtolower($want))) $bad[] = $name;
}

function st_suite($v) {
  return sprintf("kem 0x%04X kdf 0x%04X aead 0x%04X", $v['kem_id'], $v['kdf_id'], $v['aead_id']);
}

// encryptions and exports of a vector with the sender ($cs, may be false) and recipient ($cr) contexts
function st_msgs(&$bad, $v, $cs, $cr, $skR) {
  foreach ($v['encryptions'] as $i => $e) {
    st_eq($bad, "nonce$i", hpke_nonce($cr['base_nonce'], $i), $e['nonce']);
    st_eq($bad, "seal$i", hpke_ctx_seal($cs ? $cs : $cr, $i, hex2bin($e['aad']), hex2bin($e['pt'])), $e['ct']);
    st_eq($bad, "open$i", hpke_ctx_open($cr, $i, hex2bin($e['aad']), hex2bin($e['ct'])), $e['pt']);
  }
  if (count($v['encryptions'])) {                                       // single shot API = message 0
    $e = $v['encryptions'][0];
    st_eq($bad, "hpke_open", hpke_open($v['kem_id'], $v['kdf_id'], $v['aead_id'], $skR, hex2bin($v['enc']), hex2bin($v['info']), hex2bin($e['aad']), hex2bin($e['ct'])), $e['pt']);
  }
  foreach ($v['exports'] as $i => $x) {
    if ($cs) st_eq($bad, "export_s$i", hpke_ctx_export($cs, hex2bin($x['exporter_context']), $x['L']), $x['exported_value']);
    st_eq($bad, "export_r$i", hpke_ctx_export($cr, hex2bin($x['exporter_context']), $x['L']), $x['exported_value']);
    if ($v['aead_id'] == 0xFFFF) st_eq($bad, "hpke_export_r$i", hpke_export_r($v['kem_id'], $v['kdf_id'], $skR, hex2bin($v['enc']), hex2bin($v['info']), hex2bin($x['exporter_context']), $x['L']), $x['exported_value']);
  }
}

// ctx fields against the vector
function st_ctx(&$bad, $who, $v, $ctx, $fields) {
  if ($ctx === false) { $bad[] = "setup_$who"; return; }
  foreach ($fields as $f) st_eq($bad, "$who.$f", $ctx[$f], $v[$f]);
}

// RFC 9180 vectors: full sender (DeriveKeyPair(ikmE) -> fixed skE) and recipient side
echo "RFC 9180 test vectors (mode 0)\n";
$n_enc = 0;
foreach ($vec['rfc9180'] as $v) {
  $bad = array();
  $kem = $v['kem_id'];
  $r = hpke_derive_keypair($kem, hex2bin($v['ikmR']));
  $e = hpke_derive_keypair($kem, hex2bin($v['ikmE']));
  st_eq($bad, "skRm", $r ? $r['sk'] : false, $v['skRm']);
  st_eq($bad, "pkRm", $r ? $r['pk'] : false, $v['pkRm']);
  st_eq($bad, "skEm", $e ? $e['sk'] : false, $v['skEm']);
  st_eq($bad, "pkEm", $e ? $e['pk'] : false, $v['enc']);
  $f = array('enc', 'shared_secret', 'key_schedule_context', 'secret', 'key', 'base_nonce', 'exporter_secret');
  $cs = hpke_setup_s($kem, $v['kdf_id'], $v['aead_id'], hex2bin($v['pkRm']), hex2bin($v['info']), hex2bin($v['skEm']));
  $cr = hpke_setup_r($kem, $v['kdf_id'], $v['aead_id'], hex2bin($v['skRm']), hex2bin($v['enc']), hex2bin($v['info']));
  st_ctx($bad, "S", $v, $cs, $f);
  st_ctx($bad, "R", $v, $cr, $f);
  if ($cs && $cr) st_msgs($bad, $v, $cs, $cr, hex2bin($v['skRm']));
  $n_enc += count($v['encryptions']);
  st_report("rfc9180 " . st_suite($v), $bad, count($v['encryptions']) . " enc, " . count($v['exports']) . " exp");
}

// draft-ietf-hpke-pq vectors: ML-KEM / X-Wing recipient side (the CLI cannot encapsulate deterministically), P-384 KEM part
echo "draft-ietf-hpke-pq test vectors (mode 0)\n";
foreach ($vec['hpke_pq'] as $v) {
  $bad = array();
  $kem = $v['kem_id'];
  $r = hpke_derive_keypair($kem, hex2bin($v['ikmR']));
  st_eq($bad, "skRm", $r ? $r['sk'] : false, $v['skRm']);
  st_eq($bad, "pkRm", $r ? $r['pk'] : false, $v['pkRm']);
  st_eq($bad, "decap", hpke_decap($kem, hex2bin($v['enc']), hex2bin($v['skRm'])), $v['shared_secret']);
  if (isset($v['kem_only'])) {                                        // KDF of this vector is SHAKE256: KEM part only
    $e = hpke_derive_keypair($kem, hex2bin($v['ikmE']));
    $s = $e ? hpke_encap($kem, hex2bin($v['pkRm']), $e['sk']) : false;
    st_eq($bad, "encap.enc", $s ? $s['enc'] : false, $v['enc']);
    st_eq($bad, "encap.shared_secret", $s ? $s['shared_secret'] : false, $v['shared_secret']);
    st_report("hpke-pq " . sprintf("kem 0x%04X", $kem) . " KEM only", $bad, "DeriveKeyPair, Encap, Decap");
    continue;
  }
  $cr = hpke_setup_r($kem, $v['kdf_id'], $v['aead_id'], hex2bin($v['skRm']), hex2bin($v['enc']), hex2bin($v['info']));
  st_ctx($bad, "R", $v, $cr, array('shared_secret', 'key', 'base_nonce', 'exporter_secret'));
  if ($cr) st_msgs($bad, $v, false, $cr, hex2bin($v['skRm']));
  $n_enc += count($v['encryptions']);
  st_report("hpke-pq " . st_suite($v), $bad, "recipient side, " . count($v['encryptions']) . " enc, " . count($v['exports']) . " exp");
}

// X-Wing draft KEM vectors: keys, Decapsulate, and the encapsulation side X25519 part + combiner (ek_X = eseed[32:64])
echo "X-Wing KEM test vectors (draft-connolly-cfrg-xwing-kem-11)\n";
foreach ($vec['xwing_kem'] as $i => $v) {
  $bad = array();
  $seed = hex2bin($v['seed']);
  $ct = hex2bin($v['ct']);
  $pk = hex2bin($v['pk']);
  st_eq($bad, "pk", hpke_pk(0x647A, $seed), $v['pk']);
  st_eq($bad, "decap", hpke_decap(0x647A, $ct, $seed), $v['ss']);
  $ekx = substr(hex2bin($v['eseed']), 32, 32);
  $ctx = sodium_crypto_scalarmult_base($ekx);
  st_eq($bad, "ct_X", $ctx, bin2hex(substr($ct, 1088)));
  $x = hpke_xwing_expand($seed);
  $ssm = $x ? hpke_mlkem_decap(hpke_kem(0x0041), $x['seed_M'], substr($ct, 0, 1088)) : false;
  $ssx = hpke_x25519($ekx, substr($pk, 1184));
  st_eq($bad, "combiner", ($ssm && $ssx) ? hpke_xwing_combiner($ssm, $ssx, $ctx, substr($pk, 1184)) : false, $v['ss']);
  st_report("xwing-kem vector $i", $bad, "pk, Decapsulate, sender X25519 + combiner");
}

// random round trips: every KEM x AEAD (KDF rotated so every KEM meets every KDF), tamper checks
echo "Round trips (random keys)\n";
$kems = array(0x0010, 0x0011, 0x0012, 0x0020, 0x0021, 0x0040, 0x0041, 0x0042, 0x647A);
$n_rt = 0;
foreach ($kems as $ki => $kem) {
  $k = hpke_keygen($kem);
  foreach (array(0x0001, 0x0002, 0x0003, 0xFFFF) as $ai => $aead) {
    $bad = array();
    $kdf = (($ki + $ai) % 3) + 1;
    $info = "info " . random_bytes(8);
    if ($k === false) $bad[] = "keygen";
    elseif ($aead == 0xFFFF) {
      $s = hpke_export_s($kem, $kdf, $k['pk'], $info, "ctx", 32);
      $r = $s ? hpke_export_r($kem, $kdf, $k['sk'], $s['enc'], $info, "ctx", 32) : false;
      if (($s === false) || ($r === false) || ($r !== $s['secret'])) $bad[] = "export";
      $r2 = $s ? hpke_export_r($kem, $kdf, $k['sk'], $s['enc'], $info, "ctx2", 32) : false;
      if (($r2 === false) || ($s && ($r2 === $s['secret']))) $bad[] = "other exporter_context";
      if (hpke_seal($kem, $kdf, $aead, $k['pk'], $info, "", "x") !== false) $bad[] = "seal with export only";
    } else {
      $pt = random_bytes(37);
      $s = hpke_seal($kem, $kdf, $aead, $k['pk'], $info, "aad", $pt);
      if (($s === false) || (hpke_open($kem, $kdf, $aead, $k['sk'], $s['enc'], $info, "aad", $s['ct']) !== $pt)) $bad[] = "seal/open";
      if ($s) {
        $c = $s['ct']; $c[3] = chr(ord($c[3]) ^ 1);
        if (hpke_open($kem, $kdf, $aead, $k['sk'], $s['enc'], $info, "aad", $c) !== false) $bad[] = "tampered ct accepted";
        if (hpke_open($kem, $kdf, $aead, $k['sk'], $s['enc'], $info, "aaD", $s['ct']) !== false) $bad[] = "wrong aad accepted";
        if (hpke_open($kem, $kdf, $aead, $k['sk'], $s['enc'], $info . "x", "aad", $s['ct']) !== false) $bad[] = "wrong info accepted";
        $e = $s['enc']; $e[strlen($e) - 2] = chr(ord($e[strlen($e) - 2]) ^ 1);
        if (hpke_open($kem, $kdf, $aead, $k['sk'], $e, $info, "aad", $s['ct']) !== false) $bad[] = "tampered enc accepted";
        if (hpke_open($kem, $kdf, $aead, $k['sk'], substr($s['enc'], 1), $info, "aad", $s['ct']) !== false) $bad[] = "short enc accepted";
      }
      $s0 = hpke_seal($kem, $kdf, $aead, $k['pk'], $info, "", "");                 // empty pt and aad
      if (($s0 === false) || (strlen($s0['ct']) != 16) || (hpke_open($kem, $kdf, $aead, $k['sk'], $s0['enc'], $info, "", $s0['ct']) !== "")) $bad[] = "empty pt";
    }
    $n_rt++;
    st_report(sprintf("round trip kem 0x%04X kdf 0x%04X aead 0x%04X", $kem, $kdf, $aead), $bad);
  }
}

// invalid recipient public keys
echo "Invalid public keys\n";
$bad = array();
$k = hpke_keygen(0x0010);
$pk = $k['pk']; $pk[64] = chr(ord($pk[64]) ^ 1);
if (hpke_seal(0x0010, 1, 1, $pk, "", "", "x") !== false) $bad[] = "P-256 point off the curve";
if (hpke_seal(0x0010, 1, 1, "\x02" . substr($k['pk'], 1, 32), "", "", "x") !== false) $bad[] = "P-256 compressed point";
if (hpke_seal(0x0020, 1, 1, str_repeat("\0", 32), "", "", "x") !== false) $bad[] = "X25519 all-zero DH";
if (hpke_seal(0x0021, 1, 1, str_repeat("\0", 56), "", "", "x") !== false) $bad[] = "X448 all-zero DH";
if (hpke_seal(0x647A, 1, 1, substr(hpke_keygen(0x647A)['pk'], 0, 1184) . str_repeat("\0", 32), "", "", "x") !== false) $bad[] = "X-Wing all-zero X25519 DH";
if (hpke_seal(0x0041, 1, 1, str_repeat("\xff", 1184), "", "", "x") !== false) $bad[] = "ML-KEM-768 ek check";
if (hpke_seal(0x0041, 1, 1, str_repeat("\0", 1183), "", "", "x") !== false) $bad[] = "ML-KEM-768 short pk";
st_report("invalid recipient keys rejected", $bad);

$suites = count($vec['rfc9180']) + count($vec['hpke_pq']) + count($vec['xwing_kem']);
printf("%d vector suites (%d encryptions), %d round trips, %.1f s\n", $suites, $n_enc, $n_rt, microtime(true) - $t0);
echo $fail ? "FAILED: $fail\n" : "ALL PASS\n";
exit($fail ? 1 : 0);
