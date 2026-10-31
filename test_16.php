<?php

include "libs/lib.php";
include "config.php";


// test name, descr & number of subtests
$test_name = "T-16";
$test_descr = "Device policy set at personalisation";
$test_subtest_cnt = 3;


// initialize the execution env
init_env();
$test_cfg = init_test($test_name, $test_descr, $test_subtest_cnt, $cfg_tester);
if ( $cfg_debug ) var_dump( $cfg_domain );
$test_cfg['elapsed'] = hrtime(true);

echo "Processing...\n";


/////////////////////////////////////////////////////////////////////
// Local helpers (this test only)    ////////////////////////////////
/////////////////////////////////////////////////////////////////////
// DEV-447: 'policy' is set only by POST /api/auth/init, so every variant needs a wipeout and a new personalisation.
// The personalisation is T-2 itself (test_2.php) with ENCEDO_T2_POLICY = the policy array (JSON); without it T-2 enables all three.
// The test ends with the device personalised by a plain T-2 (all policies on), as the other tests expect.
$t16_all = array("raw_ecdh_enabled", "pubkey_in_search", "pubkey_in_list");

function t16_wait_status($domain) {         // device answers /api/system/status again (after wipeout / reboot)
  for ($i = 0; $i < 60; $i++) {
    $ret_val = false;
    if ( http_transaction("http", "GET", $domain, "/api/system/status", $ret_val) == 200 ) return $ret_val;
    sleep(2);
  }
  return false;
}

function t16_personalise($policy) {         // wipeout + T-2 with the given policy (null = T-2 default); true on T-2 PASS
  global $cfg_domain;
  exec("php wipeout.php 2>&1", $out);
  sleep(20);
  if ( t16_wait_status($cfg_domain) === false ) return false;
  if ($policy !== null) putenv("ENCEDO_T2_POLICY=" . json_encode($policy));
  $out = array();
  exec("php test_2.php 2>&1", $out);
  putenv("ENCEDO_T2_POLICY");
  foreach ($out as $l) if ( strpos($l, "Test result:") !== false ) return ( strpos($l, "PASS") !== false );
  return false;
}

// policy-dependent behaviour; returns "" or the first difference
function t16_check($domain, $password, $policy) {
  $on = array_fill_keys($policy, true);
  if ( helper_checkin($domain) == false ) return "checkin";
  $tc = helper_authorize($domain, $password, "system:config");
  $tg = helper_authorize($domain, $password, "keymgmt:gen");
  $tl = helper_authorize($domain, $password, "keymgmt:list");
  $ts = helper_authorize($domain, $password, "keymgmt:search");
  if ( !$tc || !$tg || !$tl || !$ts ) return "tokens";
  $ret_val = false; $not_used = false;
  if ( http_transaction("https", "GET", $domain, "/api/system/config", $ret_val, $not_used, $tc) != 200 ) return "GET config";
  if ( @$ret_val['policy'] !== array_values(array_intersect(array("raw_ecdh_enabled", "pubkey_in_search", "pubkey_in_list"), $policy)) ) return "GET config policy " . json_encode(@$ret_val['policy']);
  $run = bin2hex(openssl_random_pseudo_bytes(3));
  $keys = array();
  foreach (array("a", "b") as $k) {
    $ret_val = false;
    if ( http_transaction("https", "POST", $domain, "/api/keymgmt/create", $ret_val, json_encode(array('label' => "T-16 $k", 'type' => "SECP256R1", 'mode' => "ECDH", 'descr' => base64_encode("CCTEST:T-16_$run"))), $tg) != 200 ) return "create";
    $kid = $ret_val['kid'];
    $ret_val = false;
    if ( http_transaction("https", "GET", $domain, "/api/keymgmt/get/$kid", $ret_val, $not_used, $tg) != 200 ) return "get";
    $keys[$k] = array($kid, $ret_val['pubkey']);
  }
  $tu = helper_authorize($domain, $password, "keymgmt:use:" . $keys['a'][0]);
  $ecdh = array('kid' => $keys['a'][0], 'pubkey' => $keys['b'][1]);
  // raw ECDH only with raw_ecdh_enabled; hashed / HKDF always; the reserved hkdf_ctx prefix always 400
  $ret_val = false;
  $st = http_transaction("https", "POST", $domain, "/api/crypto/ecdh", $ret_val, json_encode($ecdh), $tu);
  if ( $st != (isset($on['raw_ecdh_enabled']) ? 200 : 403) ) return "raw ECDH: HTTP $st";
  $ret_val = false;
  if ( ($st = http_transaction("https", "POST", $domain, "/api/crypto/ecdh", $ret_val, json_encode($ecdh + array('alg' => "SHA2-256")), $tu)) != 200 ) return "ECDH SHA2-256: HTTP $st";
  $ret_val = false;
  if ( ($st = http_transaction("https", "POST", $domain, "/api/crypto/ecdh", $ret_val, json_encode($ecdh + array('alg' => "HKDF-SHA2-256", 'hkdf_ctx' => base64_encode("encedo-derive:v1:secp256r1"))), $tu)) != 400 ) return "ECDH reserved hkdf_ctx: HTTP $st";
  // public keys in search / list only with the policies; without them the flag / segment is ignored
  $ret_val = false;
  if ( http_transaction("https", "POST", $domain, "/api/keymgmt/search", $ret_val, json_encode(array('descr' => "^" . base64_encode("CCTEST:T-16_$run"), 'return_pubkey' => true)), $ts) != 200 ) return "search";
  $n = 0; foreach ((array)@$ret_val['list'] as $item) if ( isset($item['pubkey']) ) $n++;
  if ( ($n > 0) != isset($on['pubkey_in_search']) ) return "search return_pubkey: $n public keys";
  $ret_val = false;
  if ( http_transaction("https", "GET", $domain, "/api/keymgmt/list/0/15/pubkey", $ret_val, $not_used, $tl) != 200 ) return "list";
  $n = 0; foreach ((array)@$ret_val['list'] as $item) if ( isset($item['pubkey']) ) $n++;
  if ( ($n > 0) != isset($on['pubkey_in_list']) ) return "list/0/15/pubkey: $n public keys";
  // POST config never accepts policy
  $ret_val = false;
  if ( ($st = http_transaction("https", "POST", $domain, "/api/system/config", $ret_val, json_encode(array('policy' => $policy)), $tc)) != 400 ) return "POST config policy: HTTP $st";
  return "";
}


/////////////////////////////////////////////////////////////////////
// Subtest: 1        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST1:
echo "  subtest-1\n";
$test_cfg['subtests'][1] = 'ERROR';                         // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) TOE status and version
$ret_val = t16_wait_status($cfg_domain);
if ( $ret_val === false ) goto print_and_exit;
if ( isset($ret_val['hostname']) ) $cfg_domain = $ret_val['hostname'];
$ret_val = false;
if ( http_transaction("http", "GET", $cfg_domain, "/api/system/version", $ret_val) != 200 ) goto print_and_exit;
$test_cfg['hwv'] = $ret_val['hwv'];
$test_cfg['blv'] = @$ret_val['blv'];
$test_cfg['fwv'] = $ret_val['fwv'];
$test_cfg['conf'] = "ENCEDO PPA";
if ( strstr($ret_val['hwv'], "EPA") ) $test_cfg['conf'] = "ENCEDO EPA";
// b) personalisation without 'policy' -> all off
if ( !t16_personalise(array()) ) { echo "ERROR: personalisation with policy []\n"; goto print_and_exit; }
$ret_val = t16_wait_status($cfg_domain);
if ( isset($ret_val['hostname']) ) $cfg_domain = $ret_val['hostname'];
$err = t16_check($cfg_domain, $cfg_passpharse, array());
if ( $err !== "" ) { echo "ERROR: policies off: $err\n"; goto print_and_exit; }
// c) set result
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
// a) one policy only, then the policy survives a reboot
if ( !t16_personalise(array("pubkey_in_list")) ) { echo "ERROR: personalisation with policy [pubkey_in_list]\n"; goto print_and_exit; }
$ret_val = t16_wait_status($cfg_domain);
if ( isset($ret_val['hostname']) ) $cfg_domain = $ret_val['hostname'];
$err = t16_check($cfg_domain, $cfg_passpharse, array("pubkey_in_list"));
if ( $err !== "" ) { echo "ERROR: policy pubkey_in_list: $err\n"; goto print_and_exit; }
$token = helper_authorize($cfg_domain, $cfg_passpharse, "system:config");
if ($token == false) goto print_and_exit;
$ret_val = false; $not_used = false;
if ( http_transaction("https", "GET", $cfg_domain, "/api/system/reboot", $ret_val, $not_used, $token) != 200 ) goto print_and_exit;
sleep(20);
if ( t16_wait_status($cfg_domain) === false ) goto print_and_exit;
sleep(10);
$err = t16_check($cfg_domain, $cfg_passpharse, array("pubkey_in_list"));
if ( $err !== "" ) { echo "ERROR: after reboot: $err\n"; goto print_and_exit; }
// b) set result
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
// a) plain T-2 (all policies on) - also the state the other tests expect
if ( !t16_personalise(null) ) { echo "ERROR: personalisation with the T-2 default policy\n"; goto print_and_exit; }
$ret_val = t16_wait_status($cfg_domain);
if ( isset($ret_val['hostname']) ) $cfg_domain = $ret_val['hostname'];
$err = t16_check($cfg_domain, $cfg_passpharse, $t16_all);
if ( $err !== "" ) { echo "ERROR: policies on: $err\n"; goto print_and_exit; }
// b) set result
$test_cfg['subtests'][3] = 'OK';                            // mark this subtest as OK
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
