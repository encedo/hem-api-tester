<?php

include "libs/lib.php";
include "config.php";


// test name, descr & number of subtests
$test_name = "T-9";
$test_descr = "Audit log functionality";
$test_subtest_cnt = 3;


// initialize the execution env
init_env();
$test_cfg = init_test($test_name, $test_descr, $test_subtest_cnt, $cfg_tester);
if ( $cfg_debug ) var_dump( $cfg_domain );
$test_cfg['elapsed'] = hrtime(true);

$authkey = $cfg_authkey;

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
// c) set RTC clock - code from T-1.3
$ret = helper_checkin($cfg_domain);
if ($ret == false) goto print_and_exit;                     // exit on error
// d) perform local USER authentication
$token = helper_authorize($cfg_domain, $cfg_passpharse, "logger:get");   // more here https://docs.encedo.com/hem-api/reference/api-reference/audit-log#required-access-scope
if ($token == false) goto print_and_exit;                    // exit on error
// e) get logger signer public key
$ret_val = false;
$dummy_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/logger/key", $ret_val, $dummy_val, $token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
// check the key returned
$msg = base64_decode($ret_val['nonce']) ;
$sig = base64_decode($ret_val['nonce_signed']);
$pubkey = base64_decode($ret_val['key']);
$hem = base64url_encode( $pubkey );
$ret = sodium_crypto_sign_verify_detached( $sig, $msg, $pubkey);
if ($ret == false) goto print_and_exit;                   // ups - wtf?
// f) run code different per configuration
$log = false;
if ( strstr($test_cfg['conf'], "PPA") ) {
  // this is code for Encedo PPA
  //a) get current list of log entries
  $ret_val = false;
  $dummy_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/logger/list/0", $ret_val, $dummy_val, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
  $log_list_0 = $ret_val;
  //b) reboot
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "system:config");
  if ($token == false) goto print_and_exit;                    // exit on error
  $ret_val = false;
  $dummy_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/reboot", $ret_val, $dummy_val, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
  if ( !helper_wait_reboot($cfg_domain) ) goto print_and_exit;    // DEV-502: wait for the new boot (was a fixed sleep)
  //c) new log, new authentication
  $ret = helper_checkin($cfg_domain);
  if ($ret == false) goto print_and_exit;                     // exit on error
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "system:config");
  if ($token == false) goto print_and_exit;                    // exit on error
  $ret_val = false;
  $dummy_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/reboot", $ret_val, $dummy_val, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
  if ( !helper_wait_reboot($cfg_domain) ) goto print_and_exit;    // DEV-502: wait for the new boot (was a fixed sleep)
  //d) new log, new authentication
  $ret = helper_checkin($cfg_domain);
  if ($ret == false) goto print_and_exit;                     // exit on error
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "logger:get");
  if ($token == false) goto print_and_exit;                    // exit on error
  //echo "    Token: $token\n";
  $ret_val = false;
  $dummy_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/logger/list/0", $ret_val, $dummy_val, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
  $last_log_id = $ret_val['newest'];                           // DEV-483: the newest downloadable log (the current file is not listed)
  //e) download log file
  $ret_val = false;
  $dummy_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/logger/$last_log_id", $ret_val, $dummy_val, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
  //process string into array on entries
  $log = array();
  foreach(preg_split("/((\r?\n)|(\r\n?))/", $ret_val) as $line){
    $split = explode("|", $line);
    $x = count($split);
    if ($x == 7) $log[] = $line;  //log entries has always 7 fields
  }
} else {
  // this is code for Encedo EPA
  //a) reboot
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "system:config");
  if ($token == false) goto print_and_exit;                    // exit on error
  $ts = time(); //get timestamp anchor
  $ret_val = false;
  $dummy_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/reboot", $ret_val, $dummy_val, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
  sleep(30);  //wait

  //b) new log begin - make some entries
  $ret = helper_checkin($cfg_domain);
  if ($ret == false) goto print_and_exit;                     // exit on error
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "system:config");
  if ($token == false) goto print_and_exit;                    // exit on error
  $ret_val = false;
  $dummy_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/reboot", $ret_val, $dummy_val, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
  sleep(30);  //wait
  //c) get log from external logserver (last N second of log entries) - encedo backend API
  $ret_val = false;
  $now = time();
  $last = $now - $ts + 1;
  //echo "s: $ts  now:$now  last:$last\n";
  $ret_stat = http_transaction("https", "GET", "api.encedo.com", "/cctest/getmqttlog/$hem/$authkey/$last", $ret_val);
  if ($ret_stat != 200) goto print_and_exit;                   // non 200 measn error getting/downloadin log entries from MQTT syslog server
  $log = $ret_val;
}
if ($log == false)   goto print_and_exit;                    // expected is having a log data a'ka ARRAY (not false)
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
// a) set RTC clock
$ret = helper_checkin($cfg_domain);
if ($ret == false) goto print_and_exit;                     // exit on error
// b) perform local USER authentication
$token = helper_authorize($cfg_domain, $cfg_passpharse, "logger:get");   // more here https://docs.encedo.com/hem-api/reference/api-reference/audit-log#required-access-scope
if ($token == false) goto print_and_exit;                    // exit on error
// c) get logger signer public key
$ret_val = false;
$dummy_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/logger/key", $ret_val, $dummy_val, $token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
// check the key returned
$msg = base64_decode($ret_val['nonce']) ;
$sig = base64_decode($ret_val['nonce_signed']);
$pubkey = base64_decode($ret_val['key']);
$ret = sodium_crypto_sign_verify_detached( $sig, $msg, $pubkey);
if ($ret == false) goto print_and_exit;                   // ups - wtf?
// d) validate log entries - DEV-500: format v2 required (per-file key certified by the device key, every line signed); a v1 log is reported and fails
$report = array();
$ret = encedo_log_verify($pubkey, $log, $report);
echo "    log format v" . $report['version'] . ", " . $report['lines'] . " lines, " . $report['headers'] . " header(s), " . $report['rotations'] . " rotation(s), " . $report['lost'] . " lost" . (count($report['gaps']) ? ", seq gaps: " . implode(" ", $report['gaps']) : "") . "\n";
foreach ($report['errors'] as $e) echo "    $e\n";
if ( ($ret != true) || ($report['version'] != 2) || count($report['gaps']) ) goto print_and_exit;
// e) tampering is detected: a changed ts in one line (signature), a removed line (seq gap)
$i = intdiv(count($log), 2);
$bad = $log; $f = explode('|', $bad[$i]); $f[1] = dechex(hexdec($f[1]) + 1); $bad[$i] = implode('|', $f);
if ( encedo_log_verify($pubkey, $bad, $r) ) { echo "ERROR: a modified line verified\n"; goto print_and_exit; }
$bad = $log; array_splice($bad, $i, 1);
encedo_log_verify($pubkey, $bad, $r);
if ( count($r['gaps']) != 1 ) { echo "ERROR: a removed line left no seq gap\n"; goto print_and_exit; }
// f) set result
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
// DEV-483: /system/status without "logger" (the log works); PPA: logger/list statistics, limit, the current file not listed
$ret_val = false;
$dummy_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/status", $ret_val, $dummy_val);
if ( ($ret_stat != 200) || isset($ret_val['logger']) ) { echo "ERROR: status logger " . json_encode(@$ret_val['logger']) . "\n"; goto print_and_exit; }
if ( strstr($test_cfg['conf'], "PPA") ) {
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "logger:get");
  if ($token == false) goto print_and_exit;                    // exit on error
  $ret_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/logger/list/0", $ret_val, $dummy_val, $token);
  if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
  $l = $ret_val;
  foreach (array('offset', 'total', 'listed', 'oldest', 'newest', 'current', 'id') as $f) if (!isset($l[$f])) { echo "ERROR: list/0 without '$f'\n"; goto print_and_exit; }
  if ( in_array($l['current'], $l['id']) ) { echo "ERROR: the current file is listed\n"; goto print_and_exit; }
  $ret_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/logger/" . $l['current'], $ret_val, $dummy_val, $token);
  if ( $ret_stat != 409 ) { echo "ERROR: GET current: HTTP $ret_stat (409 expected)\n"; goto print_and_exit; }
  foreach (array($l['oldest'], $l['newest']) as $id) {
    $ret_val = false;
    $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/logger/$id", $ret_val, $dummy_val, $token);
    if ( $ret_stat != 200 ) { echo "ERROR: GET $id: HTTP $ret_stat\n"; goto print_and_exit; }
  }
  $sorted = $l['id'];
  sort($sorted);
  if ( ($l['total'] <= 128) && (($l['oldest'] !== $sorted[0]) || ($l['newest'] !== end($sorted)) || ($l['listed'] !== $l['total'])) ) { echo "ERROR: oldest / newest / listed\n"; goto print_and_exit; }
  // limit: slices of list/0, capped at 128; bad limit 400; a page after the end is empty
  foreach (array(array("0/2", 0, 2), array("1/2", 1, 2), array("0/500", 0, 128)) as $p) {
    $ret_val = false;
    $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/logger/list/" . $p[0], $ret_val, $dummy_val, $token);
    if ( ($ret_stat != 200) || ($ret_val['id'] !== array_slice($l['id'], $p[1], $p[2])) || ($ret_val['total'] !== $l['total']) ) { echo "ERROR: list/" . $p[0] . ": HTTP $ret_stat\n"; goto print_and_exit; }
  }
  foreach (array("0/0", "0/x") as $p) {
    $ret_val = false;
    $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/logger/list/$p", $ret_val, $dummy_val, $token);
    if ( $ret_stat != 400 ) { echo "ERROR: list/$p: HTTP $ret_stat (400 expected)\n"; goto print_and_exit; }
  }
  $ret_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/logger/list/" . $l['total'], $ret_val, $dummy_val, $token);
  if ( ($ret_stat != 200) || (count($ret_val['id']) != 0) ) { echo "ERROR: list after the end: HTTP $ret_stat\n"; goto print_and_exit; }
}
// a) set result
$test_cfg['subtests'][3] = 'OK';                             // mark this subtest as OK
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
