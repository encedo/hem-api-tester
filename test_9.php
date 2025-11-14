<?php

include "libs/lib.php";
include "config.php";


// test name, descr & number of subtests
$test_name = "T-9";
$test_descr = "Audit log functionality";
$test_subtest_cnt = 2;


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
echo "1\n";  
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
echo "2\n";
  sleep(60);  //wait 
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
echo "3\n";
  sleep(60);  //wait 
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
  $last_log_id = $ret_val['id'][count($ret_val['id']) - 2];    // get second to the last log id
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
// d) validate log entries
$output = '';
$ret = encedo_log_integrity_check($pubkey, $log, $output);
if ($ret != true) goto print_and_exit;                    // log NOT validated, expected was TRUE
// e) set result
$test_cfg['subtests'][2] = 'OK';                           // mark this subtest as OK
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
