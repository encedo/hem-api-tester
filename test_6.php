<?php

include "libs/lib.php";
include "config.php";


// test name, descr & number of subtests
$test_name = "T-6";
$test_descr = "External authenticator usage functionality";
$test_subtest_cnt = 3;   // DEV-436: 3 = multi-scope request


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
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/version", $ret_val);
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
// d) perform REMOTE USER authentication
// get backend EPK key
$ret_val = false;
$ret_stat = http_transaction("https", "GET", "api.encedo.com", "/notify/session", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
$epk = $ret_val['epk'];
// retrive auth challage
$req = array( 'epk' => $epk, 'exp' => time()+120, 'scope' => "system:config");
$post_data = json_encode( $req );
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/auth/ext/request", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
$auth_challange = $ret_val;
// send notification to the apps
$ret_val = false;
$post_data = $auth_challange;
$ret_stat = http_transaction("https", "POST", "api.encedo.com", "/notify/event/new", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
$eventid = $ret_val['eventid'];
@file_put_contents( __DIR__ . "/out/extauth_exchange.json", json_encode( array('type' => "event", 'eventid' => $eventid, 'expect' => "allow") ) );   // for ExtAuth_Simulator.php
echo "    check mobile app for notification - got 60sec\n";
$count = 0;
do {
  $ret_val = false;
  $ret_stat = http_transaction("https", "GET", "api.encedo.com", "/notify/event/check/$eventid", $ret_val);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 202 ) break;                              // 202 when pending, expected 200 means the pairing in completed on APP side
  $count++;
  if ($count > 12) break;
  sleep(5);
} while (true);
if ( $ret_stat != 200 ) goto print_and_exit;                 // other result than 200 means no user interaction in time frame
if (isset($ret_val['deny']) ) goto print_and_exit;              // if set user selected DENY on mobile app

$authreply = $ret_val['authreply'];
// validate reply and retrieve access token
$ret_val = false;
$post_data = json_encode( array('authreply' => $authreply) );
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/auth/ext/token", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                  // expected 200 means the paring if completed (on TOE side)
$token = $ret_val['token'];
//echo "    Token issued: $token\n";
// e) confirm token works
$ret_val = false;
$post_data = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/config", $ret_val, $post_data, $token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                  // expected 200 measn the pairing is completed on backend API
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
// a) perform REMOTE USER authentication and expect DENY returned
// get backend EPK key
$ret_val = false;
$ret_stat = http_transaction("https", "GET", "api.encedo.com", "/notify/session", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
$epk = $ret_val['epk'];
// retrive auth challage
$req = array( 'epk' => $epk, 'exp' => time()+60, 'scope' => "system:config");
$post_data = json_encode( $req );
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/auth/ext/request", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
$auth_challange = $ret_val;
// send notification to the apps
$ret_val = false;
$post_data = $auth_challange;
$ret_stat = http_transaction("https", "POST", "api.encedo.com", "/notify/event/new", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
$eventid = $ret_val['eventid'];
@file_put_contents( __DIR__ . "/out/extauth_exchange.json", json_encode( array('type' => "event", 'eventid' => $eventid, 'expect' => "deny") ) );   // for ExtAuth_Simulator.php
echo "    check mobile app for notification - got 60sec\n";
$count = 0;
do {
  $ret_val = false;
  $ret_stat = http_transaction("https", "GET", "api.encedo.com", "/notify/event/check/$eventid", $ret_val);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 202 ) break;                              // 202 when pending, expected 200 means the pairing in completed on APP side
  $count++;
  if ($count > 12) break;
  sleep(5);
} while (true);
if ( $ret_stat != 200 ) goto print_and_exit;                 // other result than 200 means no user interaction in time frame
if ( !isset($ret_val['deny']) ) goto print_and_exit;         // expect to get DENY
/*
NOTE:
The model of operating of Encedo HEM + APP is changed! The mobile app reply with 'authreply' ONLY is user selects ALLOW.
Otherwise the object is generated generated and 'deny'=true is returned. That is way Encedo is not challanged.
*/
// e) set result
$test_cfg['subtests'][2] = 'OK';                           // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 3        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST3:
echo "  subtest-3\n";
$test_cfg['subtests'][3] = 'ERROR';                         // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) REMOTE USER authentication with a multi-scope request (DEV-436): scope array -> the app gets the values separated by
//    spaces, approves them -> the token scope is an array and grants both endpoints
$ret_val = false;
$ret_stat = http_transaction("https", "GET", "api.encedo.com", "/notify/session", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
$epk = $ret_val['epk'];
$req = array( 'epk' => $epk, 'exp' => time()+120, 'scope' => array("keymgmt:list", "system:config"));
$post_data = json_encode( $req );
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/auth/ext/request", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
$auth_challange = $ret_val;
$ret_val = false;
$post_data = $auth_challange;
$ret_stat = http_transaction("https", "POST", "api.encedo.com", "/notify/event/new", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
$eventid = $ret_val['eventid'];
@file_put_contents( __DIR__ . "/out/extauth_exchange.json", json_encode( array('type' => "event", 'eventid' => $eventid, 'expect' => "allow") ) );   // for ExtAuth_Simulator.php
echo "    check mobile app for notification - got 60sec\n";
$count = 0;
do {
  $ret_val = false;
  $ret_stat = http_transaction("https", "GET", "api.encedo.com", "/notify/event/check/$eventid", $ret_val);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 202 ) break;                              // 202 when pending, 200 when the app answered
  $count++;
  if ($count > 12) break;
  sleep(5);
} while (true);
if ( $ret_stat != 200 ) goto print_and_exit;
if (isset($ret_val['deny']) ) goto print_and_exit;
$authreply = $ret_val['authreply'];
$ret_val = false;
$post_data = json_encode( array('authreply' => $authreply) );
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/auth/ext/token", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
$token = $ret_val['token'];
// b) the token scope is the approved array
$token_parts = explode(".", $token);
$token_details = json_decode(base64url_decode($token_parts[1]), true);
if ( $token_details['scope'] !== array("keymgmt:list", "system:config") ) { echo "    token scope " . json_encode($token_details['scope']) . "\n"; goto print_and_exit; }
// c) both values work
$ret_val = false;
$post_data = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/config", $ret_val, $post_data, $token);
if ( $ret_stat != 200 ) { echo "    system/config with the array token: HTTP $ret_stat\n"; goto print_and_exit; }
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/keymgmt/list", $ret_val, $post_data, $token);
if ( $ret_stat != 200 ) { echo "    keymgmt/list with the array token: HTTP $ret_stat\n"; goto print_and_exit; }
// d) set result
$test_cfg['subtests'][3] = 'OK';                           // mark this subtest as OK
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
