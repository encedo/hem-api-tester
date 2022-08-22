<?php

include "libs/lib.php";
include "config.php";


// test name, descr & number of subtests
$test_name = "T-5";
$test_descr = "External authenticator registration functionality";
$test_subtest_cnt = 3;


// initialize the execution env
init_env();
$test_cfg = init_test($test_name, $test_descr, $test_subtest_cnt, $cfg_tester);
if ( $cfg_debug ) var_dump( $cfg_domain );

echo "Processing...\n";


/////////////////////////////////////////////////////////////////////
// Subtest: 1        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
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
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/version", $ret_val);
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
// d) perform local USER authentication
$token = helper_authorize($cfg_domain, $cfg_passpharse, "system:config");
if ($token == false) goto print_and_exit;                    // exit on error
// e) get EID
$ret_val = false;
$not_used = false;    //dummy
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/config", $ret_val, $not_used, $token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200
$encedo_config = $ret_val;
// f) get backend API session token
$ret_val = false;
$post_data = json_encode( array('eid' => $encedo_config['eid']) );
$ret_stat = http_transaction("https", "POST", "api.encedo.com", "/notify/session", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
$epk = $ret_val['epk'];
// g) get TOE ext auth challange
$ret_val = false;
$post_data = json_encode( array('epk' => $epk) );
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/auth/ext/init", $ret_val, $post_data, $token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
$auth_challange = $ret_val;
// h) init registation session with backedn-app-encedo
$ret_val = false;
$post_data = json_encode( array('epk' => $epk, 'eid' => $auth_challange['eid'], 'request' => $auth_challange['request']) );
$ret_stat = http_transaction("https", "POST", "api.encedo.com", "/notify/register/init", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
$rid = $ret_val['rid'];
$qr_link = $ret_val['link'];
// i) generate QR code and show it - ready to scan
$hash = 'not_implemented_yet';
$qr_data = array( 'link' => $qr_link, 'hash' => $hash, 'user' => $encedo_config['user'], 'email' => $encedo_config['email'], 'hostname' => $encedo_config['hostname']);
$qr_body = json_encode( $qr_data );
$google_gen_qr_link = "https://chart.googleapis.com/chart?chs=500x500&cht=qr&choe=UTF-8&chl=" . urlencode( $qr_body );
//echo "QR code link\n$google_gen_qr_link\n";
$png = @file_get_contents($google_gen_qr_link);
$temp_file = tempnam(sys_get_temp_dir(), 'encedo');
file_put_contents($temp_file, $png);
if (PHP_OS == "WINNT") {
  shell_exec("start $temp_file");
} else {
  shell_exec("xdg-open \"$google_gen_qr_link\" 2>/dev/null 1>/dev/null &");	
}
// j) wait to user to scan the code - in polling mode
echo "    scan QR code - got 60sec\n";
$count = 0;
do {
  $ret_val = false;
  $ret_stat = http_transaction("https", "GET", "api.encedo.com", "/notify/register/check/$rid", $ret_val);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 202 ) break;                              // 202 when pending, expected 200 means the pairing in completed on APP side
  $count++;
  if ($count > 12) break;
  sleep(5);
} while (true);  
if ( $ret_stat != 200 ) goto print_and_exit;
$reply = $ret_val;  
// k) validate raiping at encedo
$ret_val = false;
$post_data = json_encode( array('pid' => $reply['pid'], 'reply' => $reply['reply']) );
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/auth/ext/validate", $ret_val, $post_data, $token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                  // expected 200 means the paring if completed (on TOE side)
$confirmation = $ret_val;
// l) confir and finalize pairing
$ret_val = false;
$post_data = json_encode( $confirmation );
$ret_stat = http_transaction("https", "POST", "api.encedo.com", "/notify/register/finalise/$rid", $ret_val, $post_data);
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
echo "  subtest-2\n";
$test_cfg['subtests'][2] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) perform local USER authentication
$token_incorrect = helper_authorize($cfg_domain, $cfg_passpharse, "system:wrong");
if ($token_incorrect == false) goto print_and_exit;                    // exit on error
// b) get EID - reuser correct token
$ret_val = false;
$not_used = false;    //dummy
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/config", $ret_val, $not_used, $token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200
$encedo_config = $ret_val;
// c) get backend API session token
$ret_val = false;
$post_data = json_encode( array('eid' => $encedo_config['eid']) );
$ret_stat = http_transaction("https", "POST", "api.encedo.com", "/notify/session", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                // expected 200 on success
$epk = $ret_val['epk'];
// d) get TOE ext auth challange
$ret_val = false;
$post_data = json_encode( array('epk' => $epk) );
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/auth/ext/init", $ret_val, $post_data, $token_incorrect);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 403 ) goto print_and_exit;
// e) set result
$test_cfg['subtests'][2] = 'OK';                           // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 3        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
echo "  subtest-3\n";
if ($diag_mode == false) {
  echo "    No DIAG mode, subtest will be skipped.\n";
  goto print_and_exit;
}
$test_cfg['subtests'][3] = 'ERROR';                       // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) simulate failer state
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/diag/break_temp", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200 - all good, FLS.1 triggered
sleep(3);
// b) reuser 'epk' and try get ext auth challange data
$ret_val = false;
$post_data = json_encode( array('epk' => $epk) );
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/auth/ext/init", $ret_val, $post_data, $token_incorrect);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 409 ) goto print_and_exit;                // expected 409 as FLS.1 is involved
// c) reboot TOE to clear failer state - only possible way
$ret_val = false;
$not_used = false;    //dummy
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/reboot", $ret_val, $not_used, $token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200 - all good
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
  echo "\nTest summary:\n";
  print_result( $test_cfg );  
  die;

/////////////////////////////////////////////////////////////////////
// end of file    ///////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
