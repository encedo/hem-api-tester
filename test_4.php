<?php

include "libs/lib.php";
include "config.php";


// test name, descr & number of subtests
$test_name = "T-4";
$test_descr = "TOE configuration change functionality";
$test_subtest_cnt = 4;


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
$diag_mode = strstr($test_cfg['fwv'], "-DIAG");
// c) set RTC clock - code from T-1.3
$ret = helper_checkin($cfg_domain);
if ($ret == false) goto print_and_exit;                     // exit on error
// d) perform local USER authentication
$token = helper_authorize($cfg_domain, $cfg_passpharse, "system:config");
if ($token == false) goto print_and_exit;                    // exit on error
//echo "  USER token: $token\n";
//$token_parts = explode(".", $token);
//$token_details = json_decode(base64_decode($token_parts[1]), true);
//echo "    scope=" . $token_details['scope'] ." role=" . $token_details['sub'] . " expire=" . $token_details['exp'] . "\n";
//read TOE configuration
$ret_val = false;
$not_used = false;    //dummy
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/config", $ret_val, $not_used, $token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200
$last_update_ts = $ret_val['uts'];
///write modified 'user'
$ret_val = false;
$new_user_name = 'Nickname-'.time();
$post_data = json_encode( array( 'user' => $new_user_name) );
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/system/config", $ret_val, $post_data, $token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200
if ( $ret_val['updated'] != true) goto print_and_exit;      //updated?
//re-read TOE configuration to check changes
$ret_val = false;
$not_used = false;    //dummy
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/config", $ret_val, $not_used, $token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200
if ($last_update_ts >= $ret_val['uts']) goto print_and_exit;  //'uts' update as changes applied correctly
// f) set result
$test_cfg['subtests'][1] = 'OK';                            // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 2        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST2:
echo "  subtest-2\n";
$test_cfg['subtests'][2] = 'ERROR';                        // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) check validator on API config endpoint
//read TOE configuration
$ret_val = false;
$not_used = false;    //dummy
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/config", $ret_val, $not_used, $token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200
$last_update_ts = $ret_val['uts'];
//validator handle too long argument
$ret_val = false;
$new_user_name = 'This is way too long, too long, tooooo loooong user field - max size is 64';
$post_data = json_encode( array( 'user' => $new_user_name) );
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/system/config", $ret_val, $post_data, $token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 400 ) goto print_and_exit;                //expected is 400 - arg incorrect
//validator handle unknown argument - will retunr 200 but no changes made
$ret_val = false;
$new_user_name = 'Nickname-'.time();
$post_data = json_encode( array( 'useR' => $new_user_name) ); //spot the typo
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/system/config", $ret_val, $post_data, $token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200
if ( $ret_val['updated'] == true) goto print_and_exit;      //updated should be false - firmware is looking up for know arguments only
//re-read TOE configuration to check no changes made
$ret_val = false;
$not_used = false;    //dummy
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/config", $ret_val, $not_used, $token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200
if ($last_update_ts != $ret_val['uts']) goto print_and_exit;  //'uts' update as changes applied correctly
// c) set result
$test_cfg['subtests'][2] = 'OK';                           // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 3        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST3:
echo "  subtest-3\n";
$test_cfg['subtests'][3] = 'ERROR';                       // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) performe correct user authentication with two different access scope, two tokens issued
//token with req scope
$token_correct = helper_authorize($cfg_domain, $cfg_passpharse, "system:config");
if ($token_correct == false) goto print_and_exit;                    // exit on error
//echo "  USER token: $token_correct\n";
//$token_parts = explode(".", $token_correct);
//$token_details = json_decode(base64_decode($token_parts[1]), true);
//echo "    scope=" . $token_details['scope'] ." role=" . $token_details['sub'] . " expire=" . $token_details['exp'] . "\n";
//token with invalid scope
$token_wrong = helper_authorize($cfg_domain, $cfg_passpharse, "system:reboot");
if ($token_correct == false) goto print_and_exit;                    // exit on error
//echo "  USER token: $token_wrong\n";
//$token_parts = explode(".", $token_wrong);
//$token_details = json_decode(base64_decode($token_parts[1]), true);
//echo "    scope=" . $token_details['scope'] ." role=" . $token_details['sub'] . " expire=" . $token_details['exp'] . "\n";
//try API with correct token
$ret_val = false;
$not_used = false;    //dummy
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/config", $ret_val, $not_used, $token_correct);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200
//try API with wrong token
$ret_val = false;
$not_used = false;    //dummy
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/config", $ret_val, $not_used, $token_wrong);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 403 ) goto print_and_exit;                //expected is 403 - token is incorrect
// b) check /attestation endpoint
if ( strstr($test_cfg['conf'], "PPA") ) {
  // this API endpoint do not check scope, just req a valid token
  $ret_val = false;
  $not_used = false;    //dummy
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/config/attestation", $ret_val, $not_used, $token_correct);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200
  $ret_val = false;
  $not_used = false;    //dummy
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/config/attestation", $ret_val, $not_used, $token_wrong);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200
  // c) check API /provisioning - should failed, only on PPA
  $ret_val = false;
  $not_used = '{"crt":"not_importand","genuine":"not_importand"}';
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/system/config/provisioning", $ret_val, $not_used, $token_correct);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 403 ) goto print_and_exit;                //expected is 403 - device provisioned
}
// d) set result
$test_cfg['subtests'][3] = 'OK';                           // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////
// Subtest: 4        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST4:
echo "  subtest-4\n";
if ($diag_mode == false) {
  echo "    No DIAG mode, subtest will be skipped.\n";
  goto print_and_exit;
}
$test_cfg['subtests'][4] = 'ERROR';                       // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) performe correct user authentication 
$token = helper_authorize($cfg_domain, $cfg_passpharse, "system:config");
if ($token == false) goto print_and_exit;                    // exit on error
//echo "  USER token: $token\n";
//$token_parts = explode(".", $token_correct);
//$token_details = json_decode(base64_decode($token_parts[1]), true);
//echo "    scope=" . $token_details['scope'] ." role=" . $token_details['sub'] . " expire=" . $token_details['exp'] . "\n";
//b) get config - should be ok
$ret_val = false;
$not_used = false;    //dummy
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/config", $ret_val, $not_used, $token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200 - all good
//c) go into failer state - simulated
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/diag/break_temp", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200 - all good, FLS.1 triggered
sleep(3);
//d) re-read config - should failed
if ( strstr($test_cfg['conf'], "PPA") ) {
  $ret_val = false;
  $not_used = false;    //dummy
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/config/attestation", $ret_val, $not_used, $token);
  var_dump($ret_stat);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 409 ) goto print_and_exit;                //expected is 409 - failer state
}
//e) reboot TOE to clear failer state - only possible way
$ret_val = false;
$not_used = false;    //dummy
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/reboot", $ret_val, $not_used, $token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200 - all good
// d) set result
$test_cfg['subtests'][4] = 'OK';                           // mark this subtest as OK
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
