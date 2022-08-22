<?php

include "libs/lib.php";
include "config.php";


// test name, descr & number of subtests
$test_name = "T-12";
$test_descr = "Embedded storage management";
$test_subtest_cnt = 2;


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
$toe_status = $ret_val;
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
// c) test is for PPA only, will fail on EPA
if ( strstr($ret_val['hwv'], "EPA") ) goto print_and_exit;
// d) set RTC clock - code from T-1.3
$ret = helper_checkin($cfg_domain);
if ($ret == false) goto print_and_exit;                     // exit on error
// e) perform local USER authentication with scope required
$token_d0 = helper_authorize($cfg_domain, $cfg_passpharse, "storage:disk0:rw");  // more here https://docs.encedo.com/hem-api/reference/api-reference/storage#required-access-scope
if ($token_d0 == false) goto print_and_exit;                   // exit on error
// f) disk0 might be (default initialization configuration) be already unlock but in RO mode
//    lock it first, wait a moment and unlock in RW mode
//    disk1 is by default locked - assumption here or error otherwise
$disk0_status = explode(':', $toe_status['storage'][0]);
$disk1_status = explode(':', $toe_status['storage'][1]);
if ($disk1_status[1] != '-') goto print_and_exit;             //disk1 unlock - assume is by default locked
if ($disk0_status[1] != '-') { //true if disk0 unlock, so lock it up
  $ret_val = false;
  $not_used = false;    //dummy
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/storage/lock", $ret_val, $not_used, $token_d0);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200
  sleep(5); //give the OS time to notice it!
}
// g) unlock disk0
$ret_val = false;
$not_used = false;    //dummy
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/storage/unlock", $ret_val, $not_used, $token_d0);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200
// h) do the same for disk1
//perform local USER authentication with scope required
$token_d1 = helper_authorize($cfg_domain, $cfg_passpharse, "storage:disk1:rw");  // more here https://docs.encedo.com/hem-api/reference/api-reference/storage#required-access-scope
if ($token_d1 == false) goto print_and_exit;                   // exit on error
////unlock disk1
$ret_val = false;
$not_used = false;    //dummy
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/storage/unlock", $ret_val, $not_used, $token_d1);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200
// g) check is status is changed
sleep(5);
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/status", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200
$toe_status = $ret_val;
$disk0_status = explode(':', $toe_status['storage'][0]);
$disk1_status = explode(':', $toe_status['storage'][1]);
if ($disk0_status[1] != 'rw') goto print_and_exit;             //expected is 'rw'
if ($disk1_status[1] != 'rw') goto print_and_exit;             //as above
// the tesetr can now check if disk0 (labeled 'ENCEDO' is available, the same with disk1 (labeled 'ENCEDO SAFE');
// h) set result
$test_cfg['subtests'][1] = 'OK';                              // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 2        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
echo "  subtest-2\n";
$test_cfg['subtests'][2] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) perform disk0&1 lock
$ret_val = false;
$not_used = false;    //dummy
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/storage/lock", $ret_val, $not_used, $token_d0);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200
$ret_val = false;
$not_used = false;    //dummy
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/storage/lock", $ret_val, $not_used, $token_d1);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200
// b) check is status is changed
sleep(5);
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/status", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200
$toe_status = $ret_val;
$disk0_status = explode(':', $toe_status['storage'][0]);
$disk1_status = explode(':', $toe_status['storage'][1]);
if ($disk0_status[1] != '-') goto print_and_exit;             //expected is 'rw'
if ($disk1_status[1] != '-') goto print_and_exit;             //as above
// the tesetr can now check if disk0 (labeled 'ENCEDO' is available, the same with disk1 (labeled 'ENCEDO SAFE');
// c) set result
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
  echo "\nTest summary:\n";
  print_result( $test_cfg );  
  die;

/////////////////////////////////////////////////////////////////////
// end of file    ///////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
