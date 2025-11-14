<?php

include "libs/lib.php";
include "config.php";


// test name, descr & number of subtests
$test_name = "T-1";
$test_descr = "Check TOE basic functions";
$test_subtest_cnt = 5;


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
// a) detect, get version details etc
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/version", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
$test_cfg['hwv'] = $ret_val['hwv'];                         //   or follow on with processing
$test_cfg['blv'] = @$ret_val['blv'];
$test_cfg['fwv'] = $ret_val['fwv'];
$test_cfg['conf'] = "ENCEDO PPA";
if ( strstr($ret_val['hwv'], "EPA") ) $test_cfg['conf'] = "ENCEDO EPA";
// c) check status - prereq: uninitialised TOE
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/status", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               // exit on API call FAIL
if ( intval($ret_val['fls_state']) !== 0) {
  echo "ERROR: fls_state !=0, is " . $ret_val['fls_state'] . "\r\n";
  goto print_and_exit;     // exit as well if prereq not fulfill
}
$toe_status = $ret_val;
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
$test_cfg['subtests'][2] = 'ERROR';                        // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) check if TLS is available
if ( !isset($toe_status['https']) ) goto print_and_exit;  // exit if HTTPS (TLS) is not operating
// b) check TLS version - false if cert is invalid
$tls_info = check_tls($cfg_domain);                        // check TLS mode, automaticly validates certificate if is trustworthy
if ( $cfg_debug ) var_dump( $tls_info );
if ( $tls_info == false ) goto print_and_exit;            // exit of TLS check FAIL
if ( $tls_info['protocol'] != "TLSv1.3" ) goto print_and_exit;
// c) make a test TLS connection to TOE API
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/status", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               // exit on API call FAIL
// d) set result
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
// a) call checkin - first phase
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/checkin", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               // exit on API call FAIL
if ( !isset($ret_val['check']) ) goto print_and_exit;      // exit as well if missformated reply
// b) call Encedo backend API at api.encedo.com
$post_data = $ret_val;
$ret_val = false;
$ret_stat = http_transaction("https", "POST", "api.encedo.com", "/checkin", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               // exit on API call FAIL
if ( !isset($ret_val['checked']) ) goto print_and_exit;    // exit as well if missformated reply
// c) call TOE API to confirm checkin procedure
$post_data = $ret_val;
$ret_val = false;
$ret_stat = http_transaction("http", "POST", $cfg_domain, "/api/system/checkin", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               // exit on API call FAIL
if ( !isset($ret_val['status']) ) goto print_and_exit;    // exit as well if missformated reply
// d) check RTC status
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/status", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               // exit on API call FAIL
if ( !isset($ret_val['ts']) ) goto print_and_exit;         // exit as well if missformated reply
// e) set result
$test_cfg['subtests'][3] = 'OK';                           // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 4        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST4:
echo "  subtest-4\n";
$test_cfg['subtests'][4] = 'ERROR';                       // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) here is a demo JWT access token with scope 'system:config' - go to https://jwt.io for more info
$demo_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzY29wZSI6InN5c3RlbTpjb25maWciLCJzdWIiOiJVIiwiaWF0IjoxNjU5NDM2OTYyLCJleHAiOjE2NTk0NjU3NjIsImp0aSI6Im92L29ZcUVQbTRmUitoVmd5Ym1TaFhxdmJUdXRHSzlKTlRhZ1F3eG1yYTA9In0.1-ugkxpfjwwM1tSe9pOayVstSR1IptgT9evlcKO5ny8";
// b) TOE validates provided access token before processing API path
$ret_val = false;
$post_data = false;                                         // dummy just to fulfill lib function
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/status", $ret_val, $post_data, $demo_token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 401 ) goto print_and_exit;               // exit if API accept incorrect token, 401 is a expected result
// c) set result
$test_cfg['subtests'][4] = 'OK';                           // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 5        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST5:
echo "  subtest-5\n";
$test_cfg['subtests'][5] = 'ERROR';                         // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) call TOE /checkin API with malformated JSON string 
$post_data = '{"checked":"somedata"';                       // malformated JSON string - missing closing '}'
$ret_val = false;
$ret_stat = http_transaction("http", "POST", $cfg_domain, "/api/system/checkin", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 400 ) goto print_and_exit;               // expected 400 - "Bad Request"
// b) call TOE /checkin API with too long JSON string 
$post_data = '{"checked":"somedata';                        //JSON opening
$y = 7300 - (strlen($post_data) + 2);                       // max POSTed body size is 7300bytes (5x1460 a'ka 5*MTU)
for ($x=0; $x < $y+1; $x++) 
   $post_data = $post_data . chr(rand(65, 90));             // random chars 'A' - 'Z'
$post_data = $post_data . '"}';                             // closing - it is a correct JSON but way too long
$ret_val = false;                                           // post_data string is 1bytes too long now
$ret_stat = http_transaction("http", "POST", $cfg_domain, "/api/system/checkin", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 413 ) goto print_and_exit;               // expected 400 - "Bad Request"
// c) set result
$test_cfg['subtests'][5] = 'OK';                           // mark this subtest as OK
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
  if ($val == 'OK') $check_passed++;
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
