<?php

include "libs/lib.php";
include "config.php";


// test name, descr & number of subtests
$test_name = "T-8";
$test_descr = "Self-test functionality";
$test_subtest_cnt = 5;


$filename_probe = "out/probe.bin";


// initialize the execution env
init_env();
$test_cfg = init_test($test_name, $test_descr, $test_subtest_cnt, $cfg_tester);
if ( $cfg_debug ) var_dump( $cfg_domain );
$default_domain = $cfg_domain;

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
if ($ret_val['fls_state'] != 0) goto print_and_exit;       // expected result - if fls_state = 0 means NO ERRORS detected
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
$diag_mode = strstr($test_cfg['fwv'], "-DIAG");
// c) set RTC clock - code from T-1.3
$ret = helper_checkin($cfg_domain);
if ($ret == false) goto print_and_exit;                     // exit on error
// d) perform local USER authentication
$token = helper_authorize($cfg_domain, $cfg_passpharse, "system:config");   // anby scope is vali, more here https://docs.encedo.com/hem-api/reference/api-reference/system/self-test#required-access-scope
if ($token == false) goto print_and_exit;                    // exit on error
$test_started_at = time();
// e) run fill self-test
$ret_val = false;
$not_used = false;    //dummy
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/selftest", $ret_val, $not_used, $token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200
// f) full selftest takes time - KAT is complicated, pull TOE until object 'kat_busy' is returned
//pull
$counter = 0;
do {
  $ret_val = false;
  $not_used = false;    //dummy
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/selftest", $ret_val, $not_used, $token);
  //if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200
  if ( isset($ret_val['kat_busy'])) {
    sleep(10);
    $counter++;
    if ($counter > 24) break;   //wait max 10sec * 24times
  } else break;
} while( true);
$test_finished_at = time();
if ($ret_val['fls_state'] != 0) goto print_and_exit;          // expected result if fls_state = 0 means NO ERRORS detected
// f) set result
$test_cfg['subtests'][1] = 'OK';                              // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 2        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
echo "  subtest-2\n";
if ($diag_mode == false) {
  echo "    No DIAG mode, subtest will be skipped.\n";
  goto print_and_exit;
}
$test_cfg['subtests'][2] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) dry-run of a status check over TLS
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/status", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
// b) run test A: 20x connection over TLS
$count = 0;
$failers_testA = 0;
do {
  $ret_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/version", $ret_val);
  if ($ret_stat == false) {
    $err = error_get_last();
    //echo "    TLS ERROR: " . $err['message']. "\"";
    $failers_testA++;
  }
  $count++;
  if ($count >= 20) break;
  sleep(1);
} while(true);
//echo "    Test A: failed connections: $failers_testA\n";
// c) simulate pocket-modification on the fly by build-in diag tool
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/diag/break_tls", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
// d) re-run the test B: 20x connection over TLS
// re-run status check and this should failed over TLS - try 20x time and count failes vs success, fault-injection is non-deterministic
$count = 0;
$failers_testB = 0;
do {
  $ret_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/version", $ret_val);
  if ($ret_stat == false) {
    $err = error_get_last();
    //echo "    TLS ERROR: " . $err['message']. "\n";
    $failers_testB++;
  } 
  $count++;
  if ($count >= 20) break;
  sleep(1);
} while(true);
//echo "    Test B: failed connections: $failers_testB\n";
// e) reboot to reset the issue
$ret_val = false;
$dummy_post = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/reboot", $ret_val, $dummy_post, $token);  // http used as TLS may fail :)
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
// f) check status
if ($failers_testB == 0) goto print_and_exit;
sleep(30);
unset($token);
// e) set result
$test_cfg['subtests'][2] = 'OK';                           // mark this subtest as OK
/*
NOTE
Other test to perform. Enter:
1. curl -v https://cctest1659620927.ence.do/api/diag/break_tls - enable simulator
2. curl -v https://cctest1659620927.ence.do/api/system/status - run a few time, more details might be reported
*/
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 3        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
echo "  subtest-3\n";
$test_cfg['subtests'][3] = 'ERROR';                         // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) check if back online
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/status", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                
if ( $ret_val['fls_state'] != 0 ) goto print_and_exit;      //should not be in FLS state
// b) set RTC clock - code from T-1.3
$ret = helper_checkin($cfg_domain);
if ($ret == false) goto print_and_exit;                     // exit on error
// c) perform local USER authentication
$token = helper_authorize($cfg_domain, $cfg_passpharse, "system:config");   
if ($token == false) goto print_and_exit;                    // exit on error
// d) trigger TRNG failer
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/diag/break_trng", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200 
$last_val = $ret_val['last_val'];
//echo "    Shannon Entropy: $last_val\n";
sleep(20);    //wait - TRNG is tested every 15sec
// e) recheck status
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/status", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                
if ( $ret_val['fls_state'] == 0 ) goto print_and_exit;      //should be non zero (2 for TRNG)
// f) check new Shannon entropy test value
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/diag/break_trng", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200 - all good
$last_val = $ret_val['last_val'];
//echo "    Shannon Entropy (fls_state): $last_val\n";
if ( strstr($test_cfg['conf'], "EPA") ) {                   // on EPA reboot remotly
    // g) reboot TOE to clear failer state - only possible way
    $ret_val = false;
    $not_used = false;    //dummy
    $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/reboot", $ret_val, $not_used, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200 - all good
    sleep(30);
} else {                                                    // on PPA shutdown and ask user to re-plug
    $ret_val = false;
    $not_used = false;    //dummy
    $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/shutdown", $ret_val, $not_used, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200 - all good
    sleep(3);
    $ret_val = false;
    $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/status", $ret_val);  //this should failed after 8sec
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat == 200 ) goto print_and_exit;              // expected is NO ANSWER == false     
    readline("    Encedo PPA is shutdown! Unplug the device, wait 5sec and plug in again. Click Enter when done.");
    sleep(30);                                           
}
// h) check if back online
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/status", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                
if ( $ret_val['fls_state'] != 0 ) goto print_and_exit;      //should not be in FLS state
// i) gather sample of 2^24 bits on random bytes to run shannon test offsite
$probe_size = 2*1024*1024; //ib bytes, equivalent of 2^24 in bits
$probe_buf = '';
//echo date(DATE_RFC2822);
do {
  $ret_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/diag/test_trng", $ret_val);  
  //if ( $cfg_debug ) var_dump( $ret_val );
var_dump($ret_stat); 
var_dump(strlen($probe_buf));
  if ( $ret_stat != 200 ) goto print_and_exit;                
  if (isset($ret_val['rnd'])) {
    $rnd = base64_decode($ret_val['rnd']);
    $probe_buf .= $rnd;
  }
  if (strlen($probe_buf) >= $probe_size) break;
} while(true);
file_put_contents($filename_probe, $probe_buf);
//echo date(DATE_RFC2822);
// j) set result
$test_cfg['subtests'][3] = 'OK';                           // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 4        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
echo "  subtest-4\n";
$test_cfg['subtests'][4] = 'ERROR';                         // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) check if back online
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/status", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                
if ( $ret_val['fls_state'] != 0 ) goto print_and_exit;      //should not be in FLS state
// b) set RTC clock - code from T-1.3
$ret = helper_checkin($cfg_domain);
if ($ret == false) goto print_and_exit;                     // exit on error
// c) perform local USER authentication - config & key import & key list
$token_cfg = helper_authorize($cfg_domain, $cfg_passpharse, "system:config");   
if ($token_cfg == false) goto print_and_exit;                    // exit on error
//echo "  Token CONFIG: $token_cfg\n";
$token_imp = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:imp");   
if ($token_imp == false) goto print_and_exit;                    // exit on error
//echo "  Token IMPORT: $token_imp\n";
$token_list = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:list");   
if ($token_list == false) goto print_and_exit;                    // exit on error
//echo "  Token LIST: $token_list\n";
// d) import a demo key
$key_import_data = array( 'label' => "T8.4 demo key", 'type' => "CURVE25519", 'pubkey' => "QCe8CjCK4YVYWoxZbtZSUR84ttscG0N5yGsFhh6TjgQ=" );
$ret_val = false;
$post_data = json_encode( $key_import_data );
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/import", $ret_val, $post_data, $token_imp);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200 - all good
$kid = $ret_val['kid'];
// e) list key repo
$ret_val = false;
$not_used = false;    //dummy
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/keymgmt/list", $ret_val, $not_used, $token_list);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200 - all good
$keychain = $ret_val;
foreach($keychain['list'] as $item) {
  if ($item['kid'] == $kid) { //lookup for imported key details
    //var_dump($item);
    $key_mem_addr = $item['_addr'];
    $key_mem_len = $item['_len'];
  }
}
if (!isset($key_mem_addr)) goto print_and_exit;             //error if not found - this is odd :/
//printf("KEY addr:%08x  at  %02x\n", $key_mem_addr, $key_mem_len);
// f) get key body memdump
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/diag/memdump/$key_mem_addr/$key_mem_len", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200 - all good
$binbody = bin2hex(base64_decode($ret_val['dump']));
//echo "KEY body: $binbody\n";
// g) inject fault into keychain (key repo)
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/diag/corrupt_repo/$key_mem_addr", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               //expected is 200 - all good
// h) do memdump again
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/diag/memdump/$key_mem_addr/$key_mem_len", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200 - all good
$binbody2 = bin2hex(base64_decode($ret_val['dump']));
//echo "KEY body: $binbody2\n";   //bytes 4-7 are set to zero (second uint32_t)
if ( $binbody == $binbody2 ) goto print_and_exit;                //if equal - mem NOT currupted
// i) perform full self-test
$ret_val = false;
$not_used = false;    //dummy
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/selftest", $ret_val, $not_used, $token_cfg);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200 - all good
//pull
$counter = 0;
sleep(2);
do {
  $ret_val = false;
  $not_used = false;    //dummy
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/selftest", $ret_val, $not_used, $token_cfg);
  //if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200
  if ( isset($ret_val['kat_busy'])) {
    sleep(10);
    $counter++;
    if ($counter > 24) break;   //wait max 10sec * 24times
  } else break;
} while( true);
if ($ret_val['fls_state'] == 0) goto print_and_exit;          // expected result if fls_state = 8 
// j) wipe-out configuration - this error cannot be cleared or the key deleted (fls prohibits)
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/diag/wipe_config  ", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                
sleep(30);
// k) set result
$test_cfg['subtests'][4] = 'OK';                            // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 5        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
echo "  subtest-5\n";
$test_cfg['subtests'][5] = 'ERROR';                         // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) check if back online
$cfg_domain = $default_domain;                              // restore default domain name
// NOTE This subtest use HTTP not HTTPS as EPA will fail - diag/wipe_out config is diag tool and no cert will be uploaded to EPA after a wipe
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/status", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                
if ( $ret_val['fls_state'] != 0 ) goto print_and_exit;      //should not be in FLS state
// b) simulate 'temp' out of range
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/diag/break_temp", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200 
sleep(5); 
// e) recheck status
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/status", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                
if ( $ret_val['fls_state'] == 0 ) goto print_and_exit;      //should be non zero (2 for TRNG)
// f) reboot TOE to clear failer state - only possible way
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/reboot", $ret_val);    //works without token as device is wipe-out
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200 - all good
sleep(10);
// g) set result
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
