<?php

include "libs/lib.php";
include "config.php";


// test name, descr & number of subtests
$test_name = "T-7";
$test_descr = "Firmware upgrade functionality functionality";
$test_subtest_cnt = 1;    // just can run one of three tests


//a few test-specific consts
//official firmware 1.0.1
$filename_hex_path_official = "https://api.encedo.com/download/firmware/jysYQzxKRb21I5I5QGRuoUF3bCsb9Pcl2M3k8jI1gVQBZGIlE6nDDibJWkxP4-hml_3YhD17E2BlGF1yMCxRBg/hex";

//offical firmware 1.0.1 with enabled DIAG module (API endpoints /api/diag/...)
$filename_hex_path_diagversion = "https://api.encedo.com/download/firmware/N2GotUmP4keUrgJTRFe9asMwjDTGzhCFnYxLTeIVxxVTOYT6yOWN_5aDg97oDBO2aKJqUHB9EfnYuIiFMFY8BA/bin";

// official current version of the Encedo Manager
$dahsboard_path = "https://api.encedo.com/download/dashboard/current";


// prompt
$arg = readline("Select subtest to run: 1, 2 or 3? ");
if ($arg != 1 && $arg != 2 && $arg != 3) {
  echo "Wrong agrgument. Exit.\n";
  die;
}
$subtest_no = $arg;


// initialize the execution env
init_env();
$test_cfg = init_test($test_name, $test_descr, array( $subtest_no => 'sel' ), $cfg_tester);
if ( $cfg_debug ) var_dump( $cfg_domain );


echo "Processing...\n";
if ($subtest_no == 1) goto subtest1; else
if ($subtest_no == 2) goto subtest2; else
if ($subtest_no == 3) goto subtest3; else {
  echo "WTF?\n";
  die;
}


subtest1:
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
$test_cfg['fws'] = $ret_val['fws'];                         // 'fws' a'ka firmware siganture is unique per binary 
$test_cfg['conf'] = "ENCEDO PPA";
if ( strstr($ret_val['hwv'], "EPA") ) $test_cfg['conf'] = "ENCEDO EPA";
if ( strstr($test_cfg['conf'], "EPA") ) goto print_and_exit;    // test not for EPA
//echo "    Current firmware signature:  " . $test_cfg['fws'] . "\n";
// c) set RTC clock - code from T-1.3
$ret = helper_checkin($cfg_domain);
if ($ret == false) goto print_and_exit;                     // exit on error
// d) perform local USER authentication
$token = helper_authorize($cfg_domain, $cfg_passpharse, "system:upgrade");   // anby scope is vali, more here https://docs.encedo.com/hem-api/reference/api-reference/system/upgrade/firmware#required-access-scope
if ($token == false) goto print_and_exit;                    // exit on error
//echo "    Token: $token\n";
// e) enable USBMODE upgrade procedure
$post_dummy = false;
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/upgrade/usbmode", $ret_val, $post_dummy, $token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
//  f) perform upgrade ...
if (PHP_OS == "WINNT") {
  echo "Microsoft Windows platform detected. Use external tool (e.g. HyperTerminal) to send FW in Intel HEX format.\n";
  readline("Press Enter to continue (when upload is done)... ");
} else {
  echo "Downloading specific version of the firmware...\n";
  $con = @file_get_contents( $filename_hex_path_official );
  $tmp = '/tmp/encedo_fw.hex';
  file_put_contents($tmp, $con);
  echo "Waiting for a device...\n";
  do {
    if (file_exists("/dev/ttyACM0")) break;
    sleep(1);
  } while (true);

  echo "Upgrading...\n";
  $cmd = "sudo chmod +x ./libs/blbx && sudo ./libs/blbx -b $tmp -p /dev/ttyACM0";
  $stat = system( $cmd );
  echo "Waiting to boot up...\n";
  sleep(15);
}
// g) check status after reboot
$count = 0;
do {
  $ret_val = false;
  $ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/status", $ret_val);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat == 200 ) break;
  $count++;
  if ($count > 10) break;
  sleep(3);
} while (true);
if ( $ret_stat != 200 ) goto print_and_exit;                  // did not boot? upsss
// h) verify new version
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/version", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                  // exit on API call FAIL
//echo "    Upgraded firmware signature: " . $ret_val['fws'] . "\n";
// f) set result
$test_cfg['subtests'][1] = 'OK';                              // mark this subtest as OK
goto summary;
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


subtest2:
/////////////////////////////////////////////////////////////////////
// Subtest: 2        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
echo "  subtest-2\n";
$test_cfg['subtests'][2] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
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
$test_cfg['fws'] = $ret_val['fws'];                         // 'fws' a'ka firmware siganture is unique per binary 
$test_cfg['conf'] = "ENCEDO PPA";
if ( strstr($ret_val['hwv'], "EPA") ) $test_cfg['conf'] = "ENCEDO EPA";
if ( strstr($test_cfg['conf'], "EPA") ) goto print_and_exit;    // test not for EPA
//echo "    Current firmware signature:  " . $test_cfg['fws'] . "\n";
// c) set RTC clock - code from T-1.3
$ret = helper_checkin($cfg_domain);
if ($ret == false) goto print_and_exit;                     // exit on error
// d) perform local USER authentication
$token = helper_authorize($cfg_domain, $cfg_passpharse, "system:upgrade");   // anby scope is vali, more here https://docs.encedo.com/hem-api/reference/api-reference/system/upgrade/firmware#required-access-scope
if ($token == false) goto print_and_exit;                    // exit on error
//echo "    Token: $token\n";
// e) upload new file
$file_contents = file_get_contents( $filename_hex_path_diagversion ); 
if ($file_contents == false) goto print_and_exit;                    // exit on error
$post_data = $file_contents;
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/system/upgrade/upload_fw", $ret_val, $post_data, $token, "firmware.bin");
if ($ret_stat == false) goto print_and_exit;                     // exit on error
//  f) check uploaded file integrity
$counter = 0;
do {
  $post_dummy = false;
  $ret_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/upgrade/check_fw", $ret_val, $post_dummy, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat == 200 ) break;      // check ok
  if ( $ret_stat >= 400 ) break;      // an error
  $counter++;
  if ($counter > 12) break;     // timeoout after 120sec
  sleep(10);
} while (true);
if ( $ret_stat != 200 ) goto print_and_exit;    // unexpected error
//  g) install new firmware - reboot, recheck in bootloader ann install if check is ok, then boot
$post_dummy = false;
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/upgrade/install_fw", $ret_val, $post_dummy, $token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
sleep(30);
//  h) wait for boot
$counter = 0;
do {
  $ret_val = false;
  $ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/status", $ret_val);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat == 200 ) break;
  $counter++;
  if ($counter > 10) break;
  sleep(3);
} while (true);
if ( $ret_stat != 200 ) goto print_and_exit;                  // did not boot? upsss
// i) verify new version
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/version", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                  // exit on API call FAIL
//echo "    Upgraded firmware signature: " . $ret_val['fws'] . "\n";
// j) set result
$test_cfg['subtests'][2] = 'OK';                           // mark this subtest as OK
goto summary;
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


subtest3:
/////////////////////////////////////////////////////////////////////
// Subtest: 3        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
echo "  subtest-3\n";
$test_cfg['subtests'][3] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
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
$test_cfg['uis'] = $ret_val['uis'];
$test_cfg['fws'] = $ret_val['fws'];                         // 'fws' a'ka firmware siganture is unique per binary 
$test_cfg['conf'] = "ENCEDO PPA";
if ( strstr($ret_val['hwv'], "EPA") ) $test_cfg['conf'] = "ENCEDO EPA";
if ( strstr($test_cfg['conf'], "EPA") ) goto print_and_exit;    // test not for EPA
//echo "    Current dashboard signature:  " . $test_cfg['uis'] . "\n";
// c) set RTC clock - code from T-1.3
$ret = helper_checkin($cfg_domain);
if ($ret == false) goto print_and_exit;                     // exit on error
// d) perform local USER authentication
$token = helper_authorize($cfg_domain, $cfg_passpharse, "system:upgrade");   // anby scope is vali, more here https://docs.encedo.com/hem-api/reference/api-reference/system/upgrade/firmware#required-access-scope
if ($token == false) goto print_and_exit;                    // exit on error
//echo "    Token: $token\n";
// e) upload new file
$file_contents = file_get_contents($dahsboard_path); 
if ($file_contents == false) goto print_and_exit;                    // exit on error
$post_data = $file_contents;
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/system/upgrade/upload_ui", $ret_val, $post_data, $token, "webroot.tar");
if ($ret_stat == false) goto print_and_exit;                     // exit on error
//  f) check uploaded file integrity
$counter = 0;
do {
  $post_dummy = false;
  $ret_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/upgrade/check_ui", $ret_val, $post_dummy, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat == 200 ) break;      // check ok
  if ( $ret_stat >= 400 ) break;      // an error
  $counter++;
  if ($counter > 12) break;     // timeoout after 120sec
  sleep(10);
} while (true);
if ( $ret_stat != 200 ) goto print_and_exit;    // unexpected error
//  g) install new firmware - reboot, recheck in bootloader ann install if check is ok, then boot
$post_dummy = false;
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/upgrade/install_ui", $ret_val, $post_dummy, $token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
sleep(5);
//  h) wait for boot
$counter = 0;
do {
  $ret_val = false;
  $ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/status", $ret_val);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat == 200 ) break;
  $counter++;
  if ($counter > 10) break;
  sleep(3);
} while (true);
if ( $ret_stat != 200 ) goto print_and_exit;                  // did not boot? upsss
// i) verify new version
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/version", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                  // exit on API call FAIL
//echo "    Upgraded dashboard signature: " . $ret_val['uis'] . "\n";
// j) set result
$test_cfg['subtests'][3] = 'OK';                           // mark this subtest as OK
goto summary;
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

summary:
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
