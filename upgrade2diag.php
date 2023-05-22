<?php

include "libs/lib.php";
include "config.php";


//official firmware 1.0.1
$filename_hex_path_official = "https://api.encedo.com/download/firmware/jysYQzxKRb21I5I5QGRuoUF3bCsb9Pcl2M3k8jI1gVQBZGIlE6nDDibJWkxP4-hml_3YhD17E2BlGF1yMCxRBg/hex";

//offical firmware 1.0.1 with enabled DIAG module (API endpoints /api/diag/...)
$filename_hex_path_diagversion = "https://api.encedo.com/download/firmware/N2GotUmP4keUrgJTRFe9asMwjDTGzhCFnYxLTeIVxxVTOYT6yOWN_5aDg97oDBO2aKJqUHB9EfnYuIiFMFY8BA/hex";

// initialize the execution env
init_env();

// prompt
$arg = readline("Select (1 or 2) version to install: 1 - official, 2 - diagnostic? ");
if ($arg != 1 && $arg != 2) {
  echo "Wrong agrgument. Exit.\n";
  exit;
}
if ($arg == 1) {
  $filename_hex_path = $filename_hex_path_official;	
} else {
  $filename_hex_path = $filename_hex_path_diagversion;
}

/////////////////////////////////////////////////////////////////////
// Install DIAG enabled version of firmware /////////////////////////
/////////////////////////////////////////////////////////////////////
// a) get TOE status - discover correct domain & https status
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/status", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
if ( isset($ret_val['hostname']) ) {                       // remap domain name to the correct one
  $cfg_domain = $ret_val['hostname'];                      
}
$status = $ret_val;
// b) detect, get version details etc
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/version", $ret_val);
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
if ( !isset($status['inited']) ) {
  // d) perform local USER authentication
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "system:upgrade");   // anby scope is vali, more here https://docs.encedo.com/hem-api/reference/api-reference/system/upgrade/firmware#required-access-scope
  if ($token == false) goto print_and_exit;                    // exit on error
  //echo "    Token: $token\n";
} else {
	$token = false;
echo "not inited\n";	
}

// e) enable USBMODE upgrade procedure
$post_dummy = false;
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/upgrade/usbmode", $ret_val, $post_dummy, $token);
var_dump($ret_stat);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
//  f) perform upgrade ...
if (PHP_OS == "WINNT") {
  echo "Microsoft Windows platform detected. Use external tool (e.g. HyperTerminal) to send FW in Intel HEX format.\n";
  readline("Press Enter to continue (when upload is done)... ");
} else {
  echo "Downloading specific version of the firmware...\n";
  $con = file_get_contents( $filename_hex_path );
  $tmp = '/tmp/encedo_fw_diag.hex';
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
echo "Firmware version: " . $ret_val['fwv'] . "\n";
echo "Done\n";
exit;

print_and_exit:
  echo "\nUpsss :/\n";
  exit;

/////////////////////////////////////////////////////////////////////
// end of file    ///////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
