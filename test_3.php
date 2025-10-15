<?php

include "libs/lib.php";
include "config.php";


// test name, descr & number of subtests
$test_name = "T-3";
$test_descr = "Local user authentication";
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
// a) get TOE status - discover correct domain & https status
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/status", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
if ( isset($ret_val['inited']) ) goto print_and_exit;      // exit as well if prereq not fulfill - dev not inited!
if ( isset($ret_val['hostname']) ) {                       // remap domain name to the correct one
  $cfg_domain = $ret_val['hostname'];                      
  echo "  New FQDN: $cfg_domain \n";
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
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/checkin", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               // exit on API call FAIL
if ( !isset($ret_val['check']) ) goto print_and_exit;      // exit as well if missformated reply
$post_data = $ret_val;
$ret_val = false;
$ret_stat = http_transaction("https", "POST", "api.encedo.com", "/checkin", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               // exit on API call FAIL
if ( !isset($ret_val['checked']) ) goto print_and_exit;    // exit as well if missformated reply
$post_data = $ret_val;
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/system/checkin", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               // exit on API call FAIL
if ( !isset($ret_val['status']) ) goto print_and_exit;    // exit as well if missformated reply
// d) perform local USER authentication
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/auth/token", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               // exit on API call FAIL
$auth_challange = $ret_val;
//generate authentication kesy based on config constants
$password = $cfg_passpharse;
$salt = $auth_challange['eid'];
$user_secret = hash_pbkdf2("sha256", $password, $salt, 600000, 32, true);
$user_public_key = sodium_crypto_box_publickey_from_secretkey($user_secret);
//echo "USER Private key: " . base64_encode($user_secret) . "\n";
//echo "USER Public key:  " . base64_encode($user_public_key) . "\n";
$ext_pubkey = base64_decode($auth_challange['spk']);
$auth_val_user = array(                                 
  'jti' => $auth_challange['jti'],
  'aud' => $auth_challange['spk'],
  'exp' => $auth_challange['exp'],
  'iat' => time(),
  'iss' => base64_encode($user_public_key),
  'scope' => "system:config",
  'ctx' => "place_here_max_64chars"
  );
unset($auth_challange);  
//authentication USER and get token
$auth_data_user = ejwt_generate($auth_val_user, $user_secret, $ext_pubkey);
$post_data = json_encode( array('auth' => $auth_data_user) );
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/auth/token", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               // exit on API call FAIL
$user_auth_token = $ret_val['token'];
$user_auth_token_save = $user_auth_token;
//echo "  USER token: $user_auth_token\n";
$token_parts = explode(".", $user_auth_token);
$token_details = json_decode(base64_decode($token_parts[1]), true);
//echo "    scope=" . $token_details['scope'] ." role=" . $token_details['sub'] . " expire=" . $token_details['exp'] . "\n";
if ($token_details['sub'] != 'U') goto print_and_exit;    // fail if token role is not USER
// e) perform local ADMIN authentication
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/auth/token", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               // exit on API call FAIL
$auth_challange = $ret_val;                                 //renew challange
//generate authentication kesy based on config constants
$password = $cfg_passpharse_admin;
$salt = $auth_challange['eid'];
$admin_secret = hash_pbkdf2("sha256", $password, $salt, 600000, 32, true);
$admin_public_key = sodium_crypto_box_publickey_from_secretkey($admin_secret);
//echo "ADMIN Private key: " . base64_encode($admin_secret) . "\n";
//echo "ADMIN Public key:  " . base64_encode($admin_public_key) . "\n";
$ext_pubkey = base64_decode($auth_challange['spk']);
$auth_val_admin = array(                                 
  'jti' => $auth_challange['jti'],
  'aud' => $auth_challange['spk'],
  'exp' => $auth_challange['exp'],
  'iat' => time(),
  'iss' => base64_encode($admin_public_key),
  'scope' => "system:config"
  );
unset($auth_challange);  
//authentication ADMIN and get token
$auth_data_admin = ejwt_generate($auth_val_admin, $admin_secret, $ext_pubkey);
$post_data = json_encode( array('auth' => $auth_data_admin) );
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/auth/token", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               // exit on API call FAIL
$admin_auth_token = $ret_val['token'];
//echo "  ADMIN token: $admin_auth_token\n";
$token_parts = explode(".", $admin_auth_token);
$token_details = json_decode(base64_decode($token_parts[1]), true);
//echo "    scope=" . $token_details['scope'] ." role=" . $token_details['sub'] . " expire=" . $token_details['exp'] . "\n";
if ($token_details['sub'] != 'M') goto print_and_exit;    // fail if token role is not ADMIN/master
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
// a) check ROLE validation
// USER is allowed to call this API but ADMIN is not
// check user token
$ret_val = false;
$dummy_post_data = '{"epk":"SfxY+3RupkwK82cpOO+30VHyPMm0LAlYT+WeNtpIx2A="}';    // just a placeholder, 
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/auth/ext/init", $ret_val, $dummy_post_data, $user_auth_token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               // expected 200 is allowed https://docs.encedo.com/hem-api/reference/api-reference/authorization/external-authenticator/registration#allowed-users
// check admin token
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/auth/ext/init", $ret_val, $dummy_post_data, $admin_auth_token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 403 ) goto print_and_exit;               // expected 403 AS is NOT allowed 
// b) check SCOPE validation
// both tokens got required SCOPE
// check user token
$ret_val = false;
$dummy_post_data = false;;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/logger/key", $ret_val, $dummy_post_data, $user_auth_token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 403 ) goto print_and_exit;               // expected 403 as has wrong scope https://docs.encedo.com/hem-api/reference/api-reference/audit-log#required-access-scope
// check admin token
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/logger/key", $ret_val, $dummy_post_data, $admin_auth_token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 403 ) goto print_and_exit;               // expected 403 
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
// a) performe correct user authentication 
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/auth/token", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               // exit on API call FAIL
$auth_challange = $ret_val;
//generate authentication kesy based on config constants
$password = $cfg_passpharse;
$salt = $auth_challange['eid'];
$user_secret = hash_pbkdf2("sha256", $password, $salt, 600000, 32, true);
$user_public_key = sodium_crypto_box_publickey_from_secretkey($user_secret);
$ext_pubkey = base64_decode($auth_challange['spk']);
$auth_val_user = array(                                 
  'jti' => $auth_challange['jti'],
  'aud' => $auth_challange['spk'],
  'exp' => $auth_challange['exp'],
  'iat' => time(),
  'iss' => base64_encode($user_public_key),
  'scope' => "system:config"
  );
unset($auth_challange);  
//authentication USER and get token
$auth_data_user = ejwt_generate($auth_val_user, $user_secret, $ext_pubkey);
$post_data = json_encode( array('auth' => $auth_data_user) );
$ret_val = false;
$hrts = hrtime(true);
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/auth/token", $ret_val, $post_data);
$hrts = intval((hrtime(true) - $hrts) / 1000000);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               // exit on API call FAIL
$user_auth_token = $ret_val['token'];
//echo "  USER token: $user_auth_token\n";
//echo "    elapsed (ms): $hrts\n";
$auth_correct_issue_time = $hrts;
if ($auth_correct_issue_time < 500) goto print_and_exit;    //SFR FPT_AFL.1 - min response time is 500ms
// b) perform incorrect authentication 5 times
$counter = 0;
$subtest3_ok = false;
do {
  $ret_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/auth/token", $ret_val);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;               // exit on API call FAIL
  $auth_challange = $ret_val;
  //generate authentication kesy based on config constants
  $password = "wrong password";
  $salt = $auth_challange['eid'] ;
  $user_secret = hash_pbkdf2("sha256", $password, $salt, 600000, 32, true);
  $user_public_key = sodium_crypto_box_publickey_from_secretkey($user_secret);
  $ext_pubkey = base64_decode($auth_challange['spk']);
  $auth_val_user = array(                                 
    'jti' => $auth_challange['jti'],
    'aud' => $auth_challange['spk'],
    'exp' => $auth_challange['exp'],
    'iat' => time(),
    'iss' => base64_encode($user_public_key),
    'scope' => "system:config"
    );
  unset($auth_challange);  
  //authentication USER and get token
  $auth_data_user = ejwt_generate($auth_val_user, $user_secret, $ext_pubkey);
  $post_data = json_encode( array('auth' => $auth_data_user) );
  $ret_val = false;
  $hrts = hrtime(true);
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/auth/token", $ret_val, $post_data);
  $hrts = intval((hrtime(true) - $hrts) / 1000000);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 401 ) goto print_and_exit;               // expected 401 as auth is invalid (wrong password)
  //echo "    elapsed (ms): $hrts (ref:$auth_correct_issue_time)\n";
  //check round
  $counter++;
  //regards SFR FPT_AFL.1 - after 3 failed authentication, response time is 3x loger (3x500ms insteed of 1x500ms )
  if ($counter > 3) {
     if ($hrts > (3*500)) { 
       $subtest3_ok = true;                                 // expected correct result - after 3 failed auth response time increase
       $last_failed_auth_time = time();                     //save timestamp of last failed authentication
     }
  }  
  if ($counter >= 5) break;
  sleep(1);  
} while (true);  
if ($subtest3_ok == false) goto print_and_exit;          // subtest failed - 3 (three) wrong auth not detected
// c) now correct auth for next 20sec
$start_time = $last_failed_auth_time - 1;                 //-1 as a jitter, we measure time inaccurate (1sec res only)
//echo "start time: $start_time \n";
$counter = 0;
$subtest3_ok = false;
do {
  $ret_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/auth/token", $ret_val);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;               // exit on API call FAIL
  $auth_challange = $ret_val;
  //generate authentication kesy based on config constants
  $password = $cfg_passpharse;
  $salt = $auth_challange['eid'];
  $user_secret = hash_pbkdf2("sha256", $password, $salt, 600000, 32, true);
  $user_public_key = sodium_crypto_box_publickey_from_secretkey($user_secret);
  $ext_pubkey = base64_decode($auth_challange['spk']);
  $auth_val_user = array(                                 
    'jti' => $auth_challange['jti'],
    'aud' => $auth_challange['spk'],
    'exp' => $auth_challange['exp'],
    'iat' => time(),
    'iss' => base64_encode($user_public_key),
    'scope' => "system:config"
    );
  unset($auth_challange);  
  //authentication USER and get token
  $auth_data_user = ejwt_generate($auth_val_user, $user_secret, $ext_pubkey);
  $post_data = json_encode( array('auth' => $auth_data_user) );
  $ret_val = false;
  $hrts = hrtime(true);
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/auth/token", $ret_val, $post_data);
  $hrts = intval((hrtime(true) - $hrts) / 1000000);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;               // expected 401 as auth is invalid (wrong password)
  //echo "    elapsed (ms): $hrts\n";
  // check round
  $counter++;
  $now_is = time();
  $elapsed = $now_is - $start_time;
  //echo "   counter: $counter \n";
  //echo "    now is: $now_is \n";
  //echo "   elapsed: $elapsed  sec\n\n";
  //regards SFR FPT_AFL.1 - after 15sec after last failed auth, reset longer response time
  if ($elapsed > 15) {
     if ($hrts < 3*500) $subtest3_ok = true;                // expected correct action
  }
  if ( $elapsed > 30) break;                                // stop after 30sec
  sleep(1);  
} while (true);  
if ($subtest3_ok == false) goto print_and_exit;            // subtest failed - 3 (three) wrong auth not detected
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
$test_cfg['subtests'][4] = 'ERROR';                       // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) performe correct user authentication 
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/auth/token", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               // exit on API call FAIL
$auth_challange = $ret_val;
//generate authentication kesy based on config constants
$password = $cfg_passpharse;
$salt = $auth_challange['eid'];
$user_secret = hash_pbkdf2("sha256", $password, $salt, 600000, 32, true);
$user_public_key = sodium_crypto_box_publickey_from_secretkey($user_secret);
$ext_pubkey = base64_decode($auth_challange['spk']);
$auth_val_user = array(                                 
  'jti' => $auth_challange['jti'],
  'aud' => $auth_challange['spk'],
  'exp' => $auth_challange['exp'],
  'iat' => time(),
  'iss' => base64_encode($user_public_key),
  'scope' => "system:config"
  );
unset($auth_challange);  
//authentication USER and get token
$auth_data_user = ejwt_generate($auth_val_user, $user_secret, $ext_pubkey);
$post_data = json_encode( array('auth' => $auth_data_user) );
$ret_val = false;
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/auth/token", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               // exit on API call FAIL
$user_auth_token = $ret_val['token'];
//echo "  USER token: $user_auth_token\n";
// b) check token by using it
$ret_val = false;
$dummy_post_data = '{"epk":"SfxY+3RupkwK82cpOO+30VHyPMm0LAlYT+WeNtpIx2A="}';    // just a placeholder, 
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/auth/ext/init", $ret_val, $dummy_post_data, $user_auth_token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               // expected 200 if allowed 
// c) modify token by changing 'exp' value (extending lifespan of the token)
$token_parts = explode(".", $user_auth_token);
$token_details = json_decode(base64_decode($token_parts[1]), true);
$token_details['exp'] = $token_details['exp'] + 3600;       //add 3600sec to lifespan
$new_token = $token_parts[0] . '.' . base64_encode(json_encode($token_details)) .'.' . $token_parts[2];
//use new token
$ret_val = false;
$dummy_post_data = '{"epk":"SfxY+3RupkwK82cpOO+30VHyPMm0LAlYT+WeNtpIx2A="}';    // just a placeholder, 
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/auth/ext/init", $ret_val, $dummy_post_data, $new_token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 401 ) goto print_and_exit;               // expected 401 as token is non-genuine
// d) set result
$test_cfg['subtests'][4] = 'OK';                           // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 5        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST5:
echo "  subtest-5\n";
$test_cfg['subtests'][5] = 'ERROR';                       // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) performe correct user authentication 
$token = helper_authorize($cfg_domain, $cfg_passpharse, "system:config", 120); 
if ($token == false) goto print_and_exit;
// b) check token by using it
$ret_val = false;
$dummy_post_data = '{"epk":"SfxY+3RupkwK82cpOO+30VHyPMm0LAlYT+WeNtpIx2A="}';    // just a placeholder, 
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/auth/ext/init", $ret_val, $dummy_post_data, $user_auth_token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               // expected 200 if allowed 
// c) wait until teh token expire
$token_parts = explode(".", $user_auth_token);
$token_details = json_decode(base64_decode($token_parts[1]), true);
//echo "Local time: " . date("H:i:s") . "\n";
//echo " Token IAT: " . date("H:i:s ", $token_details['iat']) . "\n";
//echo " Token EXP: " . date("H:i:s", $token_details['exp']) . "\n";
$slp = $token_details['exp'] - time();
//echo " sleep for: $slp sec\n";
sleep($slp + 3);
//echo "Local time: " . date("H:i:s") . "\n";
// d) check token by using it - should fail
$ret_val = false;
$dummy_post_data = '{"epk":"SfxY+3RupkwK82cpOO+30VHyPMm0LAlYT+WeNtpIx2A="}';    // just a placeholder, 
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/auth/ext/init", $ret_val, $dummy_post_data, $user_auth_token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 401 ) goto print_and_exit;               // expected 401 as token expired
// e) set result
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
  $test_cfg['elapsed'] = intval((hrtime(true) - $test_cfg['elapsed']) / 1000000);
  echo "\nTest summary:\n";
  print_result( $test_cfg );  
  die;

/////////////////////////////////////////////////////////////////////
// end of file    ///////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
