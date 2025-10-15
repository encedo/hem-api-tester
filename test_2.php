<?php

include "libs/lib.php";
include "config.php";


// test name, descr & number of subtests
$test_name = "T-2";
$test_descr = "TOE initialization";
$test_subtest_cnt = 3;


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
if ( !isset($ret_val['inited']) ) goto print_and_exit;      // exit as well if prereq not fulfill
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
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/checkin", $ret_val);
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
$ret_stat = http_transaction("http", "POST", $cfg_domain, "/api/system/checkin", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               // exit on API call FAIL
if ( !isset($ret_val['status']) ) goto print_and_exit;    // exit as well if missformated reply
// d) prepare new domain prefix and check availability
if ($cfg_enforce_ppa_domain == 0) {
  $new_prefix = "cctest" . time();
} else {   
  $new_prefix = 'my';
}
$new_fqdn = $new_prefix . ".ence.do";
echo "  New FQDN: $new_fqdn \n";
if ($cfg_enforce_ppa_domain == 0) {
  $ret_val = false;
  $ret_stat = http_transaction("https", "GET", "api.encedo.com", "/domain/check/$new_prefix", $ret_val);
  if ( $ret_stat != 404 ) goto print_and_exit;                // 404 means domain prefix is free (available)
}
// e) call initialization - TOE challenge phase
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/auth/init", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               // exit on API call FAIL
$init_challange = $ret_val;
// f) generate initialization data
//generate authentication kesy based on config constants
$password = $cfg_passpharse;
$salt = $init_challange['eid'];
$user_secret = hash_pbkdf2("sha256", $password, $salt, 600000, 32, true);
$user_public_key = sodium_crypto_box_publickey_from_secretkey($user_secret);
//echo "USER Private key: " . base64_encode($user_secret) . "\n";
//echo "USER Public key:  " . base64_encode($user_public_key) . "\n";
$password = $cfg_passpharse_admin;
$salt = $init_challange['eid'];
$admin_secret = hash_pbkdf2("sha256", $password, $salt, 600000, 32, true);
$admin_public_key = sodium_crypto_box_publickey_from_secretkey($admin_secret);
//echo "ADMIN Private key: " . base64_encode($admin_secret) . "\n";
//echo "ADMIN Public key:  " . base64_encode($admin_public_key) . "\n";
$ext_pubkey = base64_decode($init_challange['spk']);
$init_val = array(                                 //compose TOE req init data
  'jti' => $init_challange['jti'],
  'aud' => $init_challange['spk'],
  'exp' => $init_challange['exp'],
  'iat' => time(),
  'iss' => base64_encode($admin_public_key),
  'cfg' => array(
      'masterkey' => base64_encode($admin_public_key),  //masterkey is ignored
      'userkey' => base64_encode($user_public_key),
      'user' => $cfg_tester,
      'email' => "cctest@encedo.com",
      'hostname' => $new_fqdn,
      'ip' => "192.168.7.1",                      //EPA ignore this
      'storage_mode' => 81,                       //EPA ignore this
      'storage_disk0size' => 8388608,             //EPA ignore this
      'dnsd' => false,                            //EPA ignore this
      'trusted_ts' => true,
      'trusted_backend' => true,
      'allow_keysearch' => true,
      'gen_csr' => true,
      'origin' => "*"
      )
  );
$init_data = ejwt_generate($init_val, $admin_secret, $ext_pubkey);
// g) post initialization data by calling TOE/HEM API
$post_data = json_encode( array('init' => $init_data) );
$ret_val = false;
$ret_stat = http_transaction("http", "POST", $cfg_domain, "/api/auth/init", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               // exit on API call FAIL
$init_result = $ret_val;
// h) wait until storage format ends - only on PPA
do {
  $ret_val = false;
  $ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/status", $ret_val);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;
  if ( isset($ret_val['format']) ) {
    if ($ret_val['format'] == "done") break;
  } else {
    break;
  }
  sleep(1);
} while(true);
// i) finish initialization - register TLS certificate, upload to HEM and reboot
$ret_val = false;
if ($cfg_enforce_ppa_domain == 0) {
  // register new custom domain and retreive cert
  $post_array = array('csr' => $init_result['csr'], 'genuine' => $init_result['genuine']);
  if ( strstr($test_cfg['conf'], "EPA") ) {
    $post_array['cname'] = $cfg_domain;
  } else {
    $post_array['ip'] = "192.168.7.1";
  }
  $post_data = json_encode( $post_array );
  $ret_stat = http_transaction("https", "POST", "api.encedo.com", "/domain/register/$new_prefix/$authkey", $ret_val, $post_data);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( ( $ret_stat != 200 ) && ( $ret_stat != 201 ) ) goto print_and_exit;  // exit on API call FAIL
  if ( $ret_stat == 201 ) {
  // issuing may takes time - pull backedn until is not ready
    $id = $ret_val['id'];
    do {
      $ret_val = false;
      $ret_stat = http_transaction("https", "GET", "api.encedo.com", "/domain/register/$id", $ret_val);
      if ( $cfg_debug ) var_dump( $ret_val );
      if ( $ret_stat == 200 ) break;
      if ( $ret_stat >= 400 ) goto print_and_exit;  // exit on API call FAIL
      sleep(3);
    } while(true);  
    $cert_data = $ret_val;
  } else {
    $cert_data = $ret_val;
  }
} else {
  // ask for standard domain - a'ka public
  $post_array = array('genuine' => $init_result['genuine'], 'ip' => "192.168.7.1");
  $post_data = json_encode( $post_array );
  $ret_stat = http_transaction("https", "POST", "api.encedo.com", "/domain/register/$new_prefix/$authkey", $ret_val, $post_data);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;  // exit on API call FAIL
  $cert_data = $ret_val;
}
//echo "update config\n";
$ret_val = false;
$post_data = json_encode( array('tls' => $cert_data) );
$token = $init_result['token'];
$ret_stat = http_transaction("http", "POST", $cfg_domain, "/api/system/config", $ret_val, $post_data, $token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               // exit on API call FAIL
//echo "updated\n";
if ( isset($ret_val['reboot_required']) ) {
  sleep(1);
  $ret_val = false;
  $post_data = false;
  $ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/reboot", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;               // exit on API call FAIL
  sleep(15);
}
//echo "rebooted\n";
// j) final validation
$synch_tries = 3;                                           // reboot may takes more time - try N time to get synch
do {
  $ret_val = false;
  $ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/status", $ret_val);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat == 200 ) break;
  $synch_tries--;
  if ($synch_tries == 0) goto print_and_exit;             //timeout - indicate an error
  sleep(3);
} while (true);
// k) set RTC clock - code from T-1.3
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/checkin", $ret_val);
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
$ret_stat = http_transaction("http", "POST", $cfg_domain, "/api/system/checkin", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               // exit on API call FAIL
if ( !isset($ret_val['status']) ) goto print_and_exit;    // exit as well if missformated reply
// l) set result
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
// a) check if can repeat the initialization
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/auth/init", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 406 ) goto print_and_exit;               // expected 406 means already inited - expected state
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
// a) get TOE status - discover correct domain & https status
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/status", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;               // expected 406 means already inited - expected state
if ( !isset($ret_val['https']) ) goto print_and_exit;     // exit if HTTPS (TLS) is not operating
if ( isset($ret_val['hostname']) ) {                      // remap domain name to the correct one
  $cfg_domain = $ret_val['hostname'];                      //   however in this case it should be remaped already in subtest-1
}
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
