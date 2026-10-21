<?php

include "libs/lib.php";
include "config.php";


// test name, descr & number of subtests
$test_name = "T-1";
$test_descr = "Check TOE basic functions";
$test_subtest_cnt = 6;


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
// Subtest: 6        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST6:
echo "  subtest-6\n";
$test_cfg['subtests'][6] = 'ERROR';                         // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) security headers on an API response (DEV-426): nosniff, no-store, no Server/X-Powered-By, X-Request-ID echoed
$req_id = "t1-6-" . bin2hex( openssl_random_pseudo_bytes( 4 ) );
$hdrs = false;
$ret_stat = raw_https_request($cfg_domain, "GET /api/system/status HTTP/1.1\r\nHost: $cfg_domain\r\nX-Request-ID: $req_id\r\nConnection: close\r\n\r\n", $hdrs);
if ( $cfg_debug ) var_dump( $hdrs );
if ( $ret_stat != 200 ) goto print_and_exit;               // exit on API call FAIL
if ( @$hdrs['x-content-type-options'] !== "nosniff" ) goto print_and_exit;
if ( strpos(@$hdrs['cache-control'], "no-store") === false ) goto print_and_exit;
if ( isset($hdrs['server']) || isset($hdrs['x-powered-by']) ) goto print_and_exit;   // FW version must not leak
if ( @$hdrs['x-request-id'] !== $req_id ) goto print_and_exit;
// b) 401 carries WWW-Authenticate: Bearer (DEV-426)
$hdrs = false;
$ret_stat = raw_https_request($cfg_domain, "GET /api/system/status HTTP/1.1\r\nHost: $cfg_domain\r\nAuthorization: Bearer junk\r\nConnection: close\r\n\r\n", $hdrs);
if ( $cfg_debug ) var_dump( $hdrs );
if ( $ret_stat != 401 ) goto print_and_exit;               // expected 401 - invalid token
if ( strpos(@$hdrs['www-authenticate'], "Bearer") !== 0 ) goto print_and_exit;
// c) header names are case-insensitive (DEV-430): lowercase 'authorization' must be seen as a token (was ignored - 200)
$ret_stat = raw_https_request($cfg_domain, "GET /api/system/status HTTP/1.1\r\nhost: $cfg_domain\r\nauthorization: Bearer junk\r\nconnection: close\r\n\r\n");
if ( $ret_stat != 401 ) goto print_and_exit;               // expected 401 - invalid token
// d) lowercase 'content-type'/'content-length' on POST (DEV-430): malformed JSON must reach the API (was 411)
$post_data = '{"checked":"somedata"';                       // malformated JSON string - missing closing '}', as in subtest 5
$ret_stat = raw_https_request($cfg_domain, "POST /api/system/checkin HTTP/1.1\r\nhost: $cfg_domain\r\ncontent-type: application/json\r\ncontent-length: " . strlen($post_data) . "\r\nconnection: close\r\n\r\n" . $post_data);
if ( $ret_stat != 400 ) goto print_and_exit;               // expected 400 - "Bad Request" (JSON parsed and rejected)
// e) Content-Length that is not a number (DEV-430)
$ret_stat = raw_https_request($cfg_domain, "POST /api/system/checkin HTTP/1.1\r\nHost: $cfg_domain\r\nContent-Type: application/json\r\nContent-Length: " . strlen($post_data) . "abc\r\nConnection: close\r\n\r\n" . $post_data);
if ( $ret_stat != 400 ) goto print_and_exit;               // expected 400 - "Bad Request"
// f) CORS preflight with Private Network Access request (DEV-426); TOE config 'origin' is "*" after T-2
$origin = "https://hem-api-tester.encedo.com";
$hdrs = false;
$ret_stat = raw_https_request($cfg_domain, "OPTIONS /api/system/status HTTP/1.1\r\nHost: $cfg_domain\r\nOrigin: $origin\r\nAccess-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: content-type,authorization\r\nAccess-Control-Request-Private-Network: true\r\nConnection: close\r\n\r\n", $hdrs);
if ( $cfg_debug ) var_dump( $hdrs );
if ( $ret_stat != 204 ) goto print_and_exit;               // expected 204 - preflight accepted
if ( @$hdrs['access-control-allow-origin'] !== $origin ) goto print_and_exit;   // exact origin echoed, never "*"
if ( strpos(@$hdrs['vary'], "Origin") === false ) goto print_and_exit;
if ( isset($hdrs['access-control-allow-credentials']) ) goto print_and_exit;   // Bearer token API, no cookies
if ( strpos(@$hdrs['access-control-allow-methods'], "POST") === false ) goto print_and_exit;
if ( stripos(@$hdrs['access-control-allow-headers'], "Authorization") === false ) goto print_and_exit;
if ( @$hdrs['x-content-type-options'] !== "nosniff" ) goto print_and_exit;
if ( $test_cfg['conf'] == "ENCEDO PPA" ) {
  if ( @$hdrs['access-control-allow-private-network'] !== "true" ) goto print_and_exit;   // PNA only on PPA (local device)
  if ( @$hdrs['private-network-access-name'] !== "encedo-ppa" ) goto print_and_exit;
} else {
  if ( isset($hdrs['access-control-allow-private-network']) ) goto print_and_exit;     // never on EPA
}
// g) preflight without the PNA request header - no PNA answer
$hdrs = false;
$ret_stat = raw_https_request($cfg_domain, "OPTIONS /api/system/status HTTP/1.1\r\nHost: $cfg_domain\r\nOrigin: $origin\r\nAccess-Control-Request-Method: GET\r\nConnection: close\r\n\r\n", $hdrs);
if ( $cfg_debug ) var_dump( $hdrs );
if ( $ret_stat != 204 ) goto print_and_exit;
if ( isset($hdrs['access-control-allow-private-network']) ) goto print_and_exit;     // only when asked
// h) keep-alive (DEV-430): two requests on one connection
$sock = raw_https_connect($cfg_domain);
if ( $sock == false ) goto print_and_exit;
$hdrs = false;
$ret_stat = raw_https_transaction($sock, "GET /api/system/status HTTP/1.1\r\nHost: $cfg_domain\r\nConnection: keep-alive\r\n\r\n", $hdrs);
if ( ($ret_stat != 200) || (strcasecmp(@$hdrs['connection'], "keep-alive") != 0) ) { fclose($sock); goto print_and_exit; }
$ret_stat = raw_https_transaction($sock, "GET /api/system/version HTTP/1.1\r\nHost: $cfg_domain\r\nConnection: close\r\n\r\n");
fclose($sock);
if ( $ret_stat != 200 ) goto print_and_exit;               // second request on the same connection must be served
// i) set result
$test_cfg['subtests'][6] = 'OK';                           // mark this subtest as OK
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
