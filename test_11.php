<?php

include "libs/lib.php";
include "config.php";


// test name, descr & number of subtests
$test_name = "T-11";
$test_descr = "Cryptography functionality";
$test_subtest_cnt = 9;


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
// d) generate keychain search over pattern keys for HMAC operations
$pattern_plain = "CCTEST:T-10.1_SHA";   
$pattern = "^".base64_encode($pattern_plain);  //^ denotes 'begining by following bytes' - like regexpr :)
$offset = 0;
$keychain = array();
do {
  $ret_val = false;
  $post_array = array('descr' => $pattern, 'offset' => $offset );  //^ denotes 'begining by following bytes' - like regexpr :)
  $post_data = json_encode( $post_array );    
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/search", $ret_val, $post_data);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //200 if found, 404 if not
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  if ($listed == 0) break;  // go all the keys  
  foreach($ret_val['list'] as $item) $keychain[] = $item; 
  $offset = $offset + $listed;
  if ($offset >= $total) break;
} while (true);  
// e) ranodm message to perform test on
$msg_raw = base64_encode( openssl_random_pseudo_bytes( 250 ) );    // ranodm bytes of data
$keys_to_test = $ret_val['list'];
// f) iterate over found keys to call HMAC sign & verify
$counter = 0;
foreach($keychain as $item) {
  $kid = $item['kid'];
  // gen access token for that KID
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid");   // more here https://docs.encedo.com/hem-api/reference/api-reference/cryptography-operations/hmac#required-access-scope
  if ($token == false) goto print_and_exit;                    // exit on error 
  // gen mac
  $ret_val = false;
  $oper_arg = array('kid' => $kid, 'msg' => $msg_raw);
  $post_data = json_encode( $oper_arg );    
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/hash", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - HMAC hash generated
  $mac = $ret_val['mac'];
  //set two variables used in Subtest 6 and Subtest 7
  if (!isset($kid_subtest6a)) {
    $kid_subtest6a = $kid;
  } else {
    if (!isset($kid_subtest6b)) {
      $kid_subtest6b = $kid;  
    }
  }
  // verify mac
  $ret_val = false;
  $oper_arg = array('kid' => $kid, 'msg' => $msg_raw, 'mac' => $mac);
  $post_data = json_encode( $oper_arg );    
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/verify", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - HMAC verify success
  $counter++;
}
// g) if above loop ends and no 'goto' calls, all HMAC tests passed!
//echo "    Executed $counter tests over ". count($keys_to_test) . " keys\n";
if ($counter != count($keychain)) goto print_and_exit;
// h) set result
$test_cfg['subtests'][1] = 'OK';                              // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 2        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST2:
echo "  subtest-2\n";
$test_cfg['subtests'][2] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) generate keychain search over pattern keys for ExDSA operations - NIST curves
$pattern_plain = "CCTEST:T-10.1_SECP";   
$pattern = "^".base64_encode($pattern_plain);  //^ denotes 'begining by following bytes' - like regexpr :)
$offset = 0;
$keychain = array();
do {
  $ret_val = false;
  $post_array = array('descr' => $pattern, 'offset' => $offset );  //^ denotes 'begining by following bytes' - like regexpr :)
  $post_data = json_encode( $post_array );    
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/search", $ret_val, $post_data);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //200 if found, 404 if not
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  if ($listed == 0) break;  // go all the keys  
  foreach($ret_val['list'] as $item) $keychain[] = $item; 
  $offset = $offset + $listed;
  if ($offset >= $total) break;   //?
} while (true);  
// b) add ED255 and ED448 keys
$pattern_plain = "CCTEST:T-10.1_ED";   
$pattern = "^".base64_encode($pattern_plain);  //^ denotes 'begining by following bytes' - like regexpr :)
$offset = 0;
do {
  $ret_val = false;
  $post_array = array('descr' => $pattern, 'offset' => $offset );  //^ denotes 'begining by following bytes' - like regexpr :)
  $post_data = json_encode( $post_array );    
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/search", $ret_val, $post_data);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //200 if found, 404 if not
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  if ($listed == 0) break;  // go all the keys  
  foreach($ret_val['list'] as $item) $keychain[] = $item; 
  $offset = $offset + $listed;
  if ($offset >= $total) break;   //?
} while (true);  
$keys_to_test = $keychain;
$msg_raw = base64_encode( openssl_random_pseudo_bytes( 32 ) );    // random 
// f) iterate over found keys to call ExDSA sign & verify
$counter = 0;
foreach($keys_to_test as $item) {
  $kid = $item['kid'];
  $is_ecdh = strstr($item['type'], "ECDH") ? true : false; 
  $is_exdsa = strstr($item['type'], "ExDSA") ? true : false;
  $is_pkey = strstr($item['type'], "PKEY") ? true : false; 
  $type = false;
  $item_type = explode(",",  $item['type']);
  if ($item_type == false) goto print_and_exit; // wtf? this is odd
  $type = $item_type[ count($item_type) - 1];
  //echo "    Process key type: $type over ECDH:$is_ecdh and ExDSA:$is_exdsa, PKEY:$is_pkey\n";  
   if ($is_pkey != true) continue; // process only keys with private key
  // gen access token for that KID
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid");   // more here https://docs.encedo.com/hem-api/reference/api-reference/cryptography-operations/hmac#required-access-scope
  if ($token == false) goto print_and_exit;                    // exit on error 
  // process key by type
  if ($type == "ED25519") {
    //Ed25519 - EdDSA
    $oper_arg = array('kid' => $kid, 'msg' => $msg_raw, 'alg' => "Ed25519");
    $post_data = json_encode( $oper_arg );    
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/sign", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - ExDSA signature generated
    $oper_arg['sign'] = $ret_val['sign'];
    $post_data = json_encode( $oper_arg );    
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/verify", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - ExDSA signature verified
    //Ed25519ph - EdDSA
    $context = base64_encode( openssl_random_pseudo_bytes( 32 ) );    // random context
    $oper_arg = array('kid' => $kid, 'msg' => $msg_raw, 'alg' => "Ed25519ph", 'ctx' => $context);
    $post_data = json_encode( $oper_arg );    
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/sign", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - ExDSA signature generated
    $oper_arg['sign'] = $ret_val['sign'];
    $post_data = json_encode( $oper_arg );    
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/verify", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - ExDSA signature verified
    //Ed25519ctx - EdDSA
    $oper_arg = array('kid' => $kid, 'msg' => $msg_raw, 'alg' => "Ed25519ctx", 'ctx' => $context);
    $post_data = json_encode( $oper_arg );    
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/sign", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - ExDSA signature generated
    $oper_arg['sign'] = $ret_val['sign'];
    $post_data = json_encode( $oper_arg );    
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/verify", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - ExDSA signature verified
    $counter++;
  } else
  if ($type == "ED448") {
    //Ed448 - EdDSA
    $context = base64_encode( openssl_random_pseudo_bytes( 32 ) );    // random context
    $oper_arg = array('kid' => $kid, 'msg' => $msg_raw, 'alg' => "Ed448", 'ctx' => $context);
    $post_data = json_encode( $oper_arg );    
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/sign", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - ExDSA signature generated
    $oper_arg['sign'] = $ret_val['sign'];
    $post_data = json_encode( $oper_arg );    
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/verify", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - ExDSA signature verified
    //Ed448ph - EdDSA
    $context = base64_encode( openssl_random_pseudo_bytes( 32 ) );    // random context
    $oper_arg = array('kid' => $kid, 'msg' => $msg_raw, 'alg' => "Ed448ph", 'ctx' => $context);
    $post_data = json_encode( $oper_arg );    
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/sign", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - ExDSA signature generated
    $oper_arg['sign'] = $ret_val['sign'];
    $post_data = json_encode( $oper_arg );    
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/verify", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - ExDSA signature verified
    $counter++;
  } else {
    //SHA256WithECDSA  - ECDSA
    $oper_arg = array('kid' => $kid, 'msg' => $msg_raw, 'alg' => "SHA256WithECDSA");
    $post_data = json_encode( $oper_arg );    
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/sign", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - ExDSA signature generated
    $oper_arg['sign'] = $ret_val['sign'];
    $post_data = json_encode( $oper_arg );    
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/verify", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - ExDSA signature verified
    //SHA384WithECDSA  - ECDSA
    $oper_arg = array('kid' => $kid, 'msg' => $msg_raw, 'alg' => "SHA384WithECDSA");
    $post_data = json_encode( $oper_arg );    
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/sign", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - ExDSA signature generated
    $oper_arg['sign'] = $ret_val['sign'];
    $post_data = json_encode( $oper_arg );    
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/verify", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - ExDSA signature verified
    //SHA512WithECDSA  - ECDSA
    $oper_arg = array('kid' => $kid, 'msg' => $msg_raw, 'alg' => "SHA512WithECDSA");
    $post_data = json_encode( $oper_arg );    
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/sign", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - ExDSA signature generated
    $oper_arg['sign'] = $ret_val['sign'];
    $post_data = json_encode( $oper_arg );    
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/exdsa/verify", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - ExDSA signature verified
    $counter++;
  }
}
// g) if above loop ends and no 'goto' calls, all HMAC tests passed!
//echo "    Executed $counter tests over ". count($keys_to_test) . " keys\n";
if ($counter != count($keys_to_test)) goto print_and_exit;
// h) set result
$test_cfg['subtests'][2] = 'OK';                           // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 3        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST3:
echo "  subtest-3\n";
$test_cfg['subtests'][3] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) generate keychain search over pattern keys for AES operations
$pattern_plain = "CCTEST:T-10.1_AES";   
$pattern = "^".base64_encode($pattern_plain);  //^ denotes 'begining by following bytes' - like regexpr :)
$offset = 0;
$keychain = array();
do {
  $ret_val = false;
  $post_array = array('descr' => $pattern, 'offset' => $offset );  //^ denotes 'begining by following bytes' - like regexpr :)
  $post_data = json_encode( $post_array );    
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/search", $ret_val, $post_data);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //200 if found, 404 if not
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  if ($listed == 0) break;  // go all the keys  
  foreach($ret_val['list'] as $item) $keychain[] = $item; 
  $offset = $offset + $listed;
  if ($offset >= $total) break;   //?
} while (true);  
// b) iterate over found keys
$counter = 0;
foreach($keychain as $item) {
  $kid = $item['kid'];
  $type = false;
  //parse keytype
  $item_type = explode(",",  $item['type']);
  if ($item_type == false) goto print_and_exit; // wtf? this is odd
  $type = $item_type[ count($item_type) - 1];
  //echo "    Process key type: $type   KID: $kid\n";  
  // gen access token for that KID
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid");   // more here https://docs.encedo.com/hem-api/reference/api-reference/cryptography-operations/encryption/encryption-decryption#required-access-scope
  if ($token == false) goto print_and_exit;                    // exit on error 
  //AES in ECB mode
  //encrypt example message
  $msg = base64_encode( openssl_random_pseudo_bytes( 64 ) );  //msg len HAVE TO be multiple of AES block size 16bytes
  $alg = "$type-ECB";
  $post_array = array('kid' => $kid, 'msg' => $msg, 'alg' => $alg);
  $post_data = json_encode( $post_array );    
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/encrypt", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $ciphertext = $ret_val['ciphertext'];
  //try to decrypt the message
  $post_array['msg'] = $ciphertext;
  $post_data = json_encode( $post_array );    
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/decrypt", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $msg_test = $ret_val['plaintext'];
  //compare
  if ($msg != $msg_test) goto print_and_exit;    //expected is 200 on success
  //AES in CBC mode
  //encrypt example message
  $msg = base64_encode( openssl_random_pseudo_bytes( 100 ) ); //CBC can handle any message size - padding 
  $alg = "$type-CBC";
  $post_array = array('kid' => $kid, 'msg' => $msg, 'alg' => $alg);
  $post_data = json_encode( $post_array );    
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/encrypt", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $ciphertext = $ret_val['ciphertext'];
  $iv = $ret_val['iv'];
  //try to decrypt the message
  $post_array['msg'] = $ciphertext;
  $post_array['iv'] = $iv;
  $post_data = json_encode( $post_array );    
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/decrypt", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $msg_test = $ret_val['plaintext'];
  //compare
  if ($msg != $msg_test) goto print_and_exit;    //expected is 200 on success
  //AES in GCM mode
  //encrypt example message
  $msg = base64_encode( openssl_random_pseudo_bytes( 100 ) ); //GCM can handle any message size 
  $aad = base64_encode( openssl_random_pseudo_bytes( 32 ) );  
  $alg = "$type-GCM";
  $post_array = array('kid' => $kid, 'msg' => $msg, 'alg' => $alg, 'aad' => $aad);
  $post_data = json_encode( $post_array );    
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/encrypt", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $ciphertext = $ret_val['ciphertext'];
  $iv = $ret_val['iv'];
  $tag = $ret_val['tag'];
  //try to decrypt the message
  $post_array['msg'] = $ciphertext;
  $post_array['iv'] = $iv;
  $post_array['tag'] = $tag;
  $post_data = json_encode( $post_array );    
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/decrypt", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $msg_test = $ret_val['plaintext'];
  //compare
  if ($msg != $msg_test) goto print_and_exit;    //expected is equal
  $counter++;
}
if ($counter != count($keychain)) goto print_and_exit;
// c) set result
$test_cfg['subtests'][3] = 'OK';                            // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 4        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST4:
echo "  subtest-4\n";
$test_cfg['subtests'][4] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) generate keychain search over pattern keys for AES operations
$pattern_plain = "CCTEST:T-10.1_AES";   
$pattern = "^".base64_encode($pattern_plain);  //^ denotes 'begining by following bytes' - like regexpr :)
$offset = 0;
$keychain = array();
do {
  $ret_val = false;
  $post_array = array('descr' => $pattern, 'offset' => $offset );  //^ denotes 'begining by following bytes' - like regexpr :)
  $post_data = json_encode( $post_array );    
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/search", $ret_val, $post_data);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //200 if found, 404 if not
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  if ($listed == 0) break;  // go all the keys  
  foreach($ret_val['list'] as $item) $keychain[] = $item; 
  $offset = $offset + $listed;
  if ($offset >= $total) break;   //?
} while (true);  
// b) iterate over found keys
$counter = 0;
foreach($keychain as $item) {
  //var_dump($item);  
  $kid = $item['kid'];
  $type = false;
  //parse keytype
  $item_type = explode(",",  $item['type']);
  if ($item_type == false) goto print_and_exit; // wtf? this is odd
  $type = $item_type[ count($item_type) - 1];
  //echo "    Process key type: $type   KID: $kid\n";  
  // gen access token for that KID
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid");   // more here https://docs.encedo.com/hem-api/reference/api-reference/cryptography-operations/encryption/encryption-decryption#required-access-scope
  if ($token == false) goto print_and_exit;                    // exit on error 
  //WRAP
  $msg = base64_encode( openssl_random_pseudo_bytes( 32 ) ); // example random message to wrap (KEK by NIST)
  $post_array = array('kid' => $kid, 'alg' => $type, 'msg' => $msg);
  $post_data = json_encode( $post_array );    
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/wrap", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $wrapped = $ret_val['wrapped'];
  //UNWARP
  $post_array = array('kid' => $kid, 'alg' => $type, 'msg' => $wrapped);
  $post_data = json_encode( $post_array );    
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/unwrap", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $msg_test = $ret_val['unwrapped'];
  //compare
  if ($msg != $msg_test) goto print_and_exit;    //expected is equal
  $counter++;
}
if ($counter != count($keychain)) goto print_and_exit;
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
$test_cfg['subtests'][5] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) generate keychain search over pattern keys for ECDH operations - NIST curves
$pattern_plain = "CCTEST:T-10.1_SECP";   
$pattern = "^".base64_encode($pattern_plain);  //^ denotes 'begining by following bytes' - like regexpr :)
$offset = 0;
$keychain = array();
do {
  $ret_val = false;
  $post_array = array('descr' => $pattern, 'offset' => $offset );  //^ denotes 'begining by following bytes' - like regexpr :)
  $post_data = json_encode( $post_array );    
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/search", $ret_val, $post_data);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //200 if found, 404 if not
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  if ($listed == 0) break;  // go all the keys  
  foreach($ret_val['list'] as $item) $keychain[] = $item; 
  $offset = $offset + $listed;
  if ($offset >= $total) break;   //?
} while (true);  
// b) add Curve255 and Curve448 keys
$pattern_plain = "CCTEST:T-10.1_CURVE";   
$pattern = "^".base64_encode($pattern_plain);  //^ denotes 'begining by following bytes' - like regexpr :)
$offset = 0;
do {
  $ret_val = false;
  $post_array = array('descr' => $pattern, 'offset' => $offset );  //^ denotes 'begining by following bytes' - like regexpr :)
  $post_data = json_encode( $post_array );    
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/search", $ret_val, $post_data);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //200 if found, 404 if not
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  if ($listed == 0) break;  // go all the keys  
  foreach($ret_val['list'] as $item) $keychain[] = $item; 
  $offset = $offset + $listed;
  if ($offset >= $total) break;   //?
} while (true);  
$msg_raw = base64_encode( openssl_random_pseudo_bytes( 8 ) );    // ranodm
//below example public keys will be used to perform ECDH 
$supported_key_types_ecdh = array(  "SECP256R1"  => "AyH/xovr5aRefadZgVL8+ydEwEa6dzgBXmvPxFv+/LIq", 
                                    "SECP384R1"  => "AscrwMd9jmdQOdC4aMbcMqaTzx4xm3DUnVhotIieMG7JyWd+UADS0snfBegnwM2NJQ==", 
                                    "SECP521R1"  => "AgGFg+WSt3MRDdu8JQRLrG2eTrm9yhiS7JKIwQfdyZl229qzaIxKigK0XVYUn1SNo5ZW8HltDEcre2wf86ZGKBYlfA==", 
                                    "SECP256K1"  => "A5wQQqNR4mRCzgyykxp9D/I0968QHLBGEGONyIQVs0Qh", 
                                    "CURVE25519" => "X7xUStEGknG4goyuP1VlgelMwYaau0I3SddDU3wQsmc=", 
                                    "CURVE448"   => "A75QwnTMiUJd0T1TPsvZBpIUCmb79FWBMQyKuQkHwlsm5gNugOQwmZkb+EFekuL1fiHQNZN5X0I="
);    
$supported_alg = array( "SHA2-256", "SHA2-384", "SHA2-512", "SHA3-256", "SHA3-384", "SHA3-512", "" ); // last is RAW - no hash, raw ECDH result
// c) iterate over found keys to call ECDH derive
$counter = 0;
foreach($keychain as $item) {
  $kid = $item['kid'];
  $is_ecdh = strstr($item['type'], "ECDH") ? true : false; 
  $is_pkey = strstr($item['type'], "PKEY") ? true : false; 
  $type = false;
  //parse keytype
  $item_type = explode(",",  $item['type']);
  if ($item_type == false) goto print_and_exit; // wtf? this is odd
  $type = $item_type[ count($item_type) - 1];
  //echo "    Process key type: $type over ECDH:$is_ecdh, PKEY:$is_pkey\n";  
  if ($is_pkey != true) continue; // process only keys with private key
  // gen access token for that KID
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid");   // more here https://docs.encedo.com/hem-api/reference/api-reference/cryptography-operations/ecdh#required-access-scope
  if ($token == false) goto print_and_exit;                    // exit on error 
  // get pubkey assosiatec by keytype and process through all possible algs supported https://docs.encedo.com/hem-api/reference/api-reference/cryptography-operations/ecdh 
  $pubkey = $supported_key_types_ecdh[ $type ];
  foreach( $supported_alg  as $alg) {
    //echo "    alg: $alg  type: $type  pubkey: $pubkey\n";
    // kid & pubkey version
    $post_array = array('kid' => $kid, 'pubkey' => $pubkey );
    if ($alg != "") $post_array['alg'] = $alg;
    $post_data = json_encode( $post_array );    
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/ecdh", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
    // kid &ext_kid version
    $post_array = array('kid' => $kid, 'ext_kid' => $kid );
    if ($alg != "") $post_array['alg'] = $alg;
    $post_data = json_encode( $post_array );    
    $ret_val = false;
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/ecdh", $ret_val, $post_data, $token);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
    //all good, got secret (ECDH result) hashed by ALG 
    $counter++;    
  } 
  //additional tests - ECDH as a source of secrets for hmac,encryption&wrap
  //reuse code from subtest1,3&4
  //echo "HMAC - EXT_KID\n";  
  $msg = base64_encode( openssl_random_pseudo_bytes( 64 ) );
  //hash
  $ret_val = false;
  $oper_arg = array('kid' => $kid, 'ext_kid' => $kid, 'msg' => $msg_raw, 'alg' => "SHA2-256");
  $post_data = json_encode( $oper_arg );    
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/hash", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - HMAC hash generated
  $mac = $ret_val['mac'];
  // verify mac
  $ret_val = false;
  $oper_arg['mac'] = $mac;
  $post_data = json_encode( $oper_arg );    
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/verify", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - HMAC verify success
  //echo "HMAC - PUBKEY\n";
  $msg = base64_encode( openssl_random_pseudo_bytes( 64 ) );
  //hash
  $ret_val = false;
  $oper_arg = array('kid' => $kid, 'pubkey' => $pubkey, 'msg' => $msg_raw, 'alg' => "SHA2-256");
  $post_data = json_encode( $oper_arg );    
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/hash", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - HMAC hash generated
  $mac = $ret_val['mac'];
  // verify mac
  $ret_val = false;
  $oper_arg['mac'] = $mac;
  $post_data = json_encode( $oper_arg );    
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/verify", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - HMAC verify success
  //echo "CIPHER - EXT_KID\n";
  $msg = base64_encode( openssl_random_pseudo_bytes( 100 ) ); //CBC can handle any message size - padding 
  $alg = "AES128-CBC";
  $post_array = array('kid' => $kid, 'ext_kid' => $kid, 'msg' => $msg, 'alg' => $alg);
  $post_data = json_encode( $post_array );    
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/encrypt", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $ciphertext = $ret_val['ciphertext'];
  $iv = $ret_val['iv'];
  //try to decrypt the message
  $post_array['msg'] = $ciphertext;
  $post_array['iv'] = $iv;
  $post_data = json_encode( $post_array );    
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/decrypt", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $msg_test = $ret_val['plaintext'];
  //compare
  if ($msg != $msg_test) goto print_and_exit;    //expected is 200 on success
  //echo "CIPHER - PUBKEY\n";
  $msg = base64_encode( openssl_random_pseudo_bytes( 100 ) ); //CBC can handle any message size - padding 
  $ctx = base64_encode( openssl_random_pseudo_bytes( 8 ) ); 
  $alg = "AES128-CBC";
  $post_array = array('kid' => $kid, 'pubkey' => $pubkey, 'msg' => $msg, 'alg' => $alg, 'ctx' => $ctx);
  $post_data = json_encode( $post_array );    
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/encrypt", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $ciphertext = $ret_val['ciphertext'];
  $iv = $ret_val['iv'];
  //try to decrypt the message
  $post_array['msg'] = $ciphertext;
  $post_array['iv'] = $iv;
  $post_data = json_encode( $post_array );    
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/decrypt", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $msg_test = $ret_val['plaintext'];
  //compare
  if ($msg != $msg_test) goto print_and_exit;    //expected is equal
  //echo "WRAP - EXT_KID\n";
  $msg = base64_encode( openssl_random_pseudo_bytes( 32 ) ); // example random message to wrap (KEK by NIST)
  $post_array = array('kid' => $kid, 'ext_kid' => $kid, 'alg' => "AES128", 'msg' => $msg);
  $post_data = json_encode( $post_array );    
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/wrap", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $wrapped = $ret_val['wrapped'];
  //UNWARP
  $post_array['msg'] = $wrapped;
  $post_data = json_encode( $post_array );    
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/unwrap", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $msg_test = $ret_val['unwrapped'];
  //compare
  if ($msg != $msg_test) goto print_and_exit;    //expected is equal
  //echo "WRAP - PUBKEY\n";
  $msg = base64_encode( openssl_random_pseudo_bytes( 32 ) ); // example random message to wrap (KEK by NIST)
  $ctx = base64_encode( openssl_random_pseudo_bytes( 8 ) ); 
  $post_array = array('kid' => $kid, 'pubkey' => $pubkey, 'alg' => "AES128", 'msg' => $msg, 'ctx' => $ctx);
  $post_data = json_encode( $post_array );    
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/wrap", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $wrapped = $ret_val['wrapped'];
  //UNWARP
  $post_array['msg'] = $wrapped;
  $post_data = json_encode( $post_array );    
  $ret_val = false;
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/cipher/unwrap", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //expected is 200 on success
  $msg_test = $ret_val['unwrapped'];
  //compare
  if ($msg != $msg_test) goto print_and_exit;    //expected is equal  
}
if ($counter != count($supported_alg)*count($keychain)) goto print_and_exit;
// d) set result
$test_cfg['subtests'][5] = 'OK';                           // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 6        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST6:
echo "  subtest-6\n";
$test_cfg['subtests'][6] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) prerequirements
if (!isset($kid_subtest6a)) goto print_and_exit;
if (!isset($kid_subtest6b)) goto print_and_exit;
// b) get access tokens to two KIDs
$token_a = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid_subtest6a");   
if ($token_a == false) goto print_and_exit;                    // exit on error 
$token_b = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid_subtest6b");   
if ($token_b == false) goto print_and_exit;                    // exit on error 
// c) try to hash using wrong token
$msg = base64_encode( openssl_random_pseudo_bytes( 64 ) );  
$ret_val = false;
$oper_arg = array('kid' => $kid_subtest6a, 'msg' => $msg);
$post_data = json_encode( $oper_arg );    
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/hash", $ret_val, $post_data, $token_b);  //wrong token
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 403 ) goto print_and_exit;        // expected is 403 - HMAC hash executed with wrong token
// d) change token to the right one
$ret_val = false;
$oper_arg = array('kid' => $kid_subtest6a, 'msg' => $msg);
$post_data = json_encode( $oper_arg );    
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/hash", $ret_val, $post_data, $token_a);  //rigth token
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - HMAC hash generated
// e) set result
$test_cfg['subtests'][6] = 'OK';                           // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 7        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST7:
echo "  subtest-7\n";
if ($diag_mode == false) {
  echo "    No DIAG mode, subtest will be skipped.\n";
  goto print_and_exit;
}
$test_cfg['subtests'][7] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) prerequirements
if (!isset($kid_subtest6a)) goto print_and_exit;
if (!isset($kid_subtest6b)) goto print_and_exit;
if (!isset($token_a)) goto print_and_exit;
if (!isset($token_b)) goto print_and_exit;
// b) check status to ensure no failure stated exists
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/status", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
if ( $ret_val['fls_state'] != 0 ) goto print_and_exit;     // expected is no failer (zero)
// c) gen token needed to reboot after test the TOE
$token = helper_authorize($cfg_domain, $cfg_passpharse, "system:config");       // token will be needed to reboot
if ($token == false) goto print_and_exit;                    // exit on error
// d) try to hash - should succeed
$msg = base64_encode( openssl_random_pseudo_bytes( 64 ) );  
$ret_val = false;
$oper_arg = array('kid' => $kid_subtest6a, 'msg' => $msg);
$post_data = json_encode( $oper_arg );    
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/hash", $ret_val, $post_data, $token_a);  
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - success
// e) execute simulated failer
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/diag/break_temp", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200 
sleep(2); // wait a while
// f) check if in failer state is triggered
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/status", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
if ( $ret_val['fls_state'] == 0 ) goto print_and_exit;     // expected is failer state (non-zero)
// g) repeat above hash genearion
$ret_val = false;
$post_data = json_encode( $oper_arg );    
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/hmac/hash", $ret_val, $post_data, $token_a);  
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat == 200 ) goto print_and_exit;        // expected is 409 - FLS.1 involved
// h) reboot to clear simulated failer state
$ret_val = false;
$dummy_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/reboot", $ret_val, $dummy_val, $token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
sleep(30);  //wait 
// i) set result
$test_cfg['subtests'][7] = 'OK';                           // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 8        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST8:
echo "  subtest-8\n";
$test_cfg['subtests'][8] = 'ERROR';                         // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) get TOE status 
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/status", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
// b) set RTC clock - code from T-1.3
$ret = helper_checkin($cfg_domain);
// c) generate keychain search over pattern keys for ML-KEM operations
$pattern_plain = "CCTEST:T-10.1_MLKEM";   
$pattern = "^".base64_encode($pattern_plain);  //^ denotes 'begining by following bytes' - like regexpr :)
$offset = 0;
$keychain = array();
do {
  $ret_val = false;
  $post_array = array('descr' => $pattern, 'offset' => $offset );  //^ denotes 'begining by following bytes' - like regexpr :)
  $post_data = json_encode( $post_array );    
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/search", $ret_val, $post_data);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //200 if found, 404 if not
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  if ($listed == 0) break;  // go all the keys  
  foreach($ret_val['list'] as $item) $keychain[] = $item; 
  $offset = $offset + $listed;
  if ($offset >= $total) break;
} while (true);  
// d) iterate over found keys to call ML-KEM Encapsulation and the Decapsulation
//var_dump($keychain);
$counter = 0;
foreach($keychain as $item) {
  $kid = $item['kid'];
  // gen access token for that KID
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid");   // more here https://docs.encedo.com/hem-api/reference/api-reference/cryptography-operations/hmac#required-access-scope
  if ($token == false) goto print_and_exit;                    // exit on error 
  // encapsulation
  $ret_val = false;
  $oper_arg = array('kid' => $kid);
  $post_data = json_encode( $oper_arg );    
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/mlkem/encaps", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - HMAC hash generated
  $ss_encaps = $ret_val['ss'];
  $ct_encaps = $ret_val['ct'];
  // decapsulation
  $ret_val = false;
  $oper_arg = array('kid' => $kid, 'ct' => $ct_encaps);
  $post_data = json_encode( $oper_arg );    
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/mlkem/decaps", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - HMAC verify success
  // compate two SS values - should be equal
  if ($ss_encaps !== $ret_val['ss']) goto print_and_exit;
  $counter++;
}
// e) if above loop ends and no 'goto' calls, all ML-KEM tests passed!
//echo "    Executed $counter tests over ". count($keychain) . " keys\n";
if ($counter != count($keychain)) goto print_and_exit;
// f) set result
$test_cfg['subtests'][8] = 'OK';                           // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 9        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
TEST9:
echo "  subtest-9\n";
$test_cfg['subtests'][9] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) generate keychain search over pattern keys for ML-DSA operations
$pattern_plain = "CCTEST:T-10.1_MLDSA";   
$pattern = "^".base64_encode($pattern_plain);  //^ denotes 'begining by following bytes' - like regexpr :)
$offset = 0;
$keychain = array();
do {
  $ret_val = false;
  $post_array = array('descr' => $pattern, 'offset' => $offset );  //^ denotes 'begining by following bytes' - like regexpr :)
  $post_data = json_encode( $post_array );    
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/search", $ret_val, $post_data);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;    //200 if found, 404 if not
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  if ($listed == 0) break;  // go all the keys  
  foreach($ret_val['list'] as $item) $keychain[] = $item; 
  $offset = $offset + $listed;
  if ($offset >= $total) break;
} while (true);  
// b) iterate over found keys to call ML-DSA Sign & Verification
//var_dump($keychain);
$counter = 0;
foreach($keychain as $item) {
  $kid = $item['kid'];
  // gen access token for that KID
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:use:$kid");   // more here https://docs.encedo.com/hem-api/reference/api-reference/cryptography-operations/hmac#required-access-scope
  if ($token == false) goto print_and_exit;                    // exit on error 
  // sign
  $msg_raw = base64_encode( openssl_random_pseudo_bytes( 250 ) );    // ranodm bytes of data
  $ret_val = false;
  $oper_arg = array('kid' => $kid, 'msg' => $msg_raw);
  $post_data = json_encode( $oper_arg );    
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/mldsa/sign", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - HMAC hash generated
  $signature = $ret_val['sign'];
  // verification
  $ret_val = false;
  $oper_arg = array('kid' => $kid, 'msg' => $msg_raw, 'sign' => $signature);
  $post_data = json_encode( $oper_arg );    
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/crypto/pqc/mldsa/verify", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;        // expected is 200 - HMAC verify success
  $counter++;
}
// c) if above loop ends and no 'goto' calls, all ML-KEM tests passed!
echo "    Executed $counter tests over ". count($keychain) . " keys\n";
if ($counter != count($keychain)) goto print_and_exit;
// d) set result
$test_cfg['subtests'][9] = 'OK';                           // mark this subtest as OK
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
