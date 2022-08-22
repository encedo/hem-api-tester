<?php

include "libs/lib.php";
include "config.php";


// test name, descr & number of subtests
$test_name = "T-10";
$test_descr = "Key management functionality";
$test_subtest_cnt = 7;


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
// d) perform local USER authentication - gen TWO tokens
$token_keygen = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:gen");   // more here https://docs.encedo.com/hem-api/reference/api-reference/key-management/create-a-key#required-access-scope
if ($token_keygen == false) goto print_and_exit;                    // exit on error
//echo "    Token GEN: $token_keygen \n";
$token_keylist = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:list");   // more here https://docs.encedo.com/hem-api/reference/api-reference/key-management/list-the-keys#required-access-scope
if ($token_keylist == false) goto print_and_exit;                    // exit on error
//echo "    Token LST: $token_keylist \n";
// e) get listing of all keys stored in the key repository
$keychain = array();
$offset = 0;
do {
  $ret_val = false;
  $dummy_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/keymgmt/list/$offset", $ret_val, $dummy_val, $token_keylist);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  foreach($ret_val['list'] as $item) $keychain[] = $item; 
  $offset = $offset + $listed;
  if ($offset >= $total) break;   
} while(true);
//echo "  keychain1: \n".json_encode($keychain)."\n\n";
// f) create all possible key type - create a list of possible key types and iterate over it
$support_key_types = array( "SECP256R1" => ['mode' => "ECDH,ExDSA", "isECDH" => true], 
                            "SECP384R1" => ['mode' => "ECDH,ExDSA", "isECDH" => true], 
                            "SECP521R1" => ['mode' => "ECDH,ExDSA", "isECDH" => true], 
                            "SECP256K1" => ['mode' => "ECDH,ExDSA", "isECDH" => true], 
                            "CURVE25519" => ["isECDH" => true], 
                            "CURVE448"  => ["isECDH" => true], 
                            "ED25519"   => [], 
                            "ED448"     => [], 
                            "SHA2-256"  => [], 
                            "SHA2-384"  => [], 
                            "SHA2-512"  => [], 
                            "SHA3-256"  => [], 
                            "SHA3-384"  => [], 
                            "SHA3-512"  => [], 
                            "AES128"    => [], 
                            "AES192"    => [], 
                            "AES256"    => []
);
$ecdh_kids = array();
$created = 0;
foreach($support_key_types as $item => $args) {
  unset($keycreate_arg);
  $label = "T-10.1 GEN $item";
  $descr = base64_encode("CCTEST:T-10.1_$item");
  $keycreate_arg = array('label' => $label, 'type' => $item, 'descr' => $descr);
  if (isset($args['mode'])) {
    $keycreate_arg['mode'] = $args['mode'];     //add mode
  }
  $ret_val = false;
  $post_data = json_encode($keycreate_arg);
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/create", $ret_val, $post_data, $token_keygen);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;                // expected is 200 (OK)
  $kid = $ret_val['kid'];
  //echo "    KID ($item): $kid  \"$descr\"\n";  
  $created++;
  // build a list of keys for ECDH
  if (isset($args['isECDH'])) {
    $ecdh_kids[$kid] = $item;
  }
}
if ($created != count($support_key_types) ) goto print_and_exit;  //  expected is to create ALL keys
//g) gen a listing again
$keychain2 = array();
$offset = 0;
do {
  $ret_val = false;
  $dummy_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/keymgmt/list/$offset", $ret_val, $dummy_val, $token_keylist);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  foreach($ret_val['list'] as $item) $keychain2[] = $item; 
  $offset = $offset + $listed;
  if ($offset >= $total) break;   
} while(true);
//echo "  keychain2: \n" . json_encode($keychain2) . "\n\n";
// h)
if (count($keychain) + count($support_key_types ) != count($keychain2)) goto print_and_exit; // expected is to have more kesy in a keychain
// i) derive all possible ECDH based keys
$support_key_types_ecdh = array(  "SECP256R1"  => "AyH/xovr5aRefadZgVL8+ydEwEa6dzgBXmvPxFv+/LIq", 
                                  "SECP384R1"  => "AscrwMd9jmdQOdC4aMbcMqaTzx4xm3DUnVhotIieMG7JyWd+UADS0snfBegnwM2NJQ==", 
                                  "SECP521R1"  => "AgGFg+WSt3MRDdu8JQRLrG2eTrm9yhiS7JKIwQfdyZl229qzaIxKigK0XVYUn1SNo5ZW8HltDEcre2wf86ZGKBYlfA==", 
                                  "SECP256K1"  => "A5wQQqNR4mRCzgyykxp9D/I0968QHLBGEGONyIQVs0Qh", 
                                  "CURVE25519" => "X7xUStEGknG4goyuP1VlgelMwYaau0I3SddDU3wQsmc=", 
                                  "CURVE448"   => "A75QwnTMiUJd0T1TPsvZBpIUCmb79FWBMQyKuQkHwlsm5gNugOQwmZkb+EFekuL1fiHQNZN5X0I="
);    
//derive keys                               
$created = 0;
$failed_calls = array();  
//Some API call fail with 406 if the ECDH secret key is to small to be an input to generate a final key.
//e.g. ECDH on CURVE25519 is 32bytes, to small to gen e.g. SHA2-384 where 48bytes is required!
//     Also APi will faile is KID is duplicated. It is possible as for the same input ECDH data, SHA2-256 
//     and SHA3-256 (or AES256) will have the same key material! Its is a RAW ECDH without any context.
foreach($ecdh_kids as $kid_ecdh => $type_ecdh) {
  foreach($support_key_types as $item => $args) {
    unset($keycreate_arg);
    $label = "T-10.1 DER $item ($type_ecdh)";
    $label = substr($label, 0, 31);     //truncate key label to fit in limit
    $descr = base64_encode( "CCTEST:T-10.1_".$item."_".$type_ecdh );
    $pubkey = $support_key_types_ecdh[$type_ecdh];
    $keycreate_arg = array('label' => $label, 'type' => $item, 'descr' => $descr, 'kid' => $kid_ecdh, 'pubkey' => $pubkey);
    if (isset($args['mode'])) {
      $keycreate_arg['mode'] = $args['mode'];     //add mode
    }
    $ret_val = false;
    $post_data = json_encode($keycreate_arg);    
    $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/derive", $ret_val, $post_data, $token_keygen);
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat == 200 ) $created++; 
    else if ( $ret_stat == 406 ) $failed_calls[$item."-from-".$type_ecdh] = 406; 
    else break;    // this is so unexpected!   
  }
}
if ( ($ret_stat != 200) && ($ret_stat != 406)) goto print_and_exit;
// j) re-generate keychain once more time
$keychain3 = array();
$offset = 0;
do {
  $ret_val = false;
  $dummy_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/keymgmt/list/$offset", $ret_val, $dummy_val, $token_keylist);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  foreach($ret_val['list'] as $item) $keychain3[] = $item; 
  $offset = $offset + $listed;
  if ($offset >= $total) break;   
} while(true);
//echo "  keychain3: \n".json_encode($keychain3)."\n\n";
// h)
if (count($keychain2) + $created != count($keychain3)) goto print_and_exit; // expected is to have more kesy in a keychain
// f) set result
$test_cfg['subtests'][1] = 'OK';                              // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 2        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
echo "  subtest-2\n";
$test_cfg['subtests'][2] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) set RTC clock - code from T-1.3
$ret = helper_checkin($cfg_domain);
if ($ret == false) goto print_and_exit;                     // exit on error
// b) perform local USER authentication - gen TWO tokens
$token_keyimp = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:imp");   // more here https://docs.encedo.com/hem-api/reference/api-reference/key-management/import-a-key#required-access-scope
if ($token_keyimp == false) goto print_and_exit;                    // exit on error
//echo "    Token IMP: $token_keyimp \n";
$token_keylist = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:list");   // more here https://docs.encedo.com/hem-api/reference/api-reference/key-management/list-the-keys#required-access-scope
if ($token_keylist == false) goto print_and_exit;                    // exit on error
//echo "    Token LST: $token_keylist \n";
// c) get listing of all keys stored in the key repository
$keychain = array();
$offset = 0;
do {
  $ret_val = false;
  $dummy_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/keymgmt/list/$offset", $ret_val, $dummy_val, $token_keylist);
  //if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  foreach($ret_val['list'] as $item) $keychain[] = $item; 
  $offset = $offset + $listed;
  if ($offset >= $total) break;   
} while(true);
//echo "  keychain1: \n".json_encode($keychain)."\n\n";
//d) import reference keys
$keys_to_import = array( "SECP256R1"  => "AyH/xovr5aRefadZgVL8+ydEwEa6dzgBXmvPxFv+/LIq", 
                         "SECP384R1"  => "AscrwMd9jmdQOdC4aMbcMqaTzx4xm3DUnVhotIieMG7JyWd+UADS0snfBegnwM2NJQ==", 
                         "SECP521R1"  => "AgGFg+WSt3MRDdu8JQRLrG2eTrm9yhiS7JKIwQfdyZl229qzaIxKigK0XVYUn1SNo5ZW8HltDEcre2wf86ZGKBYlfA==", 
                         "SECP256K1"  => "A5wQQqNR4mRCzgyykxp9D/I0968QHLBGEGONyIQVs0Qh", 
                         "CURVE25519" => "X7xUStEGknG4goyuP1VlgelMwYaau0I3SddDU3wQsmc=", 
                         "CURVE448"   => "A75QwnTMiUJd0T1TPsvZBpIUCmb79FWBMQyKuQkHwlsm5gNugOQwmZkb+EFekuL1fiHQNZN5X0I="
);    
// NOTE Re-running this subtest may fail IF those keys are already in the keychain. Deduplication will trigger an error.
$imported = 0;
$failed_calls = array();  
foreach($keys_to_import as $type => $pubkey) {
  unset($keycreate_arg);
  $label = "T-10.2 IMP $type";
  $label = substr($label, 0, 31);     //truncate key label to fit in limit
  $descr = base64_encode( "CCTEST:T-10.2_".$type."_imported" );
  $keycreate_arg = array('label' => $label, 'type' => $type, 'descr' => $descr, 'pubkey' => $pubkey, 'mode' => "ECDH");
  $ret_val = false;
  $post_data = json_encode($keycreate_arg);    
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/import", $ret_val, $post_data, $token_keyimp);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat == 200 ) $imported++; 
  else if ( $ret_stat == 406 ) $failed_calls[$type] = 406; 
  else break;    // this is so unexpected!   
}
if ( ($ret_stat != 200) && ($ret_stat != 406)) goto print_and_exit;
//e) get new listing of all keys stored in the key repository
$keychain2 = array();
$offset = 0;
do {
  $ret_val = false;
  $dummy_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/keymgmt/list/$offset", $ret_val, $dummy_val, $token_keylist);
  //if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  foreach($ret_val['list'] as $item) $keychain2[] = $item; 
  $offset = $offset + $listed;
  if ($offset >= $total) break;   
} while(true);
//echo "  keychain2: \n".json_encode($keychain2)."\n\n";
// f) process result
if (($imported > 0) && ($imported == count($keys_to_import)) ) {      //expected if first time import
  //echo "all imported\n";
} else 
if ( count($failed_calls) == count($keys_to_import)) {                // expected if re-run - key duplication is impossible (406)
  //echo "all failed\n";
} else goto print_and_exit;       
// e) set result
$test_cfg['subtests'][2] = 'OK';                           // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 3        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
echo "  subtest-3\n";
$test_cfg['subtests'][3] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) set RTC clock - code from T-1.3
$ret = helper_checkin($cfg_domain);
if ($ret == false) goto print_and_exit;                     // exit on error
// b) perform local USER authentication - gen TWO tokens
$token_keyupd = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:upd");   // more here https://docs.encedo.com/hem-api/reference/api-reference/key-management/update-a-key#required-access-scope
if ($token_keyupd == false) goto print_and_exit;                    // exit on error
//echo "    Token UPD: $token_keyupd \n";
$token_keylist = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:list");   // more here https://docs.encedo.com/hem-api/reference/api-reference/key-management/list-the-keys#required-access-scope
if ($token_keylist == false) goto print_and_exit;                    // exit on error
//echo "    Token LST: $token_keylist \n";
// c) get listing of all keys stored in the key repository
$keychain = array();
$offset = 0;
do {
  $ret_val = false;
  $dummy_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/keymgmt/list/$offset", $ret_val, $dummy_val, $token_keylist);
  //if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  foreach($ret_val['list'] as $item) $keychain[] = $item; 
  $offset = $offset + $listed;
  if ($offset >= $total) break;   
} while(true);
//echo "  keychain1: \n".json_encode($keychain)."\n\n";
//d) find a canidate to 
$kid = false;
$key_data = false;
foreach($keychain as $item) {
  if (strstr($item['type'], "ECDH")) {
    $key_data = $item;
    $kid = $item['kid'];
    break;
  }
}
if ($kid == false) goto print_and_exit;                     // ECDH key not found
//e) update key
$label_new = $key_data['label'] . " - updated";
$label_new = substr($label_new, 0, 31);     //truncate key label to fit in limit
$post_array = array('label' => $label_new, 'kid' => $kid, 'descr' => $key_data['descr']);
$ret_val = false;
$post_data = json_encode($post_array);    
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/update", $ret_val, $post_data, $token_keyupd);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
// f) rerun listing generation
$keychain2 = array();
$offset = 0;
do {
  $ret_val = false;
  $dummy_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/keymgmt/list/$offset", $ret_val, $dummy_val, $token_keylist);
  //if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  foreach($ret_val['list'] as $item) $keychain2[] = $item; 
  $offset = $offset + $listed;
  if ($offset >= $total) break;   
} while(true);
//echo "  keychain2: \n".json_encode($keychain2)."\n\n";
// g) found key by KID and check details
$key_data2 = false;
foreach($keychain2 as $item) {
  if (strstr($item['kid'], $kid)) {
    $key_data2 = $item;
    break;
  }
}
if ($key_data2 == false) goto print_and_exit;                     // ECDH key not found
if ($key_data['updated'] == $key_data2['updated']) goto print_and_exit;   // key not updated - by timpstamp
if ($key_data['label'] == $key_data2['label']) goto print_and_exit;   // key not updated - by label
// e) set result
$test_cfg['subtests'][3] = 'OK';                           // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 4        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
echo "  subtest-4\n";
$test_cfg['subtests'][4] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) search for keys with 'descr' starting from "CCTEST"
$pattern = "CCTEST:";   
$post_array = array('descr' => "^".base64_encode($pattern) );  //^ denotes 'begining by following bytes' - like regexpr :)
$ret_val = false;
$post_data = json_encode( $post_array );    
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/search", $ret_val, $post_data);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;    //200 if found, 404 if not
// e) set result
$test_cfg['subtests'][4] = 'OK';                           // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 5        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
echo "  subtest-5\n";
if ($diag_mode == false) {
  echo "    No DIAG mode, subtest will be skipped.\n";
  goto subtest_6;
}
$test_cfg['subtests'][5] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) set RTC clock - code from T-1.3
$ret = helper_checkin($cfg_domain);
if ($ret == false) goto print_and_exit;                     // exit on error
// b) perform local USER authentication - gen TWO tokens
$token_keydel = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:del");   // more here https://docs.encedo.com/hem-api/reference/api-reference/key-management/delete-a-key#required-access-scope
if ($token_keydel == false) goto print_and_exit;                    // exit on error
//echo "    Token DEL: $token_keydel \n";
$token_keylist = helper_authorize($cfg_domain, $cfg_passpharse, "keymgmt:list");   // more here https://docs.encedo.com/hem-api/reference/api-reference/key-management/list-the-keys#required-access-scope
if ($token_keylist == false) goto print_and_exit;                    // exit on error
//echo "    Token LST: $token_keylist \n";
// c) get listing of all keys stored in the key repository
$keychain = array();
$offset = 0;
do {
  $ret_val = false;
  $dummy_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/keymgmt/list/$offset", $ret_val, $dummy_val, $token_keylist);
  //if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  foreach($ret_val['list'] as $item) $keychain[] = $item; 
  $offset = $offset + $listed;
  if ($offset >= $total) break;   
} while(true);
//echo "  keychain1: \n".json_encode($keychain)."\n\n";
//d) find a canidate to dlete  
$kid = false;
$key_data = false;
foreach($keychain as $item) {
  if (strstr($item['type'], "ExDSA")) {
    $key_data = $item;
    $kid = $item['kid'];
    break;
  }
}
if ($kid == false) goto print_and_exit;                     // ECDH key not found
//e) memdump the key material
$key_mem_addr = $key_data['_addr'];
$key_mem_len = $key_data['_len'];
//printf("KEY addr:%08x  at  %02x\n", $key_mem_addr, $key_mem_len);
// f) get key body memdump
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/diag/memdump/$key_mem_addr/$key_mem_len", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200 - all good
$binbody = bin2hex(base64_decode($ret_val['dump']));
//uncomment to see key material 
//var_dump($binbody);
//e) delete the key
$ret_val = false;
$dummy_val = false;
$ret_stat = http_transaction("https", "DELETE", $cfg_domain, "/api/keymgmt/delete/$kid", $ret_val, $dummy_val, $token_keydel);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200 - all good
//f) memdump again - check is a key material is fill with zeros (except first byte)
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/diag/memdump/$key_mem_addr/$key_mem_len", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200 - all good
$binbody2 = bin2hex(base64_decode($ret_val['dump']));
//uncomment to check if is fill with zeros
//var_dump($binbody2);
if ($binbody == $binbody2) goto print_and_exit;             //expected to be different
// g) regenarete listing - should be one key less
$keychain2 = array();
$offset = 0;
do {
  $ret_val = false;
  $dummy_val = false;
  $ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/keymgmt/list/$offset", $ret_val, $dummy_val, $token_keylist);
  //if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
  $total = $ret_val['total'];
  $listed = $ret_val['listed'];
  foreach($ret_val['list'] as $item) $keychain2[] = $item; 
  $offset = $offset + $listed;
  if ($offset >= $total) break;   
} while(true);
if ( (count($keychain) - 1) != count($keychain2)) goto print_and_exit;
// e) set result
$test_cfg['subtests'][5] = 'OK';                           // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 6        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
subtest_6:
echo "  subtest-6\n";
$test_cfg['subtests'][6] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) reuse tokens previous subtest
$keycreate_arg = array('label' => "T-10.6 test key", 'type' => "CURVE25519");
// b) try to create a key using listing token
$ret_val = false;
$post_data = json_encode($keycreate_arg);
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/create", $ret_val, $post_data, $token_keylist);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat == 200 ) goto print_and_exit;                // expected is FAIL (non 200) as token is wrong
// c) repeat the key creation with correct token BUT over http
$ret_val = false;
$post_data = json_encode($keycreate_arg);
$ret_stat = http_transaction("http", "POST", $cfg_domain, "/api/keymgmt/create", $ret_val, $post_data, $token_keygen);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat == 200 ) goto print_and_exit;                // expected is FAIL (non 200) as token is wrong
// d) repeat last time - this time with correct token and over HTTPS
$ret_val = false;
$post_data = json_encode($keycreate_arg);
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/create", $ret_val, $post_data, $token_keygen);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                // expected is 200 (OK)
$kid = $ret_val['kid'];
//echo "    KID: $kid\n";
// e) set result
$test_cfg['subtests'][6] = 'OK';                           // mark this subtest as OK
/////////////////////////////////////////////////////////////////////
// end of subtest    ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////
// Subtest: 7        ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
echo "  subtest-7\n";
if ($diag_mode == false) {
  echo "    No DIAG mode, subtest will be skipped.\n";
  goto print_and_exit;
}
$test_cfg['subtests'][7] = 'ERROR';                           // mark this subtest default as ERROR - initialization as subtest is ongoing
// a) reuse tokens previous subtest but to reboot need new
$token = helper_authorize($cfg_domain, $cfg_passpharse, "system:config");       // token will be needed to reboot
if ($token == false) goto print_and_exit;                    // exit on error
// b) simulate 'temp' out of range
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/diag/break_temp", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                //expected is 200 
sleep(1); 
// c) check if in failer state
$ret_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/status", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
if ( $ret_val['fls_state'] == 0 ) goto print_and_exit;     // expected is failer state (non-zero)
// d) try to creat a key
$keycreate_arg = array('label' => "T-10.7 test key", 'type' => "CURVE25519");
$ret_val = false;
$post_data = json_encode($keycreate_arg);
$ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/keymgmt/create", $ret_val, $post_data, $token_keygen);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 409 ) goto print_and_exit;                // expected is ERROR (409 as FLS.1 is triggered)
// e) reboot to clear simulated failer state
$ret_val = false;
$dummy_val = false;
$ret_stat = http_transaction("https", "GET", $cfg_domain, "/api/system/reboot", $ret_val, $dummy_val, $token);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;                // exit on API call FAIL
sleep(10);  //wait 
// f) set result
$test_cfg['subtests'][7] = 'OK';                           // mark this subtest as OK
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
