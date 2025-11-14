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
//echo "\r\n  keychain1: \n".json_encode($keychain)."\n\n";
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
                            "AES256"    => [],
                            "MLKEM512"  => ['not_deriveable' => true],
                            "MLKEM768"  => ['not_deriveable' => true],
                            "MLKEM1024" => ['not_deriveable' => true],
                            "MLDSA44"   => ['not_deriveable' => true],
                            "MLDSA65"   => ['not_deriveable' => true],
                            "MLDSA87"   => ['not_deriveable' => true]
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
//echo "\r\n  keychain2: \n" . json_encode($keychain2) . "\n\n";
// h)
if (count($keychain) + count($support_key_types ) != count($keychain2)) goto print_and_exit; // expected is to have more kesy in a keychain
// i) derive all possible ECDH based keys
$support_key_types_ecdh = array(  "SECP256R1"  => "AiYzWmnH7Kduz57RYNfUPcb6cla/zfUwoU9b/Srvkp0g", 
                                  "SECP384R1"  => "A5ibqhHC6r8tpS5zBtNUxDBihTBpcbf5sXDFB54ElaYG7iB9yIIlayFaAe52dzzYdg==", 
                                  "SECP521R1"  => "AwBkJIwsNBrRWA1OFOla+SwvysGRheCb437HvxSXpPYGf0TTpHnILkU8uBCQxe3JpnENurHOpzHwQEgjH7l+H2arrg==", 
                                  "SECP256K1"  => "A4DeohyhDv8O+OTdVyyHP9Sb7zM6NYQCOyw7OmcOIClM", 
                                  "CURVE25519" => "ndCJcDWdP0qBOzc3He990b3aANV2Z0qaWZZFrnnMYzg=", 
                                  "CURVE448"   => "Nc6ODat4qc66DbcrF8Pn1MuHH98dkNx33Yg2609mXiqtBfhvPJUK2YoHe7IE51ePxl91C7kV/yg="
);    
//derive keys    
$created = 0;
$failed_calls = array();  
//Some API call fail with 406 if the ECDH secret key is to small to be an input to generate a final key.
//e.g. ECDH on CURVE25519 is 32bytes, to small to gen e.g. SHA2-384 where 48bytes is required!
//     Also APi will fail is KID is duplicated. It is possible as for the same input ECDH data, SHA2-256 
//     and SHA3-256 (or AES256) will have the same key material! It is a RAW ECDH without any context.
foreach($ecdh_kids as $kid_ecdh => $type_ecdh) {
  foreach($support_key_types as $item => $args) {
    if (isset($args['not_deriveable']) )  //skip PQC key type
        continue;
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
    if ( $cfg_debug ) var_dump( $ret_stat );
    if ( $cfg_debug ) var_dump( $ret_val );
    if ( $ret_stat == 200 ) $created++; 
    else if ( $ret_stat == 406 ) $failed_calls[$item."-from-".$type_ecdh] = 406; 
    else {
      echo "DERIVE FAILED: $ret_stat";
      break;    // this is so unexpected!   
    }
  }
}
//var_dump($failed_calls);
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
$x = count($keychain2);
$y = count($keychain3);
//echo "count(kc2): $x  count(kc3): $y  created: $created";
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
TEST2:
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
//d) import reference public keys
$keys_to_import = array( "SECP256R1"  => "AmWHMI2mU68VmObAhUC06wuRksr/Z36l3vvASXM15SU4",   
                         "SECP384R1"  => "Ak2gNFPsUOvg+axmBjTZOb06I6mXd/VYRMNbUX1EqL7brYZ6XxlH1BSvzZxp6Tpa5w==",      
                         "SECP521R1"  => "AwFMpndHKVa4VLW6WsFGQPiYFGWdRgq26rzruedEz02znaOuprlB/WBTQHdTzr6+XaN3Y1mDfuFGRUGhWphzPolG+Q==",   
                         "SECP256K1"  => "AnPYPKLTA4QCgRC5G9L/eeNH2oN4LJQGAuJld4prdPXf",  
                         "CURVE25519" => "/SXE0y/e8UeJG6qQcsoLNf3k8UV/7uNrjwdRK+yYqFA=",   
                         "CURVE448"   => "/T58gObxqV+ASUkshTOGp7oMe1K/PIkxyIdbUTUZDmITsAmyV4qDrCN+Ma+Zne5Pnens5WPVTeM=", 
                         "ED25519"    => "34Y7sClsC9HhkXyR3lIEtJa+BwPMwFkVNMXY8HTnAUs=", 
                         "ED448"      => "kqh1EuwHwuP0udO3x5jMujDVhrPUgz4K9rynhJKxyxMwwunzSolDCP18KgTmwj3nnJAsFukOOpQA", 
                         "MLKEM512"   => "OOM2eGaoXHyRdcwhnqGHi2W1WxmE2WZFmtDL0fM7fJe2hkp05ZdexXAVf+UFDAy8nLYCdjigABFdvQI44NQnPIaE4GCow/d+7lux5AqgODtrGQdokxeLdDS0hKCYO5SRVgi/jGd5I+Qck2OtFCVn4xiRfhMPwMEDu5BEIPo3nSK2sEnFXRqNt1WVkbJ66eKzwiEfUYENH7SqqRiBS1g4WnETCCFdbhNultnDlWBrqzltYtAj5aCRrWcsoaEpjGCDXtiGJ6S680rOIMysZ9UYt1Fj9VsU9cKQI+E1a7ypEJCY8bU2HSOZpDcxApOgPJJ/MACNmVqxLthRewVw+sQDNUkcMvbMX+wMuEESyLFVj8kqiMNoHMNWnTJv30lLNLNnWwPCphqytTJPoyS6RIhR5rxkShVyRJsVABVIsAZJkoR02zgTXHBOD/MUBzc70KpX8oPMseNs8ySBFitFNUCH1LQa7DR9jTE+s5lqH9CDSxYvg/u1X9M/5HI3BHTBIiND81QtxJw3NnpZ4EuNGcWJHFVMYOYV1kA/j0iFpRZetedN0jZhb0EAi3E2YvuA+ZB70gmFSqBdPqWZHFi9aNSLGCBHJxAAs8WbpIpZ4icKhyCfNqiGNmu/omA1BQe5wfyUgVSNeMBENgCecDWXMLaVSgcD5BljJkQ3mPwaNWFq5RglfYYmDhR3vtmj73kN90BcWzKn+ot+0UJC9dGIZLKanhs3hgF++yi+tNmunPNvPoYxdzK87WGAWowGKrC+POsAsLi1BXYJljGWeNki/Ptt2JAJNMYkSEghPaKlwUh4NkMDr9OZPDBk0DgYl/G+CcfFWzhWsCRDJ/kpmqcXAGAKTmJ/AovJNPtKoMQxqbutDCOi9FibwVxzX0aWnMZaBycmc8YhZhqfLnKQpJa1DOgXuxNsnBZV0PWxpGIqUmoJeoS2X8KE2NEcorg7oYZYBmMtO4RAxQPDu+SWqrRHz8Q7mqGTllxgd2wOrRCYaPJEmiQI/PiAuhE9N7GMLCQCzDN2PWzSEHaDpm3OlnlnRwgafVObImdDvbVo4Mf+yX+AGmY=",   
                         "MLKEM768"   => "d3ECxJqDTTUEnnERXxlsEIms5fchDDDKU5tFyfe2qldGWUpjDFiiM2Nh9aQWa7JMw0QQrpBSokZmjWE18rizu2NqI0RueYCkIhVdzDEhloYKhtlK6xtfOqdQiXClHzV50hLC48XIitM2kRLFh9WE6DSB20id9pCP7XKuL8E5UZOVCLwKVUtZ7OamkBUx+KiAnngg5nAezEZFw7Vlm1wrMdWLvywVDGHGVgNsPrA2qKtQamWPtwHP3NS0eixdykKZ50NBLstg2kSLQXoENsQo3YSB/bxg6pfLwaciofA8VbcZn4uxfLxDOlt1yxkohsCNVBxHTFeqg1BKefyxagS/7QdqYTZXk0JaaHwrTQqe6CCdqSg+crtCIgfQzvh22zw9vRQDdzKkWCssnyxPoDckeRCAvtoQDvaTduA9p9yAQFmUlliBGcdhLdMiL2lvMms3iwKT6uacE6CXXJy8zgipAfK0rJZQ+cuQ5PA9JEen1ttzh7l8+CzO7YI6AcIjd6Im/VLBS8hEsrStTaGBvaF7x9cXCqCTppJIQvSAvZe+r8ocVVOxFMOCV5AClosnATmnLrqMtgvDghsigUlVGeiKXEIOESEIYlOWzmV6NeC+sIAGuBeYAeAUR5p5NaaiW1MNRQEKX2g0MdVfV9OBX3a4MMllcbuCKiphoiqA8dp3U8lx5Fqa0uB95MzJ8dkWqWrHK5RjEzqkbBEfiBSCYOB0IkWTOUx5oXB4ZnyR3TOvOAFfrndEQZNougN7hfUvHUuX6Xc2GPUedSsraYChOGloaGsZmzyGYvUkAiLCXZE+M7IwQjMwgVxTEedcOcF2EdZKVomOMklcuRM1NZSB+CsmwIWXYFkVxwoplMpXbkqL7KOE2BKxCBOp0eQ9HKBWjRiQEjMmBlx1ICdJx0bGzQbLj6CDWWtN1rlUd5ya6XByBIqUmVsZg8FhBJY27wFb/Fc+v8KN6QdmKMYmPJdNJCJT2FEVnQgT7JghgPptHkl0PVE5TTN9+wVNKjEhjXpM/4Gk1HmqRrI5JIFnzEmhSiAd5CwtJdyD49IXVPtLXPI9vCtb9xF2TwgAwViAQ6Z/MFRbT/YLS4BfZ4SEi4WEf+m0sMIaYWMYHZONwOGRvRfCbYSdTNKtwJkYXbRkJXmDwNUS+mAeEKYwptcftBCX4ZKFkcOcctSBGIquAkGUPvfG2EUz/TqDbcwze8IXGYI2BaxHuTto20AVF5tLRWc+KDHK8op1LhiBWlOqh9ywZjJfO4DLaYZmbKOcv/NEULVYzagxK0l/F3obdittlZwecPyD60MY4JgjUuQriImWRTR1ovAdPSxA4YoIERp3vtlh6PGvd9d7LuUc9/l/VPmKd2leGKcxueFTQJi2sXWiuSlY5RytDHFJ2YGKzhom8XVDIioEIxxaeyF9HjUJ/ei7nuuqE5AL/4Cg5gyQHxisJdwA+hMf9xyL8/lxSdoI5FGBCeljEKmNV6LPzLoLPENWprKYfaYKMWNG+fk3kmhP9lV/6WhBPvZ4pjKaQ7kkDtywdQAN1mEaKFnbcuPJeptV9vjEh1qQXfgkkP5i8ABnHFVTqAI=",    
                         "MLKEM1024"  => "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",   
                         "MLDSA44"    => "qg/G33Zq4jTz4t5LwC+CsZMvsb2ULgS4YOWScB4RuabCfO6cPYpPtO8LTSX7wftRO9AynCaRzMRMWG1dxrIQwuMiWOSMZG3AzAfS+3uXcMUvkDIpb1MysnziUIvkNmHxUo9+xAWkdLwueb2QK/otPtoPK9VSU6M3CHyzu2HXmRSZY9ZWcX4R2mmJNvllVcB8rvTJu0jFl6/Tlkeflf+RVq53cFKTW8bZ/14g2iqgCzV4apCynQXQ/akkiJ8XY0iSTxZz75AR32B23VuHHgU3AbPHU5JgIcgIwhSiGjxZ0sYOdrd+A2z4lphVNjBAwtQo8vBrLQaHD0sWiu854yzsecf+N5LS95qbTC7CT05jQLTtJkt2wMr9/fuxAvTent+I6+0v0rMnEcVZk4UhV9s6rTz0N9DxsWIjTgXB8Ye/Bi+wdNkq3rSk6uqkLaFopBqzYYcMouDgUCYzYEeGGeJHlh5JsL4GGxcqlQQat19sLITHrACXf1TMXy4f/Rx7XcdCuaJm1ejEvUrP+qufN85/eK6mguZoJsFVIHc/Wq9fgSaUGqINu0tsHNy+xJffLhRmtnoAykmqNyD0iXICAd9vuKhwMJAD3ZG9E3xeiEIjSp7TrCJtj3Z0lNfzzhpzFzcDeLlWeQ3Yw/KWqJFOBJNeCGYxuio2giVJN4gUFuQDI3ATWukc6dME7gjvyY9JJlZVvopJA/sy9unL5s03goj9Uj7BU9ecWCPhxQg48WnWHjjCGoSfj8m65A7KWtnBmhjD3boDCfdkcteZ7+YD7tu06k+rBsaijtNwG+1jNGIE9+yEE/5oIfLbob00PzrzWSOVvtjQ7oGPkVZSmtcEVpzoP9za5ln5WFSKeCth1GPKOXwc1/Wi6Bk4GNECfsQPohLvQGcvRvFyAZXMv7INIlnwVgneeXpSPA0MgQeKO6dY+NyNbbobxJ4H4jEfcQx47h9NaersG8PIT96RR4rmSDmSWslQfgLwi7tLtcXAHFNMTQ20TDmuISsc9gIKePFkCadsvk2/1CJXYbxW0FCWGLyATG3/wL3GrWtgK5S9eElCMAVE28tHFjxQFmWSIvrwMSKQDqIW8D7Kq+/E49FY7Ysa16BR8VTE5cnFObcFrjnaLo4rEIrPj+9zA9N0Qoz6CfGOv86PrTSTAuif+owZmtRb54oOL/yJqdWsjPBTwqrFWmX5/3iQY630ciP5C43alfT6k7EumouiXKVPmriQJZsOfNkk0iifiHc+nN4G+tLPHpOwHFvXLYcMCrohLo2e2ULxNxuVcMd9evks76cHH3ykIt0LdLA285od7o4m1sAtaiIXZxr8GYobgmUkC7ZzBQyhy2ko1G22TWVQjUd+aaViGXq66gnnRjBDwvk5TBfIWUVKROvKyFyUwlMCKT3JLLNq1omLFj4HnzJ7YHoYisnSrIpXaWaxOXHtJrY+ywb/P5j0WHVzjMCyTC+2ALt9Z5V2tdRyAdNVjt7+GN5tOA4Ol2s3HGxsbX6pmLiQVrTVaJkx+WrMyN8E18oMlLpqriTEODtZv7TJyx1EKrDp2L8+iSMPP4OuIyuSHdaRA8DAfXXry5uRUo6veBwivvCdCmPoNdSnw1pomMge4vF6A5VvXTB0tLJDJsFmtiPLLhTRzlfThFYDOtLZAXqSMgntimqxT8UpngdDHaEnUsE12fBlVzmCJXRiIeswU8sIrvFhGtISFs3qaR7ay+2vTIAb9OIHRzIwPzxsxdaqm0tFjuL/jw==",   
                         "MLDSA65"    => "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",   
                         "MLDSA87"    => "iyBioeaMRmjMNNXJ0ivbOho6KXkGhMYzw66PiMmmryndFsv1jtJTiUcOM9iXnXNwu1pNirCMTSB1VtJDrBBfhtgD7F4+4AKKW1uyyhd+wpowydRgl6qHHw5Pm6lh9EHv4whc1BbuCxiCBgIo4n4mM5I3XVqbGiHl9l2+aRWmQcF1fbuX8QJ9HWO68RGdjVzM62d1Vm/KRC60dLh0W08hubQfbZAA4pQQrVklCQWzdmtIXqX+gC6h17VMtXzSM7+pUi8wUUv0V2qvI0f07tNUUg8VGvmPFsyBwerp7UcB6MDbRSaUEa2vjQW81JkgOlHuPK58QPrczbnIFOmzCR6ia92KqktM0NIMNwudGMa7xDU5qFdWrbhDTRqPrnThGnFIeuis1snJqUyZXbmkas50ucmd4sjo77SrCh/KYSgHs7EtW7GTbNJp3OW+Feb2YoII7XmTSBkuDUpGCFpQhS3gcyOZaEDN/n3Y5bOvn2xzin3Fs+9iYXEogmpLy/8PKPy0qPgTGAsdaBtSj8Ykgpw+cvQjuixqFecQSgE4cIaWxSRhoudinR6aIjA/IxCijrMTuGw2RnBfAJ4+8dwZj7lCjn72yzIWRtIR5y+EJj1KWlwQnU7eqzcqZ9isYKstLzMW8WwgmnO9/0B+yGGey9sOqNz0khFPZaFHqbBMPtkucwC+O3HMoBoIPbS607rPLjMzHqlOB15QfPwRziBJIizWf43jV1Eru7JeIY1p1usFHLpKf03Oz87Nf/ODyG2XAISclwHkq6yGhOSF+4beF/fVgDHX0Hfn577m7VuyXbggsx9gDI4go2fHVilML1Dn9MEkyzEzBm6zLUP/JZUSpVGAsOY9DdikqitMGvoQwe0HcwDSSZwfT1Z69vv21c1FhZ2gyWxIoLA+rpkDlb/6WPg/cyUT0/pWLcX/VxN7NYlfC1JkvrTVN+xst/7vMqcuVBFijbU6lCgV9OkH6yD0Bwflttmx1aWFiagHZlyUBo9mZk3QivZwsLV39GjEARJ1DkjiG5pcQueSpZWMJcLvquYoM+z3a1T3O3kffGd1nMT8Tu7aqaLSklLGmtNKzD9VVZ9SK5H/jbsvD7uI1iNheIX0klZ0h137FAB9bkQN9smFmUdyxvnSt0fb3DTGoEXn7+RS5yrP5fkr49wxI1IKzhRz5IidmZaaaQrdVSh9fLwkSeOSSt0/3+aEPXwXmBnZOIy0PlOhIxKtonKSVyRYBN7vGTDX71hSzpcdlLA87slROfrUYrdb4z0URCFhvzOR30ZFR2rK/AM5C1x+FQD+K04Xm2Xilcadcp7FutvHFS/11Sl8wEGXHuz0AhPGklNrAh6vk6A2P46rWwp8irwGFkxmolPBoDf/xZ1sAxlD7G9jfp5Sxn9sPA0WikT9ybI0Lj+LwSfMUoDdHpgp276DNe8s0ozPtKFaOdHXB/ZuOCSZZkHDJ+SdnVsRQicXhPok5OFQ1+kEmNkF2yCGtYDypEHUjfZzw5DBxhLr2A2XxvTXyMc2OgLQiI2zFxiZeQC7h7dI3rpwcMwdXCJtlQvBPCHsP8dhbmbj1573AlKaAWfU5Cki48H+DDMKKGVNY9Eb3REVP2kw/dNMF5uH8sgXkqh7i/CNXAkNyuHONdiq91xlXr88s2bN9gg0rzMd/+znbSD5S0glrJLrp+LB5NtuWmm6H84tJ54Pt/xFvIB8EDCd1d7SB5gjKqh/QqA2ykW+h3N6nWVgI2iCSKEUbClNYQGMgelmOmuqOkNXT3lToI1x2tpflXxzQIXOHklDbDgmhaIaLOKzFr96vJ98Ht3gj5L29STkIgL3jxHcIEt2sE1KFtHFuj4ClEKK3TSXh5CWWZB+wpUJoANNy23XzcCsHJmU4QEHMofvUwWOXYgBJmE6qLcG+Q/yLsylXmeu7tWae9avcAlT/O56wUAA42v/C3NM1s04cmUWXgrllIkHoiS9SZYRBh2FAM0ZK04lgY9El+XWhF7czCLkpTvQB7yaP4OXYRXyqb9dEgR13K/eyB8jX+nwjPt9sZPydC7tupE2dk1dv+cxYO/q7eOvK4526CjuyqiBGZWpdVMEPJnlUXxu/0d1eiqBh6O/vvoWYOF9sF2UuvS27pKOS/GJASzIz2gzEiNIAz5rMjksBhnJDk8HajgDjFc71oLutrmGD20x3YQRdIah2ZUiwc7+SqlZilJA1aYHsyJV0q0vZ34xTazrrleuX8SdDvyby0DVr3U0vOamX4aPvJoi3im+a0vgLKn1/9oYl+8HvYFhd6SbdbIEmJGidphMEMbmUctFHUDKh7dPg1JZnVNO2sWemLUFtuq95CEYZQT58A8hOUP/bv01eHlo5ekpOrmtWfSMEXnVqkWYsPHrMgoGpsKz+rx26IScRUbMDUURVBMZ0wGgCiXHORx9RLfdNV9htafwGGR0AkIJs06n3nW+MSMVYhlDvadF1zNK5GNqHJmOldXlMfT8m/2Y1JwJpbPo/yyeMVNoJxq9FsRmHQGPUYa+dmoKrBhtCDJZ2B81lUz7RrKvecwCWNKX5vFTU0yd5eyXangrKAT/7aUyhdCfDnJIww6UB8EEEFmsaxCrGPYo0czCuERkFbTrCgC6Gzsditeiqjc/V7q6YBrxYAFhEmc7yWoos+igJgZZwZYqqcLSFvFvVBFtdDfwb/Jqcpn6BivMusIvhsbBiqWPzSk27leVemuWfENPVgy/p11wlV/jiaRNZzjMKmYYr2MZ55q3mD+Ap8swp6o/KRzMl5ITTBjKBX4yxtjKw/XZ1DvsDwbmuqot1047AoGeVbYqH/EF9cPvPnbnnS2DuMmZoUYmyxTyIACLn63e6Ztnxlcnysfxo9lJTa20BpARx4PBRrFSB/FKaxm2jnwTpU56g0tg0kakco2FZKsYJtA+zPlHxgrMX9MXv1czSQF0LIOyecAV6dr+CvSBvcjTLccnpvt4Vl/b2KxOexe1CgmCgNUEm/zeSKHWqVwtfsyI/9iTOBON+UE4E5g/LQ9Hism+P57ZLXfmmLRiR6Zjh9Sl/MldIe0oy4++hqVYNGE3Xo/9y9LXrL1s4C74wD/9J8y8a1lc/WBJfQFL+UblKpmj3piyHbpUJAqgangbazvp/2TSHHZFLzXFn/jVa/UPW1Gq0FZIFzHhWYZjvpsksq2fD3iVZVgW+16ADJpQVBDhB4Mej84wFGwmKB+3EHuKirdHdMP1Woc4D1PgQRT7EoSzeI44nJzLLAVvKXO2T4ZxND5AHNWKoNOabHfdxbtldhHjZvIRNAKtTXR5EJJ5E0+BRSvC7E1kvsaaZa9FqWAv5ibDLCqjkPbq1wm1Sy8MzLwrvUJNynnpSqTTkaJ17zLDTk6CZT5s/zgUApHXTDL5ViIWEKpLDWnqRm0pNz7Db8Xq2RY4TgfbmItXlDq2RLZlo8KYtIx3QccFikfKzFUA8wElOR/yG/HFR21HGK3h"   
                         
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
TEST3:
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
TEST4:
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
TEST5:
echo "  subtest-5\n";
if ($diag_mode == false) {
  echo "    No DIAG mode, subtest will be skipped.\n";
  goto TEST6;
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
TEST6:
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
TEST7:
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

SUMMARY:
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
