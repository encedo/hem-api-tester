<?php

include "libs/lib.php";
include "config.php";


// initialize the execution env
init_env();


/////////////////////////////////////////////////////////////////////
// Wipe out the TOE       ///////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
echo "Wipe-out the TOE\n";
// a) get TOE status - discover correct domain & https status
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/status", $ret_val);
if ( $cfg_debug ) var_dump( $ret_val );
if ( $ret_stat != 200 ) goto print_and_exit;
if ( isset($ret_val['hostname']) ) {                       // remap domain name to the correct one
  $cfg_domain = $ret_val['hostname'];                      
}
// b) get access token if needed - only if device is inited
$token = false;
if ( !isset($ret_val['inited']) ) {
  $ret = helper_checkin($cfg_domain);
  if ($ret == false) goto print_and_exit;                     
  $token = helper_authorize($cfg_domain, $cfg_passpharse, "system:config");   
  if ($token == false) goto print_and_exit;                   
  $post_data = json_encode( array( 'wipeout' => true ) );
  $ret_val = false;
  $ret_stat = http_transaction("http", "POST", $cfg_domain, "/api/system/config", $ret_val, $post_data, $token);
  if ( $cfg_debug ) var_dump( $ret_val );
  if ( $ret_stat != 200 ) goto print_and_exit;
  echo "Done\n";
  exit;
  
} else {
  echo "Nothing to do\n";
  exit;
}


print_and_exit:
  echo "\nUpsss :/\n";
  exit;

/////////////////////////////////////////////////////////////////////
// end of file    ///////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
