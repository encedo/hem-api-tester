<?php

// Two first variables are likely to be often changed. The others change with caution.

// adjust the tester name to be included in the test report summary
$cfg_tester = "John Doe";


// adjust the Encedo EPA default domain name (can be found in Delivery Note)
$cfg_epa_domain = "_changeme_.cloud.ence.do";


// Encedo helper backend API authorization key
$cfg_authkey = "_changeme_";


// Constants

// default local user passphrase use in all test
$cfg_passpharse = "example passphrase";

// default local master/admin passphrase use in all test
$cfg_passpharse_admin = "example admin passphrase";


// (optional) change the TOE chip ID on the Encedo EPA node
$cfg_epa_chipid = 10; 


// (optional) the Encedo PPA factory-default domain
$cfg_ppa_domain = "my.ence.do";


// (optional) var_dump() returned values
$cfg_debug =  0;
