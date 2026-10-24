<?php
/////////////////////////////////////////////////////////////////////
// ExtAuth_Simulator.php - simulator of the Encedo authenticator (mobile app) for T-5 and T-6
//
//   php ExtAuth_Simulator.php [serve]   app side of test_5 / test_6: waits for the requests the tests write to
//                                       out/extauth_exchange.json and answers them through api.encedo.com
//   php ExtAuth_Simulator.php direct    pairs and gets one access token talking to the HEM directly (no backend)
//   php ExtAuth_Simulator.php neg       as direct, plus malformed sealed scopes on /api/auth/ext/token (expects 406)
//
// Protocol functions in libs/extauth.php. See README.md.
/////////////////////////////////////////////////////////////////////

include "libs/lib.php";
include "libs/extauth.php";
include "config.php";

init_env();

$mode = isset($argv[1]) ? $argv[1] : "serve";
$exchange_file = __DIR__ . "/out/extauth_exchange.json";    // written by test_5 (QR data) and test_6 (event id)
$state_file = __DIR__ . "/out/extauth_state.json";          // pairing of the simulated app (keys, pid, eid)
@mkdir(__DIR__ . "/out");                                    // out/ is not in the repository (.gitignore)
$backend = "api.encedo.com";
$app_label = "ExtAuth_Simulator (PHP)";
$app_fid = "extauth-simulator-no-push";                     // push token placeholder - the simulator polls instead


function sim_save_state($app) {
  global $state_file;
  $out = array('pid' => $app['pid'], 'aid_prv' => base64_encode($app['aid_prv']), 'aid' => base64_encode($app['aid']), 'eid' => base64_encode($app['eid']));
  file_put_contents($state_file, json_encode($out, JSON_PRETTY_PRINT));
}

function sim_load_state() {
  global $state_file;
  $in = json_decode(@file_get_contents($state_file), true);
  if (!is_array($in)) return false;
  return array('pid' => $in['pid'], 'aid_prv' => base64_decode($in['aid_prv']), 'aid' => base64_decode($in['aid']), 'eid' => base64_decode($in['eid']));
}

function sim_show($name, $code, $want) {
  printf("  %-48s %3d  (want %d) %s\n", $name, $code, $want, ($code == $want) ? "OK" : "<--");
  return ($code == $want);
}


/////////////////////////////////////////////////////////////////////
// serve: app side of test_5 (pairing) and test_6 (events)
/////////////////////////////////////////////////////////////////////
// pairing as the app does after scanning the QR code of test_5
function sim_handle_pair($qr) {
  global $app_fid, $app_label;
  $u = parse_url($qr['link']);
  $ret_val = false;
  $ret_stat = http_transaction($u['scheme'], "GET", $u['host'], $u['path'], $ret_val);
  if ($ret_stat != 200) { echo "  GET link: $ret_stat\n"; return; }
  if (!hash_equals($qr['hash'], base64_encode(hash('sha256', $ret_val['request'], true)))) { echo "  QR hash does not match the request - ignored\n"; return; }
  $req = extauth_payload($ret_val['request']);
  $app = extauth_new_app();
  $app['eid'] = base64_decode($req['iss']);
  $reply = extauth_pairing_reply($app, $req, $app_label);
  $mac = base64_encode(hash_hmac("sha256", $reply . $app_fid, sodium_crypto_scalarmult($app['aid_prv'], base64_decode($req['aud'])), true));
  $post_data = json_encode(array('reply' => $reply, 'fid' => $app_fid, 'mac' => $mac, 'aid' => base64_encode($app['aid'])));
  $ret_val = false;
  $ret_stat = http_transaction($u['scheme'], "POST", $u['host'], $u['path'], $ret_val, $post_data);
  if (!sim_show("pairing with " . $qr['hostname'] . " (" . $qr['user'] . ")", $ret_stat, 200)) return;
  $app['pid'] = $ret_val['pid'];
  sim_save_state($app);
  echo "  paired, pid " . $app['pid'] . "\n";
}

// access request as the app does after the push notification of test_6: allow or deny as the test expects
function sim_handle_event($ev) {
  global $backend;
  $app = sim_load_state();
  if ($app === false) { echo "  no pairing - run test_5 with the simulator first\n"; return; }
  $path = "/notify/event/data/" . $ev['eventid'] . "/" . extauth_pidx($app['pid']);
  $ret_val = false;
  for ($i = 0; $i < 10; $i++) {                               // the event may need a moment on the backend
    $ret_stat = http_transaction("https", "GET", $backend, $path, $ret_val);
    if ($ret_stat == 200) break;
    sleep(1);
  }
  if ($ret_stat != 200) { echo "  GET event: $ret_stat\n"; return; }
  $m = extauth_session_key($app['aid_prv'], $app['eid'], $ret_val['jti']);
  $plain = extauth_unseal($ret_val['scope'], $m);
  if ($plain === false) { echo "  sealed scope invalid (MAC) - ignored\n"; return; }
  $res = false;
  $not_used = false;
  if ($ev['expect'] === "deny") {
    sim_show("event '$plain': deny", http_transaction("https", "DELETE", $backend, $path, $res, $not_used), 200);
    return;
  }
  $authreply = extauth_authreply($app, $ret_val['jti'], extauth_seal($plain, $m));
  $mac = base64_encode(hash_hmac("sha256", $authreply, sodium_crypto_scalarmult($app['aid_prv'], base64_decode($ret_val['epk'])), true));
  $post_data = json_encode(array('authreply' => $authreply, 'mac' => $mac));
  sim_show("event '$plain': allow", http_transaction("https", "POST", $backend, $path, $res, $post_data), 200);
}

if ($mode === "serve") {
  echo "ExtAuth simulator: waiting for test_5 / test_6 requests in out/" . basename($exchange_file) . " (Ctrl+C to stop)\n";
  @unlink($exchange_file);
  while (true) {
    clearstatcache();
    if (is_file($exchange_file)) {
      usleep(200000);                                         // let the writer finish
      $msg = json_decode(file_get_contents($exchange_file), true);
      unlink($exchange_file);
      if (is_array($msg) && isset($msg['type'])) {
        echo date("H:i:s") . " " . $msg['type'] . "\n";
        if ($msg['type'] === "pair") sim_handle_pair($msg['qr']);
        if ($msg['type'] === "event") sim_handle_event($msg);
      }
    }
    usleep(500000);
  }
}


/////////////////////////////////////////////////////////////////////
// direct / neg: pairing and access token against the HEM only
/////////////////////////////////////////////////////////////////////
if (($mode !== "direct") && ($mode !== "neg")) {
  echo "usage: php ExtAuth_Simulator.php [serve|direct|neg]\n";
  exit(1);
}
$ret_val = false;
$ret_stat = http_transaction("http", "GET", $cfg_domain, "/api/system/status", $ret_val);
if ($ret_stat != 200) exit("HEM not reachable\n");
if (isset($ret_val['inited'])) exit("HEM not initialised (run test_2 first)\n");
if (isset($ret_val['hostname'])) $cfg_domain = $ret_val['hostname'];
if (helper_checkin($cfg_domain) == false) exit("checkin failed (RTC)\n");
$token = helper_authorize($cfg_domain, $cfg_passpharse, "system:config");
if ($token == false) exit("local authorization failed\n");

echo "Pairing (direct)\n";
$app = false;
$code_ok = false;
if (!sim_show("POST /api/auth/ext/init + /api/auth/ext/validate", extauth_pair_direct($cfg_domain, $token, $app_label, $app, $code_ok), 200)) exit(1);
echo "  code " . ($code_ok ? "verified" : "MISMATCH") . "\n";

echo "Access token (direct)\n";
$authreq = false;
if (!sim_show("POST /api/auth/ext/request", extauth_request_direct($cfg_domain, "system:config", $authreq), 200)) exit(1);
$sealed = isset($authreq['scope'][$app['pid']]) ? $authreq['scope'][$app['pid']] : false;
$m = extauth_session_key($app['aid_prv'], $app['eid'], $authreq['jti']);
$plain = extauth_unseal($sealed, $m);
if ($plain === false) exit("  sealed scope for this pid missing or invalid\n");
echo "  requested scope '$plain' (MAC verified)\n";
$ext_token = false;
sim_show("POST /api/auth/ext/token", extauth_token_direct($cfg_domain, $app, $authreq['jti'], extauth_seal($plain, $m), $ext_token), 200);
$ret_val = false;
$not_used = false;
sim_show("issued token: GET /api/system/config", $ext_token ? http_transaction("https", "GET", $cfg_domain, "/api/system/config", $ret_val, $not_used, $ext_token) : 0, 200);

if ($mode === "neg") {
  echo "Malformed sealed scope (DEV-438 A5)\n";
  $raw = base64_decode(substr($sealed, 1));
  $mac = hash_hmac("sha256", $plain, $m, true);
  $pad0 = openssl_encrypt(str_repeat("x", 15) . "\0", "aes-128-cbc", substr($m, 0, 16), OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, substr($m, 16, 16));
  $t = false;
  sim_show("one block, no room for the MAC (16 B)", extauth_token_direct($cfg_domain, $app, $authreq['jti'], "A" . base64_encode(random_bytes(16)), $t), 406);
  sim_show("ciphertext not whole blocks (20 B + MAC)", extauth_token_direct($cfg_domain, $app, $authreq['jti'], "A" . base64_encode(random_bytes(20) . $mac), $t), 406);
  sim_show("padding byte 0", extauth_token_direct($cfg_domain, $app, $authreq['jti'], "A" . base64_encode($pad0 . $mac), $t), 406);
  sim_show("wrong MAC", extauth_token_direct($cfg_domain, $app, $authreq['jti'], "A" . base64_encode(substr($raw, 0, -32) . random_bytes(32)), $t), 406);
  sim_show("valid again (HEM still fine)", extauth_token_direct($cfg_domain, $app, $authreq['jti'], extauth_seal($plain, $m), $t), 200);
}
