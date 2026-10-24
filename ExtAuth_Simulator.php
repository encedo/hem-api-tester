<?php
/////////////////////////////////////////////////////////////////////
// ExtAuth_Simulator.php - simulator of the Encedo authenticator (mobile app) for T-5 and T-6
//
//   php ExtAuth_Simulator.php [serve]   app side of test_5 / test_6: waits for the requests the tests write to
//                                       out/extauth_exchange.json and answers them through api.encedo.com
//   php ExtAuth_Simulator.php direct    pairs and gets one access token talking to the HEM directly (no backend)
//   php ExtAuth_Simulator.php neg       as direct, plus malformed sealed scopes on /api/auth/ext/token (expects 406)
//
// Protocol as in encedo-authenticator docs/PROTOCOL.md. See README.md.
/////////////////////////////////////////////////////////////////////

include "libs/lib.php";
include "config.php";

init_env();

$mode = isset($argv[1]) ? $argv[1] : "serve";
$exchange_file = __DIR__ . "/out/extauth_exchange.json";    // written by test_5 (QR data) and test_6 (event id)
$state_file = __DIR__ . "/out/extauth_state.json";          // pairing of the simulated app (keys, pid, eid)
@mkdir(__DIR__ . "/out");                                    // out/ is not in the repository (.gitignore)
$backend = "api.encedo.com";
$app_label = "ExtAuth_Simulator (PHP)";
$app_fid = "extauth-simulator-no-push";                     // push token placeholder - the simulator polls instead


// JWT payload without signature check (the app has no secret before pairing)
function sim_payload($jwt) {
  $p = explode(".", $jwt);
  return json_decode(base64url_decode($p[1]), true);
}

// session key of one request: M = HMAC-SHA256(key = X25519(aid_prv, eid), msg = jti bytes); AES key = M[0:16], IV = M[16:32]
function sim_session_key($aid_prv, $eid, $jti) {
  return hash_hmac("sha256", base64_decode($jti), sodium_crypto_scalarmult($aid_prv, $eid), true);
}

// sealed scope: "A" + base64( AES-128-CBC(PKCS#7) || HMAC-SHA256(plain, M) )
function sim_seal($plain, $m) {
  $ct = openssl_encrypt($plain, "aes-128-cbc", substr($m, 0, 16), OPENSSL_RAW_DATA, substr($m, 16, 16));
  return "A" . base64_encode($ct . hash_hmac("sha256", $plain, $m, true));
}

// returns the plain scope, false if the format or the MAC is wrong
function sim_unseal($sealed, $m) {
  if (!is_string($sealed) || ($sealed === "") || ($sealed[0] !== "A")) return false;
  $raw = base64_decode(substr($sealed, 1));
  if (strlen($raw) < 48) return false;
  $plain = openssl_decrypt(substr($raw, 0, -32), "aes-128-cbc", substr($m, 0, 16), OPENSSL_RAW_DATA, substr($m, 16, 16));
  if ($plain === false) return false;
  if (!hash_equals(hash_hmac("sha256", $plain, $m, true), substr($raw, -32))) return false;
  return $plain;
}

// pairing reply for the request JWT from /api/auth/ext/init
function sim_pairing_reply($app, $req) {
  global $app_label;
  $claims = array('jti' => $req['jti'], 'iss' => base64_encode($app['aid']), 'aud' => $req['iss'], 'epk' => $req['aud'], 'label' => $app_label);
  return ejwt_generate($claims, $app['aid_prv'], $app['eid']);
}

// authreply for an access request (jti from the request, scope sealed with its session key)
function sim_authreply($app, $jti, $sealed, $period = 900) {
  $now = time();
  $claims = array('aud' => base64_encode($app['eid']), 'jti' => $jti, 'exp' => $now + $period, 'iat' => $now, 'pid' => $app['pid'], 'iss' => base64_encode($app['aid']), 'scope' => $sealed);
  return ejwt_generate($claims, $app['aid_prv'], $app['eid']);
}

function sim_new_app() {
  $prv = random_bytes(32);
  return array('aid_prv' => $prv, 'aid' => sodium_crypto_scalarmult_base($prv));
}

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

// pid in a backend URL path: base64url without padding
function sim_pidx($pid) {
  return rtrim(strtr($pid, '+/', '-_'), '=');
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
  global $app_fid;
  $u = parse_url($qr['link']);
  $ret_val = false;
  $ret_stat = http_transaction($u['scheme'], "GET", $u['host'], $u['path'], $ret_val);
  if ($ret_stat != 200) { echo "  GET link: $ret_stat\n"; return; }
  if (!hash_equals($qr['hash'], base64_encode(hash('sha256', $ret_val['request'], true)))) { echo "  QR hash does not match the request - ignored\n"; return; }
  $req = sim_payload($ret_val['request']);
  $app = sim_new_app();
  $app['eid'] = base64_decode($req['iss']);
  $reply = sim_pairing_reply($app, $req);
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
  $path = "/notify/event/data/" . $ev['eventid'] . "/" . sim_pidx($app['pid']);
  $ret_val = false;
  for ($i = 0; $i < 10; $i++) {                               // the event may need a moment on the backend
    $ret_stat = http_transaction("https", "GET", $backend, $path, $ret_val);
    if ($ret_stat == 200) break;
    sleep(1);
  }
  if ($ret_stat != 200) { echo "  GET event: $ret_stat\n"; return; }
  $m = sim_session_key($app['aid_prv'], $app['eid'], $ret_val['jti']);
  $plain = sim_unseal($ret_val['scope'], $m);
  if ($plain === false) { echo "  sealed scope invalid (MAC) - ignored\n"; return; }
  $res = false;
  $not_used = false;
  if ($ev['expect'] === "deny") {
    sim_show("event '$plain': deny", http_transaction("https", "DELETE", $backend, $path, $res, $not_used), 200);
    return;
  }
  $authreply = sim_authreply($app, $ret_val['jti'], sim_seal($plain, $m));
  $mac = base64_encode(hash_hmac("sha256", $authreply, sodium_crypto_scalarmult($app['aid_prv'], base64_decode($ret_val['epk'])), true));
  $post_data = json_encode(array('authreply' => $authreply, 'mac' => $mac));
  sim_show("event '$plain': allow", http_transaction("https", "POST", $backend, $path, $res, $post_data), 200);
}

if ($mode === "serve") {
  echo "ExtAuth simulator: waiting for test_5 / test_6 requests in " . basename($exchange_file) . " (Ctrl+C to stop)\n";
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
$epk_prv = random_bytes(32);
$epk = sodium_crypto_scalarmult_base($epk_prv);
$ret_val = false;
$post_data = json_encode(array('epk' => base64_encode($epk)));
if (!sim_show("POST /api/auth/ext/init", http_transaction("https", "POST", $cfg_domain, "/api/auth/ext/init", $ret_val, $post_data, $token), 200)) exit(1);
$req = sim_payload($ret_val['request']);
$app = sim_new_app();
$app['eid'] = base64_decode($ret_val['eid']);
$app['pid'] = base64_encode(random_bytes(32));                // assigned by the backend in the real flow
$reply = sim_pairing_reply($app, $req);
$ret_val = false;
$post_data = json_encode(array('pid' => $app['pid'], 'reply' => $reply));
if (!sim_show("POST /api/auth/ext/validate", http_transaction("https", "POST", $cfg_domain, "/api/auth/ext/validate", $ret_val, $post_data, $token), 200)) exit(1);
$code = base64_encode(hash_hmac("sha256", $reply, sodium_crypto_scalarmult($epk_prv, $app['eid']), true));
echo "  kid " . $ret_val['kid'] . ", code " . (hash_equals($code, $ret_val['code']) ? "verified" : "MISMATCH") . "\n";

echo "Access token (direct)\n";
$ret_val = false;
$post_data = json_encode(array('epk' => base64_encode(sodium_crypto_scalarmult_base(random_bytes(32))), 'scope' => "system:config"));
if (!sim_show("POST /api/auth/ext/request", http_transaction("https", "POST", $cfg_domain, "/api/auth/ext/request", $ret_val, $post_data), 200)) exit(1);
$authreq = sim_payload($ret_val['authreq']);
$sealed = isset($authreq['scope'][$app['pid']]) ? $authreq['scope'][$app['pid']] : false;
$m = sim_session_key($app['aid_prv'], $app['eid'], $authreq['jti']);
$plain = sim_unseal($sealed, $m);
if ($plain === false) exit("  sealed scope for this pid missing or invalid\n");
echo "  requested scope '$plain' (MAC verified)\n";

function sim_token_try($app, $jti, $sealed) {
  global $cfg_domain;
  $ret_val = false;
  $post_data = json_encode(array('authreply' => sim_authreply($app, $jti, $sealed)));
  $ret_stat = http_transaction("https", "POST", $cfg_domain, "/api/auth/ext/token", $ret_val, $post_data);
  return array($ret_stat, isset($ret_val['token']) ? $ret_val['token'] : false);
}
list($ret_stat, $ext_token) = sim_token_try($app, $authreq['jti'], sim_seal($plain, $m));
sim_show("POST /api/auth/ext/token", $ret_stat, 200);
$ret_val = false;
$not_used = false;
sim_show("issued token: GET /api/system/config", $ext_token ? http_transaction("https", "GET", $cfg_domain, "/api/system/config", $ret_val, $not_used, $ext_token) : 0, 200);

if ($mode === "neg") {
  echo "Malformed sealed scope (DEV-438 A5)\n";
  $raw = base64_decode(substr($sealed, 1));
  $mac = hash_hmac("sha256", $plain, $m, true);
  $pad0 = openssl_encrypt(str_repeat("x", 15) . "\0", "aes-128-cbc", substr($m, 0, 16), OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, substr($m, 16, 16));
  sim_show("one block, no room for the MAC (16 B)", sim_token_try($app, $authreq['jti'], "A" . base64_encode(random_bytes(16)))[0], 406);
  sim_show("ciphertext not whole blocks (20 B + MAC)", sim_token_try($app, $authreq['jti'], "A" . base64_encode(random_bytes(20) . $mac))[0], 406);
  sim_show("padding byte 0", sim_token_try($app, $authreq['jti'], "A" . base64_encode($pad0 . $mac))[0], 406);
  sim_show("wrong MAC", sim_token_try($app, $authreq['jti'], "A" . base64_encode(substr($raw, 0, -32) . random_bytes(32)))[0], 406);
  sim_show("valid again (HEM still fine)", sim_token_try($app, $authreq['jti'], sim_seal($plain, $m))[0], 200);
}
