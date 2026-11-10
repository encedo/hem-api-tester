<?php
/////////////////////////////////////////////////////////////////////
// extauth.php - Encedo authenticator (mobile app) side of the external authentication protocol
// Used by ExtAuth_Simulator.php (T-5/T-6 without a phone) and test_15.php (robustness of the ExtAuth endpoints).
// Protocol as in encedo-authenticator docs/PROTOCOL.md; needs libs/lib.php (ejwt_generate, base64url_decode, http_transaction).
/////////////////////////////////////////////////////////////////////

// JWT payload without signature check (the app has no secret before pairing)
function extauth_payload($jwt) {
  $p = explode(".", $jwt);
  if (count($p) < 2) return false;
  return json_decode(base64url_decode($p[1]), true);
}

// new app key pair (X25519): aid_prv, aid
function extauth_new_app() {
  $prv = random_bytes(32);
  return array('aid_prv' => $prv, 'aid' => sodium_crypto_scalarmult_base($prv));
}

// session key of one request: M = HMAC-SHA256(key = X25519(aid_prv, eid), msg = jti bytes); AES key = M[0:16], IV = M[16:32]
function extauth_session_key($aid_prv, $eid, $jti) {
  return hash_hmac("sha256", base64_decode($jti), sodium_crypto_scalarmult($aid_prv, $eid), true);
}

// sealed scope: "A" + base64( AES-128-CBC(PKCS#7) || HMAC-SHA256(plain, M) )
function extauth_seal($plain, $m) {
  $ct = openssl_encrypt($plain, "aes-128-cbc", substr($m, 0, 16), OPENSSL_RAW_DATA, substr($m, 16, 16));
  return "A" . base64_encode($ct . hash_hmac("sha256", $plain, $m, true));
}

// returns the plain scope, false if the format or the MAC is wrong
function extauth_unseal($sealed, $m) {
  if (!is_string($sealed) || ($sealed === "") || ($sealed[0] !== "A")) return false;
  $raw = base64_decode(substr($sealed, 1));
  if (strlen($raw) < 48) return false;
  $plain = openssl_decrypt(substr($raw, 0, -32), "aes-128-cbc", substr($m, 0, 16), OPENSSL_RAW_DATA, substr($m, 16, 16));
  if ($plain === false) return false;
  if (!hash_equals(hash_hmac("sha256", $plain, $m, true), substr($raw, -32))) return false;
  return $plain;
}

// pairing reply for the request JWT from /api/auth/ext/init ($app needs aid_prv, aid, eid)
function extauth_pairing_reply($app, $req, $label) {
  $claims = array('jti' => $req['jti'], 'iss' => base64_encode($app['aid']), 'aud' => $req['iss'], 'epk' => $req['aud'], 'label' => $label);
  return ejwt_generate($claims, $app['aid_prv'], $app['eid']);
}

// authreply for an access request: jti from the request, scope sealed with its session key ($app needs aid_prv, aid, eid, pid)
function extauth_authreply($app, $jti, $sealed, $period = 900) {
  $now = time();
  $claims = array('aud' => base64_encode($app['eid']), 'jti' => $jti, 'exp' => $now + $period, 'iat' => $now, 'pid' => $app['pid'], 'iss' => base64_encode($app['aid']), 'scope' => $sealed);
  return ejwt_generate($claims, $app['aid_prv'], $app['eid']);
}

// pid in a backend URL path: base64url without padding
function extauth_pidx($pid) {
  return rtrim(strtr($pid, '+/', '-_'), '=');
}

// pairing against the HEM directly (no backend): ext/init + ext/validate with a random pid of $pid_len bytes
// returns the HTTP status of the failing call or of ext/validate; $app gets the keys, eid and pid, $code_ok the check of 'code'
function extauth_pair_direct($domain, $token, $label, &$app, &$code_ok, $pid_len = 32) {
  $epk_prv = random_bytes(32);
  $ret_val = false;
  $post_data = json_encode(array('epk' => base64_encode(sodium_crypto_scalarmult_base($epk_prv))));
  $ret_stat = http_transaction("https", "POST", $domain, "/api/auth/ext/init", $ret_val, $post_data, $token);
  if ($ret_stat != 200) return $ret_stat;
  $req = extauth_payload($ret_val['request']);
  $app = extauth_new_app();
  $app['eid'] = base64_decode($ret_val['eid']);
  $app['pid'] = base64_encode(random_bytes($pid_len));        // assigned by the backend in the real flow
  $reply = extauth_pairing_reply($app, $req, $label);
  $ret_val = false;
  $post_data = json_encode(array('pid' => $app['pid'], 'reply' => $reply));
  $ret_stat = http_transaction("https", "POST", $domain, "/api/auth/ext/validate", $ret_val, $post_data, $token);
  $code_ok = ($ret_stat == 200) && hash_equals(base64_encode(hash_hmac("sha256", $reply, sodium_crypto_scalarmult($epk_prv, $app['eid']), true)), $ret_val['code']);
  return $ret_stat;
}

// access request (no token): returns the HTTP status, $authreq gets the authreq payload
function extauth_request_direct($domain, $scope, &$authreq) {
  $ret_val = false;
  $post_data = json_encode(array('epk' => base64_encode(sodium_crypto_scalarmult_base(random_bytes(32))), 'scope' => $scope));
  $ret_stat = http_transaction("https", "POST", $domain, "/api/auth/ext/request", $ret_val, $post_data);
  $authreq = ($ret_stat == 200) ? extauth_payload($ret_val['authreq']) : false;
  return $ret_stat;
}

// authreply to /api/auth/ext/token: returns the HTTP status, $token gets the issued token (false if none)
function extauth_token_direct($domain, $app, $jti, $sealed, &$token, $period = 900) {
  $ret_val = false;
  $post_data = json_encode(array('authreply' => extauth_authreply($app, $jti, $sealed, $period)));
  $ret_stat = http_transaction("https", "POST", $domain, "/api/auth/ext/token", $ret_val, $post_data);
  $token = isset($ret_val['token']) ? $ret_val['token'] : false;
  return $ret_stat;
}
