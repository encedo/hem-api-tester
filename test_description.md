# hem-api-tester: test description

What every test checks, its subtests, the options and cases tried and the HEM endpoints it calls. Generated from the test code; keep it in sync when a test changes.

**Typical order:** `wipeout.php` (back to the uninitialised state), T-1, T-2 (initialisation), then T-3 ... T-15. T-1 needs TLS: after a classic wipe the TOE uses /tmp/tls.json from an earlier initialisation; after the factory default (T-15.13, `wipeout.php factory`) there is none, so run T-2 first. T-11 needs the keys created by T-10. T-5 and T-6 need the Encedo authenticator app or `ExtAuth_Simulator.php` (see README). T-7 and T-8 are interactive. Subtests that use `/api/diag/...` need a DIAG build; on a build without DIAG they are reported as `SKIPPED (no DIAG)` and count as passed.

**Status codes:** as in the HEM API docs (general information, response codes): 400 input validation, 401 token, 403 access scope, 404 path, 406 operation failed, 409 internal state, 411/413 protocol, 418 TLS required.

## Index

| Test | Title | File | Subtests |
|---|---|---|---|
| [T-0](#t-0--performance-tests) | Performance tests | `test_0.php` | 2 |
| [T-1](#t-1--check-toe-basic-functions) | Check TOE basic functions | `test_1.php` | 6 |
| [T-2](#t-2--toe-initialization) | TOE initialization | `test_2.php` | 3 |
| [T-3](#t-3--local-user-authentication) | Local user authentication | `test_3.php` | 5 |
| [T-4](#t-4--toe-configuration-change-functionality) | TOE configuration change functionality | `test_4.php` | 4 |
| [T-5](#t-5--external-authenticator-registration-functionality) | External authenticator registration functionality | `test_5.php` | 3 |
| [T-6](#t-6--external-authenticator-usage-functionality) | External authenticator usage functionality | `test_6.php` | 2 |
| [T-7](#t-7--firmware-upgrade-functionality) | Firmware upgrade functionality | `test_7.php` | 1 (picked at the prompt from 1, 2 or 3) |
| [T-8](#t-8--self-test-functionality) | Self-test functionality | `test_8.php` | 5 |
| [T-9](#t-9--audit-log-functionality) | Audit log functionality | `test_9.php` | 2 |
| [T-10](#t-10--key-management-functionality) | Key management functionality | `test_10.php` | 8 |
| [T-11](#t-11--cryptography-functionality) | Cryptography functionality | `test_11.php` | 9 |
| [T-12](#t-12--embedded-storage-management) | Embedded storage management | `test_12.php` | 2 |
| [T-13](#t-13--attestation-post-apisystemconfigattestation-jwt-key-block-proof-of-possession) | Attestation (POST /api/system/config/attestation): JWT, key block, proof of possession | `test_13.php` | 5 |
| [T-14](#t-14--key-derivation-interoperability-local-reproduction-of-apikeymgmtderive) | Key derivation interoperability (local reproduction of /api/keymgmt/derive) | `test_14.php` | 3 |
| [T-15](#t-15--input-validation-and-robustness) | Input validation and robustness | `test_15.php` | 13 |

## T-0 — Performance tests

**File:** `test_0.php` · **Subtests:** 2 · **Preconditions:** any init state (`inited` is not checked); `fls_state` must be 0; HTTPS (TLS) running (`https` present in status) for subtest 2

The test reads the TOE version and status, then measures HTTPS API performance: it sends 100 sequential `GET /api/system/version` requests over TLS and prints the average time per request. Only HTTP 200 on every call is checked. The timing is printed but has no pass/fail threshold.

| # | Subtest | What is checked (options / cases) | Expected result |
|---|---|---|---|
| 0.1 | Detect TOE | `GET /api/system/version` over http (hwv/blv/fwv; EPA if hwv contains "EPA", else PPA); `GET /api/system/status` over http; domain remapped to `hostname` if present | 200 on both; `fls_state` == 0 |
| 0.2 | HTTPS performance | Status must report `https`; 100 sequential `GET /api/system/version` over https; average time per request printed | `https` present; 200 on all 100 calls |

**Endpoints:** `GET /api/system/version` (http, https), `GET /api/system/status` (http)

## T-1 — Check TOE basic functions

**File:** `test_1.php` · **Subtests:** 6 · **Preconditions:** `fls_state` 0 (the code comment says "uninitialised TOE", but `inited` is not checked); HTTPS (TLS) running with a trusted certificate; internet access to api.encedo.com (checkin); 1.6 f expects the config `origin` to be "*", which the comment says is set after T-2

The test checks basic TOE functions: version and status detection, TLS 1.3 with a trusted certificate, the RTC checkin round-trip through api.encedo.com, and rejection of a forged token. It also checks input validation (malformed JSON, body over 7300 bytes) and HTTP-layer behaviour over raw TLS: security headers, WWW-Authenticate, case-insensitive header names, invalid Content-Length, CORS/PNA preflight and keep-alive (DEV-426, DEV-430).

| # | Subtest | What is checked (options / cases) | Expected result |
|---|---|---|---|
| 1.1 | Detect TOE | `GET /api/system/version` over http (hwv/blv/fwv, PPA/EPA); `GET /api/system/status` over http | 200 on both; `fls_state` == 0 |
| 1.2 | TLS check | Status must report `https`; `check_tls()` (certificate trust and peer name checked); `GET /api/system/status` over https | protocol "TLSv1.3"; 200 |
| 1.3 | Checkin / RTC | `GET /api/system/checkin` → `POST api.encedo.com/checkin` → `POST /api/system/checkin` (http); then `GET /api/system/status` | 200 on each, with `check` / `checked` / `status` present; status has `ts` |
| 1.4 | Forged token | `GET /api/system/status` with a hard-coded demo JWT (scope system:config, foreign signature, expired) | 401 |
| 1.5 | Input validation | `POST /api/system/checkin` with malformed JSON (no closing `}`); with valid JSON 1 byte over the 7300-byte limit | 400; 413 |
| 1.6 | HTTP headers (raw TLS) | a) GET status with X-Request-ID; b) `Authorization: Bearer junk`; c) lowercase `authorization`; d) POST checkin with lowercase content-type/content-length and malformed JSON; e) non-numeric Content-Length ("<n>abc"); f) OPTIONS preflight with Origin, ACR-Method POST, ACR-Headers, PNA request; g) preflight without PNA header; h) two requests on one keep-alive connection | a) 200, `nosniff`, Cache-Control has `no-store`, no Server/X-Powered-By, X-Request-ID echoed; b) 401 with WWW-Authenticate starting "Bearer"; c) 401; d) 400; e) 400; f) 204, exact origin echoed, Vary has Origin, no Allow-Credentials, Allow-Methods has POST, Allow-Headers has Authorization, `nosniff`; PPA: Allow-Private-Network "true" and Private-Network-Access-Name "encedo-ppa"; EPA: no PNA header; g) 204, no PNA header; h) 200 with `Connection: keep-alive`, then 200 |

**Endpoints:** `GET /api/system/version` (http), `GET /api/system/status` (http, https, raw https), `GET /api/system/checkin` (http), `POST /api/system/checkin` (http, raw https), `OPTIONS /api/system/status` (raw https), `GET /api/system/version` (raw https, keep-alive), external `POST https://api.encedo.com/checkin`

## T-2 — TOE initialization

**File:** `test_2.php` · **Subtests:** 3 · **Preconditions:** not initialised (status must contain `inited`), `fls_state` 0; internet access to api.encedo.com (checkin, domain registration and TLS certificate); the TOE reboots during the test

The test initialises the TOE. It sets the RTC through checkin, runs the `/api/auth/init` challenge/response with USER and ADMIN keys (PBKDF2 of the passphrases, X25519 ECDH-signed JWT) and sends the full configuration. It then waits for the storage format to finish, registers the domain and certificate at api.encedo.com, uploads the TLS certificate, reboots and checks the device again. It also checks that the device cannot be initialised a second time and that TLS 1.3 works on the new hostname.

| # | Subtest | What is checked (options / cases) | Expected result |
|---|---|---|---|
| 2.1 | Initialise | Status/version; checkin round-trip; domain prefix: `my` (default, `$cfg_enforce_ppa_domain`=1) or `cctest<time>` (EPA mode), checked free via `/domain/check`; `GET`+`POST /api/auth/init` (cfg: userkey, user, email, hostname, ip, storage_mode 81, disk0size 8 MB, dnsd false, trusted_ts/backend, allow_keysearch, gen_csr, origin "*"); poll status until `format` is "done"; N18: during the format `GET /api/auth/token` and `GET /api/keymgmt/list` checked once; domain register (PPA default: genuine+ip; otherwise csr+genuine+cname/ip, polled while 201); `POST /api/system/config` {tls}; reboot if `reboot_required`; status (up to 3 tries); checkin again | 200 on TOE calls; `/domain/check` 404 (free); N18 calls return 409; register 200 (or 201 then poll until 200, any status ≥400 fails); status 200 after reboot; checkin fields present |
| 2.2 | Re-init blocked | `GET /api/auth/init` again | 409 |
| 2.3 | TLS on new host | Status over http must report `https`; domain remapped to `hostname`; `check_tls()`; `GET /api/system/status` over https | 200; TLSv1.3 with a trusted certificate; 200 |

**Endpoints:** `GET /api/system/status` (http, https), `GET /api/system/version` (http), `GET /api/system/checkin` (http), `POST /api/system/checkin` (http), `GET /api/auth/init` (http), `POST /api/auth/init` (http), `GET /api/auth/token` (http, during format), `GET /api/keymgmt/list` (http, during format), `POST /api/system/config` (http, init token), `GET /api/system/reboot` (http, init token); external `POST https://api.encedo.com/checkin`, `GET https://api.encedo.com/domain/check/<prefix>` (EPA mode only), `POST https://api.encedo.com/domain/register/<prefix>/<authkey>`, `GET https://api.encedo.com/domain/register/<id>` (polling after 201)

## T-3 — Local user authentication

**File:** `test_3.php` · **Subtests:** 5 · **Preconditions:** initialised (no `inited` in status), `fls_state` 0, HTTPS running; internet access to api.encedo.com (checkin); long run time (about 30 s in 3.3 plus a full token lifetime wait in 3.5)

The test checks local authentication over HTTPS: USER and ADMIN tokens are issued with the correct roles (`sub` U / M), and the API enforces role and scope. It checks the FPT_AFL.1 timing: at least 500 ms per auth, more than 1500 ms after 3 failed attempts, and back under 1500 ms more than 15 s after the last failure. It also checks that a tampered token is rejected and that an expired token is rejected.

| # | Subtest | What is checked (options / cases) | Expected result |
|---|---|---|---|
| 3.1 | USER + ADMIN auth | Status; version and checkin over https; `GET`+`POST /api/auth/token` with USER passphrase (scope system:config, `ctx` set) and with ADMIN passphrase (scope system:config) | 200; USER token `sub`=="U"; ADMIN token `sub`=="M" |
| 3.2 | Role / scope check | `POST /api/auth/ext/init` (placeholder epk) with USER and with ADMIN token; `GET /api/logger/key` with both (scope system:config) | ext/init: USER 200, ADMIN 403; logger/key: 403 for both |
| 3.3 | Auth failure delay (FPT_AFL.1) | Correct auth timed; 5 wrong-password attempts timed; then correct auth in a loop for about 30 s after the last failure | Correct auth ≥500 ms; wrong attempts 401, attempts 4–5 take >1500 ms; correct auths 200, under 1500 ms once >15 s have passed |
| 3.4 | Tampered token | Correct USER token used on `POST /api/auth/ext/init`; then `exp` +3600 changed in the payload with the signature kept | 200; tampered token → 401 |
| 3.5 | Token expiry | `helper_authorize` (scope system:config, exp 120 s); `POST /api/auth/ext/init` with `$user_auth_token`; wait (exp − iat + 3 s); retry | 200 before; 401 after expiry |

**Endpoints:** `GET /api/system/status` (http), `GET /api/system/version` (https), `GET /api/system/checkin` (https), `POST /api/system/checkin` (https), `GET /api/auth/token` (https; http via helper_authorize), `POST /api/auth/token` (https; http via helper_authorize), `POST /api/auth/ext/init` (https), `GET /api/logger/key` (https); external `POST https://api.encedo.com/checkin`

## T-4 — TOE configuration change functionality

**File:** `test_4.php` · **Subtests:** 4 · **Preconditions:** initialised, `fls_state` 0, HTTPS running; internet access to api.encedo.com (checkin); subtest 4 needs a DIAG build (fwv contains "-DIAG") and reboots the TOE

The test checks reading and changing the TOE config with a system:config USER token. A valid change must raise `uts`. A field that is too long must be rejected, and an unknown key must be ignored. The test also checks scope enforcement, the PPA-only attestation and provisioning endpoints, and that a simulated failure state (FLS.1) blocks the API until a reboot.

| # | Subtest | What is checked (options / cases) | Expected result |
|---|---|---|---|
| 4.1 | Config change | Status/version; `helper_checkin`; `helper_authorize` (system:config); GET config, POST `{user:"Nickname-<time>"}`, GET config again; CORS (e): origin list `Cors-X.Hem-Api-Tester.Encedo.com other.example.com *.wild.example.com`, OPTIONS preflight from cors-x (lower case), cors-y, other.example.co, a.wild.example.com, a.b.wild.example.com, GET with Origin cors-y, GET without Origin; previous origin restored | 200 on all; `updated` true; new `uts` > old `uts`; CORS: 204 with the origin echoed for cors-x and a.wild, 412 for the others, 200 without Origin, origin restored |
| 4.2 | Config validator | POST `user` longer than the 64-character limit; POST unknown key `useR`; GET config again | 400; 200 with `updated` false; `uts` unchanged |
| 4.3 | Scope check | Tokens with scope system:config and system:reboot used on GET config; PPA only: `GET /api/system/config/attestation` with both tokens, `POST /api/system/config/provisioning` (dummy crt/genuine) | config: 200 / 403; attestation: 200 for both; provisioning 403 (already provisioned) |
| 4.4 | Failure state (DIAG-only) | New token; GET config; `GET /api/diag/break_temp` (no token); wait 3 s; PPA only: GET attestation; `GET /api/system/reboot`. Without DIAG: 'SKIPPED (no DIAG)', counts as passed | 200; 200 (FLS.1 triggered); attestation 409; reboot 200 |

**Endpoints:** `GET /api/system/status` (http), `GET /api/system/version` (https), `GET /api/system/checkin` + `POST /api/system/checkin` (http, via helper_checkin), `GET`+`POST /api/auth/token` (http, via helper_authorize), `GET /api/system/config` (https), `POST /api/system/config` (https), `OPTIONS /api/system/status` + `GET /api/system/status` with Origin (raw https, 4.1 CORS), `GET /api/system/config/attestation` (https, PPA), `POST /api/system/config/provisioning` (https, PPA), `GET /api/diag/break_temp` (https, DIAG), `GET /api/system/reboot` (https); external `POST https://api.encedo.com/checkin` (via helper_checkin)

## T-5 — External authenticator registration functionality

**File:** `test_5.php` · **Subtests:** 3 · **Preconditions:** initialised, `fls_state` 0, HTTPS running; internet access to api.encedo.com and quickchart.io; user interaction in 5.1 (scan the QR code with the Encedo mobile app within about 60 s, or use ExtAuth_Simulator.php with `out/extauth_exchange.json`); subtest 3 needs a DIAG build and reboots the TOE

The test checks pairing an external authenticator (mobile app) through the Encedo backend notify service. The TOE challenge is shown as a QR code and the backend is polled until the app replies. The reply is validated on the TOE and the pairing is finalised on the backend. The test also checks that a token with the wrong scope cannot start a pairing, and that pairing is blocked (409) in a simulated failure state.

| # | Subtest | What is checked (options / cases) | Expected result |
|---|---|---|---|
| 5.1 | Pairing (interactive) | Status/version; `helper_checkin`; `helper_authorize` (system:config); GET config (eid, user, email, hostname); `/notify/session` → epk; `POST /api/auth/ext/init` {epk}; `/notify/register/init` → rid, link; QR made from {link, hash=base64(SHA-256(request)), user, email, hostname} and opened (also written to `out/extauth_exchange.json`); `/notify/register/check/<rid>` polled every 5 s (up to 13 polls); `POST /api/auth/ext/validate` {pid, reply}; `/notify/register/finalise/<rid>` | 200 on all calls; poll returns 202 while pending and must end with 200 |
| 5.2 | Wrong scope | Token with scope `system:wrong`; GET config (correct token); new `/notify/session` epk; `POST /api/auth/ext/init` with the wrong-scope token | config/session 200; ext/init 403 |
| 5.3 | Failure state (DIAG-only) | `GET /api/diag/break_temp`; wait 3 s; `POST /api/auth/ext/init` (epk from 5.2, wrong-scope token); `GET /api/system/reboot` (correct token). Without DIAG: 'SKIPPED (no DIAG)', counts as passed | 200; ext/init 409 (FLS.1); reboot 200 |

**Endpoints:** `GET /api/system/status` (http), `GET /api/system/version` (https), `GET /api/system/checkin` + `POST /api/system/checkin` (http, via helper_checkin), `GET`+`POST /api/auth/token` (http, via helper_authorize), `GET /api/system/config` (https), `POST /api/auth/ext/init` (https), `POST /api/auth/ext/validate` (https), `GET /api/diag/break_temp` (https, DIAG), `GET /api/system/reboot` (https); external `POST https://api.encedo.com/checkin` (via helper_checkin), `POST https://api.encedo.com/notify/session`, `POST https://api.encedo.com/notify/register/init`, `GET https://api.encedo.com/notify/register/check/<rid>`, `POST https://api.encedo.com/notify/register/finalise/<rid>`, `GET https://quickchart.io/qr?...` (QR image)

## T-6 — External authenticator usage functionality

**File:** `test_6.php` · **Subtests:** 2 · **Preconditions:** initialised device, `fls_state` = 0; internet access to api.encedo.com (checkin + /notify backend); user interaction on the paired Encedo mobile app within ~60 s per subtest (ALLOW in 6.1, DENY in 6.2), or ExtAuth_Simulator.php driven by `out/extauth_exchange.json`

The test checks remote (external) user authentication through the Encedo mobile app and the api.encedo.com notification backend. The HEM creates an ext-auth challenge for scope `system:config`, the challenge goes to the app as a notification event, and the tester polls for the user's decision. When the user allows, the reply is exchanged for a token and the token must work. When the user denies, a deny result must come back.

| # | Subtest | What is checked (options / cases) | Expected result |
|---|---|---|---|
| 6.1 | Remote auth - ALLOW | Status/version discovery, RTC checkin; get backend `epk`; `POST /api/auth/ext/request` (epk, exp = now+120 s, scope `system:config`); post the challenge to `/notify/event/new`; write `{eventid, expect: "allow"}` for the simulator; poll `/notify/event/check/<id>` every 5 s, up to 13 times; send `authreply` to `/api/auth/ext/token`; use the token on `GET /api/system/config` | All HEM calls 200; event check ends with 200 and no `deny`; ext token issued (200); `/api/system/config` with the token returns 200 |
| 6.2 | Remote auth - DENY | Same flow with exp = now+60 s and `expect: "deny"`; `/api/auth/ext/token` is not called (the app returns only `deny`) | ext request 200; event check ends with 200 and the reply contains `deny` |

**Endpoints:** `GET /api/system/status` (http), `GET /api/system/version` (https), `GET /api/system/checkin` (http), `POST /api/system/checkin` (http), `POST /api/auth/ext/request` (https), `POST /api/auth/ext/token` (https), `GET /api/system/config` (https); external: `POST api.encedo.com/checkin`, `GET api.encedo.com/notify/session`, `POST api.encedo.com/notify/event/new`, `GET api.encedo.com/notify/event/check/<eventid>` (all https)

## T-7 — Firmware upgrade functionality

**File:** `test_7.php` · **Subtests:** 1 (picked at the prompt from 1, 2 or 3) · **Preconditions:** initialised device, `fls_state` = 0; PPA only (exits on EPA); internet access to api.encedo.com and ipfs.encedo.com; interactive (subtest number prompt; 7.1 on Windows needs a manual HEX upload with an external tool and Enter; 7.1 on Linux needs sudo and `/dev/ttyACM0`)

The test checks the firmware/UI upgrade paths. The operator runs one of three subtests per run. Each subtest authorises with scope `system:upgrade`, runs the upgrade, waits for the device to come back and reads the version again. The test does not compare the old and new `fws`/`uis` values: it only needs the upgrade calls to succeed and the device to answer again.

| # | Subtest | What is checked (options / cases) | Expected result |
|---|---|---|---|
| 7.1 | USB-mode upgrade | `GET /api/system/upgrade/usbmode`; Windows: user sends the Intel HEX manually; Linux: downloads official FW 1.2.2 HEX from IPFS and flashes it with `libs/blbx -b <hex> -p /dev/ttyACM0` (sudo), waits 15 s; polls status up to 11 times, 3 s apart | usbmode 200; status 200 after reboot; version 200 |
| 7.2 | Firmware upload (HTTP) | Downloads FW 1.2.2 DIAG build from IPFS; `POST upload_fw` (file `firmware.bin`); polls `check_fw` up to 13 times, 10 s apart (stops on 200 or >= 400); `install_fw`; waits 30 s, then polls status | Upload does not fail at transport level; `check_fw` 200; `install_fw` 200; status and version 200 after reboot |
| 7.3 | Dashboard (UI) upload | Downloads the current Encedo Manager from api.encedo.com; `POST upload_ui` (file `webroot.tar`); polls `check_ui` (same rules as 7.2); `install_ui`; waits 5 s, then polls status | `check_ui` 200; `install_ui` 200; status and version 200 afterwards |

**Endpoints:** `GET /api/system/status` (http), `GET /api/system/version` (https), `GET /api/system/checkin` (http), `POST /api/system/checkin` (http), `GET /api/auth/token` (http), `POST /api/auth/token` (http), `GET /api/system/upgrade/usbmode` (https), `POST /api/system/upgrade/upload_fw` (https), `GET /api/system/upgrade/check_fw` (https), `GET /api/system/upgrade/install_fw` (https), `POST /api/system/upgrade/upload_ui` (https), `GET /api/system/upgrade/check_ui` (https), `GET /api/system/upgrade/install_ui` (https); external: `POST api.encedo.com/checkin`, `GET api.encedo.com/download/dashboard/current`, `GET ipfs.encedo.com/ipfs/<cid>` (FW HEX and DIAG FW images)

## T-8 — Self-test functionality

**File:** `test_8.php` · **Subtests:** 5 · **Preconditions:** initialised device, `fls_state` = 0; DIAG build for 8.2–8.5 (on a build without DIAG they are `SKIPPED (no DIAG)` and count as passed); internet access to api.encedo.com; interactive (8.3 on PPA: unplug/replug after shutdown and press Enter); destructive (8.4 wipes the configuration)

The test checks the self-test and failure-state (FLS) mechanisms. It runs a full self-test and then injects faults with DIAG tools: TLS packet corruption, a TRNG failure, key-repository corruption and an out-of-range temperature. After each fault the device must detect it (non-zero `fls_state` or failing TLS) and recover after a reboot or power cycle. 8.3 also collects a 2 MiB TRNG sample into `out/probe.bin` for offline entropy analysis.

| # | Subtest | What is checked (options / cases) | Expected result |
|---|---|---|---|
| 8.1 | Full self-test | Status/version (both http), checkin, token `system:config`; `GET /api/system/selftest`, then polls while `kat_busy` is set (up to 25 times, 10 s apart) | All calls 200; final `fls_state` = 0 |
| 8.2 | TLS fault injection (DIAG-only) | 20 https `GET /api/system/version` calls (baseline, not evaluated); `GET /api/diag/break_tls` (http); 20 more https calls, counting failures; reboot over http with the token; waits 30 s | `break_tls` 200; reboot 200; at least 1 failed TLS connection after injection. Without DIAG: `SKIPPED (no DIAG)` |
| 8.3 | TRNG failure + sample | Status `fls_state` = 0; checkin, token; `GET /api/diag/break_trng`, wait 20 s; status; `break_trng` again (reads `last_val`); EPA: reboot; PPA: `shutdown`, status must not answer, user replugs, wait 30 s; status; then repeated `GET /api/diag/test_trng` until 2 MiB of `rnd` data is collected into `out/probe.bin` | After the break, `fls_state` != 0; after the shutdown, status does not answer (PPA); after recovery, `fls_state` = 0; all DIAG calls 200 |
| 8.4 | Key repo corruption | Tokens `system:config`, `keymgmt:imp`, `keymgmt:list`; import a CURVE25519 public key ("T8.4 demo key"); find its `_addr`/`_len` in `/api/keymgmt/list`; memdump, `corrupt_repo/<addr>`, memdump again; full self-test with polling; `GET /api/diag/wipe_config`, wait 30 s; PPA: read `genuine` from `config/attestation`, register the `my` domain at api.encedo.com, POST `tls` to `/api/system/config` (http, no token), reboot (http); EPA: message only | Import/list 200; key found; dumps differ; self-test 200 with `fls_state` != 0; wipe 200; on PPA, attestation, domain register, config and reboot all 200 |
| 8.5 | Temperature fault | Default `cfg_domain` restored; all over http; status `fls_state` = 0; `GET /api/diag/break_temp`, wait 5 s; status; reboot without a token (device is wiped) | `break_temp` 200; `fls_state` != 0 afterwards; reboot 200 |

**Endpoints:** `GET /api/system/status` (http, https), `GET /api/system/version` (http, https), `GET /api/system/checkin` (http), `POST /api/system/checkin` (http), `GET /api/auth/token` (http), `POST /api/auth/token` (http), `GET /api/system/selftest` (https), `GET /api/system/reboot` (http, https), `GET /api/system/shutdown` (https), `POST /api/keymgmt/import` (https), `GET /api/keymgmt/list` (https), `GET /api/system/config/attestation` (http), `POST /api/system/config` (http), `GET /api/diag/break_tls` (http), `GET /api/diag/break_trng` (https), `GET /api/diag/test_trng` (https), `GET /api/diag/memdump/<addr>/<len>` (https), `GET /api/diag/corrupt_repo/<addr>` (https), `GET /api/diag/wipe_config` (https), `GET /api/diag/break_temp` (http); external: `POST api.encedo.com/checkin`, `POST api.encedo.com/domain/register/my` (https)

## T-9 — Audit log functionality

**File:** `test_9.php` · **Subtests:** 2 · **Preconditions:** initialised device, `fls_state` = 0; internet access to api.encedo.com; EPA additionally needs `$cfg_authkey` and the device's MQTT log on the Encedo backend; two reboots (60 s waits on PPA, 30 s on EPA)

The test checks the signed audit log. It reads the logger public key and verifies an Ed25519 signature over a fresh nonce. It then reboots twice to produce new log files and gets the entries: on PPA from the device, on EPA from the Encedo MQTT log server. The integrity check verifies the signed key records (Ed25519) and checks the truncated HMAC-SHA256 on every entry line.

| # | Subtest | What is checked (options / cases) | Expected result |
|---|---|---|---|
| 9.1 | Log retrieval | Status/version (http), checkin, token `logger:get`; `GET /api/logger/key` with Ed25519 verify of `nonce_signed` over `nonce`. PPA: `list/0`, two reboots (`system:config` token, checkin before each), `list/0`, download the second-to-last log id, keep the lines with 7 `|` fields. EPA: two reboots, then `GET api.encedo.com/cctest/getmqttlog/<hem pubkey b64url>/<authkey>/<seconds>` | All calls 200; signature valid; non-empty log data |
| 9.2 | Log integrity | Checkin, token `logger:get`, `/api/logger/key` and the signature verified again; `encedo_log_integrity_check()`: on key records (fields 2 and 3 = 0) the Ed25519 signature of the HMAC key is verified with the logger key; on the other lines the first 16 B of HMAC-SHA256 are compared | Key 200; signature valid; integrity check returns true |

**Endpoints:** `GET /api/system/status` (http), `GET /api/system/version` (http), `GET /api/system/checkin` (http), `POST /api/system/checkin` (http), `GET /api/auth/token` (http), `POST /api/auth/token` (http), `GET /api/logger/key` (https), `GET /api/logger/list/0` (https), `GET /api/logger/<id>` (https), `GET /api/system/reboot` (https); external: `POST api.encedo.com/checkin`, `GET api.encedo.com/cctest/getmqttlog/<hem>/<authkey>/<last>` (https, EPA only)

## T-10 — Key management functionality

**File:** `test_10.php` · **Subtests:** 8 · **Preconditions:** initialised device, `fls_state` = 0; internet access to api.encedo.com (checkin); DIAG build for 10.5 and 10.8 (otherwise `SKIPPED (no DIAG)`, counted as passed); 10.4 depends on the keys created in 10.1; on a re-run, 10.2 expects all imports to be rejected as duplicates

The test checks the key-management API: key generation for all supported types (NIST/Koblitz EC, X25519/X448, EdDSA, SHA2/SHA3 HMAC, AES, ML-KEM, ML-DSA), ECDH-based derivation with its options, public-key import, update, search, delete, scope/TLS enforcement, the random endpoint and refusal in failure state. Each create and derive reply must match the list record and the key read back by `GET /api/keymgmt/get`.

| # | Subtest | What is checked (options / cases) | Expected result |
|---|---|---|---|
| 10.1 | Create + derive | Tokens `keymgmt:gen`, `keymgmt:list`; paged list; create 23 types (SECP256R1/384R1/521R1/256K1 with mode `ECDH,ExDSA`, CURVE25519, CURVE448, ED25519, ED448, SHA2-256/384/512, SHA3-256/384/512, AES128/192/256, MLKEM512/768/1024, MLDSA44/65/87), `return_pubkey` on every second key; check reply (`type` last flag, label, descr, `created` = `updated`, `pubkey` only for asymmetric keys when requested) and GET (no `kid`, same fields); derive all 17 non-PQC types from each of the 6 ECDH keys with a fixed peer pubkey (102 derives), same checks; derive-option cases on the SECP256R1 key and on a new ED25519 key with mode `ECDH` | All creates 200; list count +23; all 102 derives 200 and list count + derived; options: no salt 409 (duplicate), salt 200, same salt 409, `ext_kid` 200, ED25519 main 200, ED25519 + `ext_kid` 200, MLKEM512 type 400, AES512 400, salt 129 B 400, salt not base64 400, uncompressed 65 B pubkey 406, label 64 200, label 65 400 |
| 10.2 | Import | Tokens `keymgmt:imp`, `keymgmt:list`; import 17 public keys (4 SECP, CURVE25519/448, ED25519/448, MLKEM512/768/1024, MLDSA44/65/87), all with mode `ECDH`, label cut to 31 chars; imported NIST keys read back with a `keymgmt:get` token | All 17 return 200 (first run) or all 409 (re-run, duplicates); any other status fails; NIST pubkey (02/03 prefix) read back unchanged |
| 10.3 | Update | Tokens `keymgmt:upd`, `keymgmt:list`; first key with `ECDH` in `type`: label + " - updated"; then label 64 chars and descr 128 B; then label 65 chars, and descr 129 B | Update 200 and the list shows a new label and `updated`; the 64/128 values are stored exactly as sent; 65 chars / 129 B give 400 |
| 10.4 | Search | No-token search `descr` `^CCTEST:`; with a `keymgmt:list` token, paged (15 per page): type filter (SHA2-256, SECP256R1, SECP384R1 return only that type); type `XYZ` and mode `SIGN` rejected; mode `ECDH`, `ExDSA` and `ECDH,ExDSA` (returned keys carry all flags); `return_pubkey` (SECP256R1 has `pubkey`, AES256 has none); suffix `_SHA3-512$` and prefix `^...ED448`; pattern limits | No-token search 200; filters non-empty and correct; XYZ/SIGN 400; `""`, `^`, `$` 400; 129 B pattern 400; 128 B pattern 200 |
| 10.5 | Delete + zeroise (DIAG-only) | Tokens `keymgmt:del`, `keymgmt:list`; first key with `ExDSA`; memdump at `_addr`/`_len`; `DELETE /api/keymgmt/delete/<kid>`; memdump again; list again | Delete 200; memory content changed; list count -1. Without DIAG: `SKIPPED (no DIAG)` |
| 10.6 | Scope / TLS enforcement | Create CURVE25519 with the `keymgmt:list` token (https); with the `keymgmt:gen` token over http; with the `keymgmt:gen` token over https | First two calls must not return 200; the third returns 200 |
| 10.7 | Random (`/api/crypto/random`) | No token; http with a token; default length; `/0`, `/8193`, `/abc`, `/12x`, `/api/crypto/randomx`; 8 × `/8192` | No token 401; http 418; default 200 with 32 B; bad lengths 400; `randomx` 404; each chunk 8192 B and unique; 64 KB has all 256 byte values and a mean of 126–129 |
| 10.8 | FLS refuses keygen (DIAG-only) | Token `system:config`; `GET /api/diag/break_temp`; status; create CURVE25519 with the `keymgmt:gen` token; reboot | break_temp 200; `fls_state` != 0; create 409; reboot 200. Without DIAG: `SKIPPED (no DIAG)` |

**Endpoints:** `GET /api/system/status` (http, https), `GET /api/system/version` (http), `GET /api/system/checkin` (http), `POST /api/system/checkin` (http), `GET /api/auth/token` (http), `POST /api/auth/token` (http), `GET /api/keymgmt/list/<offset>` (https), `POST /api/keymgmt/create` (https, http in 10.6), `GET /api/keymgmt/get/<kid>` (https), `POST /api/keymgmt/derive` (https), `POST /api/keymgmt/import` (https), `POST /api/keymgmt/update` (https), `POST /api/keymgmt/search` (https), `DELETE /api/keymgmt/delete/<kid>` (https), `GET /api/crypto/random[/<n>]` (https, http), `GET /api/crypto/randomx` (https), `GET /api/system/reboot` (https), `GET /api/diag/memdump/<addr>/<len>` (https), `GET /api/diag/break_temp` (https); external: `POST api.encedo.com/checkin` (https)

## T-11 — Cryptography functionality

**File:** `test_11.php` · **Subtests:** 9 · **Preconditions:** device initialised, `fls_state` = 0, test keys from T-10 present (labels/descr starting `CCTEST:T-10.1_SHA`, `_SECP`, `_ED`, `_AES`, `_CURVE`, `_MLKEM`, `_MLDSA`), internet access to api.encedo.com (checkin), subtest 7 needs a DIAG build (device reboots there)

Runs every cryptographic operation of the HEM API over the keys that T-10 created: HMAC, ECDSA/EdDSA, AES encrypt/decrypt and wrap/unwrap, ECDH (including HKDF output and ECDH-derived secrets for HMAC/cipher/wrap), ML-KEM and ML-DSA. Each key is used with its own `keymgmt:use:<kid>` token. It also checks that a token issued for a different key is refused, and (DIAG only) that crypto operations are blocked once a failure state (FLS) has been simulated.

| # | Subtest | What is checked (options / cases) | Expected result |
|---|---|---|---|
| 11.1 | HMAC | Setup: status (initialised, fls_state 0), version, checkin. Pages through `keymgmt/search` for descr `^CCTEST:T-10.1_SHA`. Per key: `hmac/hash` on 250 random bytes, then `hmac/verify` of the returned mac. The first two KIDs are kept for 11.6/11.7 | 200 on every hash and verify, verify with `verified: true`; every key in the list was processed |
| 11.2 | ExDSA sign/verify | Keys matching `^CCTEST:T-10.1_SECP` + `^CCTEST:T-10.1_ED`; only keys with PKEY. ED25519: Ed25519, Ed25519ph (+ctx), Ed25519ctx (+ctx). ED448: Ed448 (+ctx), Ed448ph (+ctx). All other types (NIST/K1): SHA256/384/512WithECDSA. Message: 32 random bytes | 200 on every sign and verify, verify with `verified: true`; counter = number of keys listed |
| 11.3 | AES cipher | Keys `^CCTEST:T-10.1_AES`, alg `<type>-ECB` (64 B message), `<type>-CBC` (100 B, returned iv), `<type>-GCM` (100 B, 32 B aad, iv and tag) | 200 on encrypt and decrypt; the plaintext equals the original for every mode and key |
| 11.4 | AES wrap/unwrap | Same AES keys, `cipher/wrap` of 32 random bytes with `alg` = key type, then `cipher/unwrap` | 200 on both calls; unwrapped equals the original |
| 11.5 | ECDH (+HKDF, derived secrets, ED25519 dual mode) | Keys `^CCTEST:T-10.1_SECP` + `^CCTEST:T-10.1_CURVE` (PKEY only), using a fixed peer pubkey per curve (P-256/384/521, K1, X25519, X448). alg SHA2-256/384/512, SHA3-256/384/512 or raw, each with `pubkey` and with `ext_kid`=own kid. DEV-427 HKDF-SHA2-256/384/512 with hkdf_len 0/16/33/128 compared with local `hash_hkdf` over the raw secret; also without salt/ctx; limits hkdf_len 15/129, salt/ctx 129 B; salt/ctx 128 B. ECDH secret used as the key for hmac hash/verify, AES128-CBC encrypt/decrypt and AES128 wrap/unwrap (both via ext_kid and via pubkey+ctx). DEV-422: new ED25519 keys with mode "ECDH,ExDSA" and "ExDSA": Ed25519 signature checked locally (sodium); ECDH compared with local X25519 (Ed25519 pub converted to Curve25519) | 200 and matching values; 400 for every case over a limit; dual-mode key gives an ECDH result equal to the local one, ExDSA-only key must not return 200 for ECDH; counter = 7 × number of keys |
| 11.6 | Wrong-key token | `hmac/hash` on KID A using the token for KID B, then using the token for KID A | 403 with the wrong token, 200 with the right one |
| 11.7 | FLS on simulated failure (DIAG only) | Without DIAG: `SKIPPED (no DIAG)`. https status (fls_state 0), hmac/hash works, `GET /api/diag/break_temp`, wait 2 s, check status, repeat the hash, then reboot with a `system:config` token and wait 30 s | break_temp 200; fls_state ≠ 0 afterwards; hash ≠ 200 (409 expected); reboot 200 |
| 11.8 | ML-KEM | Status, checkin (result not checked), keys `^CCTEST:T-10.1_MLKEM`: `pqc/mlkem/encaps` → ss, ct, then `pqc/mlkem/decaps` with that ct | 200 on both; decaps ss = encaps ss for every key |
| 11.9 | ML-DSA | Keys `^CCTEST:T-10.1_MLDSA`: `pqc/mldsa/sign` of 250 random bytes, then `pqc/mldsa/verify` | 200 on both for every key, verify with `verified: true` |

**Endpoints:** `GET /api/system/status` (http; https in 11.7), `GET /api/system/version` (http), `GET /api/system/checkin` (http), `POST https://api.encedo.com/checkin`, `POST /api/system/checkin` (http), `GET /api/auth/token` + `POST /api/auth/token` (http, helper_authorize), `POST /api/keymgmt/search`, `POST /api/keymgmt/create`, `GET /api/keymgmt/get/{kid}`, `POST /api/crypto/hmac/hash`, `POST /api/crypto/hmac/verify`, `POST /api/crypto/exdsa/sign`, `POST /api/crypto/exdsa/verify`, `POST /api/crypto/cipher/encrypt`, `POST /api/crypto/cipher/decrypt`, `POST /api/crypto/cipher/wrap`, `POST /api/crypto/cipher/unwrap`, `POST /api/crypto/ecdh`, `POST /api/crypto/pqc/mlkem/encaps`, `POST /api/crypto/pqc/mlkem/decaps`, `POST /api/crypto/pqc/mldsa/sign`, `POST /api/crypto/pqc/mldsa/verify`, `GET /api/diag/break_temp` (DIAG), `GET /api/system/reboot` (all https unless stated otherwise)

## T-12 — Embedded storage management

**File:** `test_12.php` · **Subtests:** 2 · **Preconditions:** device initialised, `fls_state` = 0, PPA hardware only (fails on EPA), disk1 locked at the start, internet access to api.encedo.com (checkin); the tester can watch the USB drives ENCEDO / ENCEDO SAFE appear and disappear

Checks the lock/unlock of the two built-in USB storage disks with tokens scoped to each disk. The disk state is read from the `storage` array in `/api/system/status` (`<disk>:<mode>`, where `-` means locked).

| # | Subtest | What is checked (options / cases) | Expected result |
|---|---|---|---|
| 12.1 | Unlock disk0 + disk1 RW | Setup: status, https version, PPA check, checkin. Token `storage:disk0:rw`; disk1 must be locked; if disk0 is unlocked (e.g. RO by default) it is locked first and the test waits 5 s. `storage/unlock` with the disk0 token, then with a `storage:disk1:rw` token; status read again after 5 s | lock/unlock 200; both disks show `rw` |
| 12.2 | Lock both | `storage/lock` with the disk0 token, then with the disk1 token; status read again after 5 s | 200 on both; both disks show `-` (locked) |

**Endpoints:** `GET /api/system/status` (http first, then https), `GET /api/system/version` (https), `GET /api/system/checkin` (http), `POST https://api.encedo.com/checkin`, `POST /api/system/checkin` (http), `GET /api/auth/token` + `POST /api/auth/token` (http, helper_authorize), `GET /api/storage/lock` (https), `GET /api/storage/unlock` (https)

## T-13 — Attestation (POST /api/system/config/attestation): JWT, key block, proof of possession

**File:** `test_13.php` · **Subtests:** 5 · **Preconditions:** device initialised, FW with attestation (FW 1.3.0, DEV-423), internet access to api.encedo.com (checkin), local OpenSSL CLI ≥ 3.5 (`openssl`, or the path in `ENCEDO_OPENSSL`) for ML-DSA/ML-KEM, PHP openssl + sodium

Checks the attestation JWT. The test verifies locally: the ES256 signature with the jwk from the header, the header (typ `encedo-attest+jwt`, kid = SHA-1(04‖x‖y)) and the claims (aud, nonce, iat < exp, UUIDv4 jti, device hwv/fwv). It covers device attestation, the key block with and without metadata, request validation and access control. It also checks the three proof-of-possession methods (signature, ECDH-MAC, KEM-MAC) against locally computed values, and that pop_args which do not fit the key are refused.

| # | Subtest | What is checked (options / cases) | Expected result |
|---|---|---|---|
| 13.1 | Device attestation | Status (initialised), checkin, `keymgmt:list` token, nonce 32 B, aud `encedo-cctest-t13`; second request with a new nonce | 200; JWT passes all checks; no `key`/`pop` block; second JWT has a different jti and the same attestation key (kid) |
| 13.2 | Request validation, access | nonce 15/16/64/65 B, nonce not base64, no nonce, no aud, aud 64/65 chars, kid of 32 non-hex chars; request without a token | 400/200/200/400, 400, 400, 400, 200/400, 400; 401 without a token |
| 13.3 | Key block | Creates ED25519, SECP256R1 (ExDSA), MLDSA65, CURVE25519, SECP256R1 (ECDH), MLKEM768 with a `keymgmt:gen` token. ED25519 attested with `keymgmt:use:<kid>`, with and without `include_metadata`; then with the `keymgmt:list` token | 200; key.kid and key.pubkey.primary match; no pop; label/descr only with metadata and with the right values; 403 with the keymgmt:list token |
| 13.4 | Proof of possession | sig (`pop_args` {}): ED25519 (sodium), P-256 (openssl_verify), ML-DSA-65 (OpenSSL CLI) over the canonical `encedo-attest-pop:v1:sig` message. ECDH-MAC: CURVE25519 and P-256 ECDH with a local ephemeral key (`verifier_eph_pub`, `_alg`). KEM-MAC: local ML-KEM-768 encaps (CLI), `ciphertext`, `ciphertext_alg` | 200; signature verifies; mac = HMAC-SHA256(HKDF-SHA256(ss, salt=nonce, info), canonical msg) matches the local value |
| 13.5 | Strict PoP | pop_args without kid; {} for CURVE25519 / P-256 ECDH-only / MLKEM768; KEM args for CURVE25519; ECDH args for MLDSA65; wrong alg CURVE448 for an X25519 key; ML-KEM ciphertext of 1087 B | 400 for every case |

**Endpoints:** `GET /api/system/status` (http), `GET /api/system/checkin` (http), `POST https://api.encedo.com/checkin`, `POST /api/system/checkin` (http), `GET /api/auth/token` + `POST /api/auth/token` (http, helper_authorize), `POST /api/system/config/attestation` (https), `POST /api/keymgmt/create` (https), `GET /api/keymgmt/get/{kid}` (https)

## T-14 — Key derivation interoperability (local reproduction of /api/keymgmt/derive)

**File:** `test_14.php` · **Subtests:** 3 · **Preconditions:** device initialised, FW with derive (FW 1.3.0, DEV-428/429), internet access to api.encedo.com (checkin), PHP openssl + bcmath + sodium

Checks that `/api/keymgmt/derive` can be reproduced off the device. Z = ECDH(local peer, HEM main key), OKM = HKDF-SHA512(Z, salt, info `encedo-derive:v1:<type>`). For NIST types d = (OKM mod (n−1)) + 1 with OKM of L+8 bytes; for other types OKM is the key itself. The public keys of derived asymmetric keys must equal the locally computed ones. Derived symmetric keys must give the same HMAC/AES results as the local key.

| # | Subtest | What is checked (options / cases) | Expected result |
|---|---|---|---|
| 14.1 | NIST → NIST | Setup: status, version, PHP extensions, checkin, `keymgmt:gen` token. For each main key SECP256R1/384R1/521R1/256K1 (mode ECDH, created with return_pubkey) and a local peer on the same curve: derive every NIST type, without and with a 16 B hkdf_salt | 200 for each derive; pubkey equals the local compressed pubkey; 32 checks made |
| 14.2 | X25519 → all | CURVE25519 main key, local X25519 peer (sodium); targets CURVE25519 (scalarmult_base of OKM), ED25519 (OKM as seed) and the 4 NIST types, without and with salt | 200 for each derive; pubkey equals the local value |
| 14.3 | Symmetric | SECP256R1 main key, salt 16 B; derive SHA2-256/384/512, SHA3-256/384/512, AES128/192/256; each derived key used on the HEM: `hmac/hash` (64 B) or `cipher/encrypt` `<type>-ECB` | 200; HEM mac/ciphertext equals the local HMAC / AES-ECB result with the HKDF key |

**Endpoints:** `GET /api/system/status` (http), `GET /api/system/version` (http), `GET /api/system/checkin` (http), `POST https://api.encedo.com/checkin`, `POST /api/system/checkin` (http), `GET /api/auth/token` + `POST /api/auth/token` (http, helper_authorize), `POST /api/keymgmt/create` (https), `POST /api/keymgmt/derive` (https), `POST /api/crypto/hmac/hash` (https), `POST /api/crypto/cipher/encrypt` (https)

## T-15 — Input validation and robustness

**File:** `test_15.php` · **Subtests:** 12 · **Preconditions:** device initialised, FW with the DEV-438 fixes, internet access to api.encedo.com (checkin), TLS 1.3 to the device with a trusted certificate (raw requests)

Sends malformed input (DEV-438) and checks that each case gets the expected error code. After every subtest it checks that the device still answers and did not restart: `uptime` in `/api/system/status` must not go down (`check_alive`). It covers HTTP body framing, KID format, base64 padding, auth JWT claims, AES-CBC around the block size, an undecryptable TLS key in the config, and malformed ExtAuth sealed scopes and pid lengths.

| # | Subtest | What is checked (options / cases) | Expected result |
|---|---|---|---|
| 15.1 | HTTP body framing | Setup: status, https version, check_alive, checkin. Raw TLS `POST /api/auth/token`: body longer than Content-Length (2 + 200 extra bytes); no Content-Length | 400; 411; device alive |
| 15.2 | KID format | `keymgmt:upd` token; kid 30 hex, 31 hex, 33 hex, 32 non-hex in `keymgmt/update` and `crypto/hmac/hash` | 400 for all 8 cases; alive |
| 15.3 | base64 padding | `keymgmt:imp` token; import ED25519 pubkey with '=' inside, with 3 padding chars; valid pubkey as reference | 400, 400; 200 for the reference; alive |
| 15.4 | Auth JWT claims | Own token request (scope keymgmt:list): valid; jti cut to 4 B; jti 33 B; no jti; no iss | 200; 401 ×4; alive |
| 15.5 | AES-CBC block sizes | New AES256 key; AES256-CBC encrypt + decrypt of 1, 15, 16, 17, 31, 32 B | 200 on both calls and the plaintext matches for every length; alive |
| 15.6 | Bad TLS key in config | `system:config` token; `POST /api/system/config` with `tls` = random emp (91 B) + random key string (113 chars) | 200 without `reboot_required`; alive after 2 s |
| 15.7 | ExtAuth sealed scope / pid | Direct pairing (ext/init + validate, code verified), ext/request for system:config, unseal. ext/token cases: valid; 16 B single block without MAC; not whole blocks; padding byte 0; wrong MAC; pid = 16 B prefix of the paired pid. ext/validate with a 16 B pid | 200, 406 ×5; validate 400; alive |
| 15.8 | HTTP header case | `content-type: Application/JSON` + `CONTENT-LENGTH` on POST /api/auth/token with `{}`; `authorization: bearer <token>` on GET /api/system/config; `Connection: Keep-Alive, TE` then a second request on the same TLS connection | 400 (JSON, not an upload); 200; both 200; device alive |
| 15.9 | Token scope, upload, disk size (DEV-438 phase 2 group 1) | token requested without a scope on POST /api/auth/ext/init and GET /api/system/config; POST /api/system/upgrade/upload_fw with x.txt and with Content-Length 3 MiB; storage_disk0size read and written back, 0 and -5 | 403, 403; 400, 413; written back = no change; 400, 400; device alive |
| 15.10 | Derive input decoding (DEV-438 phase 2 group 2) | POST /api/keymgmt/derive with a valid request, a descr of 5 characters and a pubkey of 43 characters (pass the character check, do not decode) | 200; 400; 400 (was 406) |
| 15.11 | Decrypt IV/tag, remote auth delay (DEV-438 phase 2 group 3) | AES256-CBC decrypt without iv, AES256-GCM decrypt without tag; 5 POST /api/auth/ext/token with an invalid authreply, timed | 400, 400 (CBC used a zero IV before); 401 each, first >= 500 ms, 5th >= 1500 ms; 16 s pause for the counter |
| 15.12 | Verify result, status codes (DEV-438 phase 3) | New ED25519 and SHA2-256 keys; hmac/verify with a wrong MAC, exdsa/verify with a wrong signature; verify, cipher/encrypt, cipher/wrap, ecdh, mlkem/encaps with an unknown kid; cipher/encrypt and ecdh with the ExDSA-only ED25519 key; hmac/hash with alg `SHA2-256-X`; ecdh without pubkey/ext_kid; AES256-CBC decrypt of 20 B; keymgmt/search with mode 5; GET keymgmt/list/abc; storage/unlock/rw with a `storage:disk0` token; storage/unlock/xx; GET auth/init | 200 `{"verified":false}` ×2; 404 ×6; 400 ×7; 403; 404; 409; alive |
| 15.13 | Factory default (service wipe) | POST config `{"wipeout":"nonsense"}`; `{"wipeout":"factory"}` over http; wait for the reboot | 400; 200; TOE back not initialised and HTTPS not started (internal disk formatted - no /tmp/tls.json). **Runs last: the TOE has to be initialised again with T-2 (T-1 needs TLS)** |

**Endpoints:** `GET /api/system/status` (http), `GET /api/system/version` (https), `GET /api/system/checkin` (http), `POST https://api.encedo.com/checkin`, `POST /api/system/checkin` (http), `GET /api/auth/token` + `POST /api/auth/token` (http, helper_authorize and auth_with_claims), `POST /api/auth/token` (raw https), `POST /api/keymgmt/update`, `POST /api/crypto/hmac/hash`, `POST /api/keymgmt/import`, `POST /api/keymgmt/create`, `POST /api/crypto/cipher/encrypt`, `POST /api/crypto/cipher/decrypt`, `POST /api/system/config`, `POST /api/auth/ext/init`, `POST /api/auth/ext/validate`, `POST /api/auth/ext/request`, `POST /api/auth/ext/token` (all https unless stated otherwise)

## Tools

**ExtAuth_Simulator.php** simulates the Encedo authenticator mobile app, using the protocol functions in `libs/extauth.php`. **`serve`** (the default) lets T-5/T-6 run without a phone. It deletes `out/extauth_exchange.json`, then polls for it every 0.5 s. test_5 writes `{"type":"pair","qr":...}` in place of showing a QR code; the simulator fetches the QR link and checks the hash against the request. It then posts the pairing reply (with fid placeholder, MAC and aid) to the link through the backend and saves the pairing (pid, aid keys, eid) in `out/extauth_state.json`. test_6 writes `{"type":"event","eventid":...,"expect":"allow"|"deny"}`; the simulator reads the event from `api.encedo.com/notify/event/data/<eventid>/<pid>` (up to 10 tries) and unseals the scope. For `deny` it sends DELETE; otherwise it POSTs a sealed authreply with a MAC. **`direct`** checks the status (initialised), runs checkin and gets a `system:config` token. It then pairs with the HEM directly (`/api/auth/ext/init` + `/validate`), runs `/api/auth/ext/request` + `/api/auth/ext/token`, and uses the issued token on `GET /api/system/config`, with no backend. **`neg`** does the same as direct, then sends malformed sealed scopes to `/api/auth/ext/token` (one block, not whole blocks, padding byte 0, wrong MAC → 406 expected), then a valid one (200).

**wipeout.php** wipes the device (classic wipe: config and keys; `php wipeout.php factory`: service wipe to the factory default, the internal disk with the UI, TLS files and logs is formatted too - initialise with T-2 afterwards, T-1 needs TLS). It reads `/api/system/status`; if the device is initialised it runs checkin, gets a `system:config` token and sends `POST /api/system/config` with `{"wipeout": true}` or `{"wipeout": "factory"}` (over http) and prints "Done". If the device is not initialised it prints "Nothing to do".

**upgrade2diag.php** installs FW 1.2.2 on PPA: the official build (choice 1) or the DIAG build with the `/api/diag/...` endpoints (choice 2), both from ipfs.encedo.com. It requires fls_state 0, exits on EPA, runs checkin, and gets a `system:upgrade` token when the device is initialised (no token otherwise). It then calls `GET /api/system/upgrade/usbmode`. On Windows the HEX file must be sent with an external tool and the user presses Enter when done. On other systems it downloads the HEX, waits for `/dev/ttyACM0` and flashes it with `sudo ./libs/blbx`. Afterwards it polls status (up to about 10 tries) and prints the new `fwv` from `/api/system/version`.
