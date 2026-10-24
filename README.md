hem-api-tester
=======

A set of scripts, one per functionality, to test Encedo HEM API. The tests are a part of the Common Criteria certification procedure.


Using
=====

1. Download the Ubuntu 22.04 (recommended) ISO image, flash the USB stick and boot the PC from the stick. Link: https://ubuntu.com/download/desktop 

2. Select 'Try Ubuntu" to start a fresh Ubuntu instance and get a desktop.

3. Get connected to the Internet (set WiFi or wired connection).

3. Upgrade the system and install the required packages. Open `terminal` and type:

   `sudo apt update`
   
   `sudo apt upgrade`
   
   `sudo apt install git php-cli`

4. Clone this repository.

   `git clone https://github.com/encedo/hem-api-tester.git`
   
   `cd hem-api-tester`

5. Run first test - e.g. to test Encedo PPA.

   `php test_1.php`

Cheers :)



P.S. Edit config.php with `$cfg_authkey` and `$cfg_epa_domain`.


External authenticator simulator
================================

T-5 (pairing) and T-6 (remote authorization) need the Encedo authenticator mobile app. `ExtAuth_Simulator.php` plays the app, so both tests can run without a phone. It follows the app protocol (encedo-authenticator `docs/PROTOCOL.md`): X25519 keys, HS256 JWT with the `ecdh: x25519` header, and the sealed scope `"A" + base64(AES-128-CBC || HMAC-SHA256)`.

Run it in a second terminal, then the test in the first one:

   `php ExtAuth_Simulator.php`          (terminal 2 - waits, Ctrl+C to stop)

   `php test_5.php`, then `php test_6.php`   (terminal 1)

How it talks to the tests:

* test_5 writes the QR code data to `out/extauth_exchange.json` (in addition to showing the QR code). The simulator reads it, gets the pairing request from the `link`, checks the `hash`, sends the reply through api.encedo.com and saves the pairing to `out/extauth_state.json`.
* test_6 writes the event id and the expected answer (`allow` in subtest 1, `deny` in subtest 2) to `out/extauth_exchange.json`. The simulator gets the event from api.encedo.com, decrypts and verifies the scope, and allows or denies it.
* Both files are in `out/`, which is not in the repository (`.gitignore`). `extauth_state.json` holds the private key of the simulated app.

T-5 pairs a new simulated app on every run; T-6 uses the last pairing. If a real phone is paired too, it gets the same notifications - close the app or leave it alone.

Other modes (without api.encedo.com, against the HEM only; the HEM must be initialised):

   `php ExtAuth_Simulator.php direct`   pairing and one access token

   `php ExtAuth_Simulator.php neg`      as `direct`, plus malformed sealed scopes on `/api/auth/ext/token` (each must give 406 and the HEM must keep working)

The protocol functions are in `libs/extauth.php`; test_15 uses them too.


Input validation test (T-15)
============================

`php test_15.php` sends malformed input (body longer than Content-Length, KIDs of a wrong length, misplaced base64 padding, auth JWTs with missing or shortened claims, short AES-CBC messages, a TLS key that cannot be decrypted, malformed ExtAuth replies) and checks the error code from the API docs (400/401/406/411) and that the device is still running without a restart after every subtest. It needs an initialised device (run test_2 first), no DIAG endpoints and no user interaction.

