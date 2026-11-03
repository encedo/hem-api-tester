<?php
// DEV-500: offline verifier of an HEM audit log file (format v1 and v2)
//   php tools/hem_log_verify.php <device log public key, base64 or base64url> <file.log>
// The key is "key" from GET /api/logger/key. Exit code 0 = verified, 1 = not verified / gaps, 2 = usage.
if ($argc != 3) { fwrite(STDERR, "usage: php hem_log_verify.php <pub_dev base64> <file.log>\n"); exit(2); }
chdir(__DIR__ . "/..");
include "libs/lib.php";
$pub = base64_decode(strtr($argv[1], '-_', '+/'));
if (strlen($pub) != 32) { fwrite(STDERR, "the public key is not 32 B\n"); exit(2); }
if (!is_readable($argv[2])) { fwrite(STDERR, "cannot read " . $argv[2] . "\n"); exit(2); }
$lines = preg_split("/\r?\n/", file_get_contents($argv[2]));
$report = array();
$ok = encedo_log_verify($pub, $lines, $report);
printf("%s: format v%d, %d lines, %d header(s), %d rotation(s), %d events lost\n", $argv[2], $report['version'], $report['lines'], $report['headers'], $report['rotations'], $report['lost']);
foreach ($report['gaps'] as $g) echo "  seq gap $g (deleted line)\n";
foreach ($report['errors'] as $e) echo "  $e\n";
if ($report['version'] == 1) echo "  v1: HMAC with the key from the file - consistency only, no protection against a holder of the file\n";
echo ($ok && !count($report['gaps'])) ? "VERIFIED\n" : "NOT VERIFIED\n";
exit(($ok && !count($report['gaps'])) ? 0 : 1);
