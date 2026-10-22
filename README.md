# php2shell-defend

A dependency-free scanner to check whether your own PHP servers are vulnerable to
**CVE-2026-109618** and **CVE-2026-109619** (the "php2shell" multipart memory bug),
so you can confirm you are patched before an attacker does.

This is a defensive, self-assessment fork of Assetnote's
[`php2shell-scanner`](https://github.com/assetnote/php2shell-scanner), reworked to:

- **run on a stock Python 3.9+** with no packages to install (no `h11`, no `tqdm`);
- **avoid false positives** on patched servers that have a low `memory_limit`; and
- **reduce the impact** a scan has on a vulnerable host.

> Only scan systems you own or are explicitly authorised to test.

## How it works

Unpatched PHP keeps every header line of each multipart part in memory — about
105 bytes of PHP memory per byte received. Patched PHP (8.2.35, 8.3.36, 8.4.27,
8.5.12 and later) discards all part headers except `Content-Disposition` and
`Content-Type`.

The scanner sends a small multipart **control** request, then one or more
**probes**: a single form field whose part-header block is padded with junk
header lines. On a vulnerable build a probe exhausts `memory_limit` while PHP
parses the request; a patched build uses a flat ~2 MiB regardless of probe size.

When a probe produces a PHP memory-exhaustion error, a differential empty
HTTP 500, or a PHP-FPM worker failure, the scanner sends a **baseline** request
of the same size carrying the padding as file content (which PHP streams to
disk). The host is reported `VULNERABLE` only if that baseline succeeds — if it
also fails, the failure was caused by request size (a proxy limit, an app error)
rather than the bug, and the result is `INCONCLUSIVE`. A host advertising an
unpatched PHP version in `X-Powered-By` without crashing is also reported
vulnerable.

Default probes are 1.5 MiB and 3 MiB, which detects a `memory_limit` up to about
315 MiB. Raise it with `--max-probe-mib` (e.g. `7.5` ≈ 790 MiB). The scanner
tests `/index.php` by default, preserves a path given in the URL, retests
phpMyAdmin at `/show_config_errors.php`, and does not follow redirects.

## Requirements

- Python 3.9+ (standard library only)

## Usage

```bash
# Single host
python3 scanner.py -u https://example.com

# A list of hosts, 20 at a time, saving vulnerable ones to JSON
python3 scanner.py -l hosts.txt -t 20 -o results.json

# Custom headers / path, higher memory_limit detection
python3 scanner.py -u https://example.com -H "Cookie: session=abc"
python3 scanner.py -u https://example.com --path /app.php
python3 scanner.py -u https://example.com --max-probe-mib 7.5
```

Exit codes: `0` nothing vulnerable, `1` at least one vulnerable host, `2` could
not write the output file.

### Options

```
-u, --url          Single URL/host to check
-l, --list         File containing hosts (one per line)
-t, --threads      Concurrent threads (default: 10)
--timeout          Request timeout in seconds (default: 60)
-o, --output       Output file for results (JSON)
--all-results      Save all results, not only vulnerable hosts
-k, --insecure     Disable TLS certificate verification
-H, --header       Custom header 'Key: Value' (repeatable)
-v, --verbose      Show verdict reasons and response snippets
-q, --quiet        Only print vulnerable hosts
--no-color         Disable colored output
--sapi             Verdict rules: auto, mod_php, or fpm (default: auto)
--max-probe-mib    Largest probe in MiB (default: 3)
--path             Custom path to test (repeatable)
--path-file        File of paths to test (one per line)
```

## Verdicts

- **VULNERABLE** — a probe crashed the handler and the same-size baseline
  succeeded, or an unpatched version is advertised.
- **FIXED** — the advertised `X-Powered-By` version includes the patch.
- **NO SIGNAL** — no crash and no version advertised. Note the probes only reach
  a `memory_limit` of about 105 × `--max-probe-mib`; a higher limit (or `-1`) is
  not detectable this way — verify the installed PHP version directly.
- **INCONCLUSIVE** — a proxy/WAF rejected the probe, or the baseline failed too.

## Impact on the target

Each tested path gets a 42-byte control request plus probes of 1.5 MiB and 3 MiB
(a vulnerable host also gets one same-size baseline). On a vulnerable host the
triggering probe fails with a PHP fatal error and, under PHP-FPM, the affected
worker is replaced automatically. In testing with official `php` Docker images
(8.3/8.4/8.5 mod_php, and 8.4 PHP-FPM behind nginx) the server kept serving
normal requests throughout and returned to baseline memory afterwards; each
result records `service_recovered`. PHP's memory use is bounded by `memory_limit`
— keep `--max-probe-mib` low for hosts that may run without one.

## Limitations

- A `memory_limit` above ~105 × `--max-probe-mib` (including `-1`) is not
  detected and yields `NO SIGNAL`.
- Probes of 8 MiB or more exceed PHP's default `post_max_size` and are ignored
  unless that setting was raised.
- Version verdicts read `X-Powered-By`; distro packages that backport the fix
  without bumping the version string can read as vulnerable — check the package.

## Credits

Original php2shell discovery by the Calif team —
[calif.io/php2shell](https://calif.io/php2shell/). The upstream scanner was built
by the Assetnote Security Research Team —
[github.com/assetnote/php2shell-scanner](https://github.com/assetnote/php2shell-scanner).
This defensive fork is maintained by Vidoc Security.
