# hscan — Holloman YARA-X Signature Scanner

Reads a file from stdin (or a path argument), computes its holloman fingerprint,
and emits a YARA-X rule with a `holloman.clusterid` condition.

The Hilbert-curve mapping, Lanczos-3 kernel generation, and rotation are
portable C (`holloman.c`); the two SIMD scaling passes are delegated to
[libholloman3](https://github.com/wessorh/libholloman3), vendored as a git
submodule.

## Build

```bash
git submodule update --init --recursive
make          # build hscan (and libholloman3 via its Makefile)
make test     # determinism + rule generation tests
make clean    # remove binary and object files
```

Requires: gcc, `make`, and the libholloman3 submodule (AVX2/SSE4.1 on x86-64,
NEON on aarch64, with a scalar fallback).

## Usage

```bash
cat malware.exe | ./hscan
./hscan -short < sample.dll
./hscan -t trojan.redir -T "Browser redirect" -ref "https://..." -tlp AMBER < evil.dll
./hscan -out rule.yar -name payload.exe < payload.bin
```

## Flags

| Flag | Description |
|------|-------------|
| `-out FILE` | Write rule to file instead of stdout |
| `-name NAME` | Set filename metadata |
| `-short` | Output cluster ID only (`<order>.<32hex>`) |
| `-t FAMILY` | Threat family name |
| `-T DESC` | Threat description |
| `-ref URL` | Reference URL |
| `-tlp LEVEL` | TLP marking (RED/AMBER/GREEN/WHITE) |
| `-author NAME` | Rule author |
| `-help` | Show usage |
