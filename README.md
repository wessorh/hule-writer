# hscan — Holloman YARA-X Signature Scanner

Reads a file from stdin, computes its holloman fingerprint via AVX2, and
emits a YARA-X rule with `hollomon.cluster_id` condition.

**Self-contained** — includes holloman5 AVX2 sources. No external libraries.

## Build

```bash
make          # build hscan
make test     # determinism + rule generation tests
make clean    # remove binary and object files
```

Requires: gcc, AVX2 CPU.

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
| `-short` | Output cluster ID only (`k.xxxx...`) |
| `-t FAMILY` | Threat family name |
| `-T DESC` | Threat description |
| `-ref URL` | Reference URL |
| `-tlp LEVEL` | TLP marking (RED/AMBER/GREEN/WHITE) |
| `-author NAME` | Rule author |
| `-help` | Show usage |
