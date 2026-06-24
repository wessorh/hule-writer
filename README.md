# hscan — Holloman YARA-X Signature Scanner

Reads a file from stdin, computes its holloman fingerprint via AVX2, and
emits a YARA-X rule with `hollomon.cluster_id` condition.

## Build

```bash
make          # build hscan
make test     # determinism + rule generation tests
make clean    # remove binary
make install  # install to /usr/local/bin
```

Requires: gcc, AVX2 CPU, libholloman_avx2.a from holloman5.

## Usage

```bash
# Basic: stdin → stdout
cat malware.exe | ./hscan

# Short mode: just the cluster ID
./hscan -short < sample.dll

# With threat intelligence metadata
./hscan -t trojan.redir -T "Browser redirect" -ref "https://intel.example.com/123" -tlp AMBER -author alice < evil.dll

# Write to file
./hscan -out rule.yar -name payload.exe < payload.bin

# Pipe from another tool
curl -s https://example.com/sample | ./hscan -t unknown
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

## Output

```yara
import "hollomon"

rule hscan_payloadexe_00006e40 {
    meta:
        description = "Browser redirect"
        scanner     = "hscan"
        file_size   = 28224
        fingerprint = "6d6669235f546057123a0e0800000000"
        cluster_id  = "k.6d6669235f546057123a0e0800000000"
        scanned_at  = "2026-06-24T19:32:49"
        filename    = "payload.exe"
        family      = "trojan.redir"
        reference   = "https://intel.example.com/123"
        tlp         = "AMBER"
        author      = "alice"
    condition:
        hollomon.cluster_id == "k.6d6669235f546057123a0e0800000000"
}
```

## How It Works

1. Reads entire input into memory (up to 1 GB)
2. Selects Hilbert order from file size: `ceil(log4(len))`, min 8
3. Computes 16-byte holloman fingerprint via AVX2-accelerated Hilbert
   curve mapping + 2D Lanczos-3 downsampling
4. Emits YARA-X rule using `hollomon` module
