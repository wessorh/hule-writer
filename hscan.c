/*
 * hscan — Holloman YARA-X signature scanner
 *
 * Reads a file from stdin, computes its holloman fingerprint via AVX2,
 * and emits a YARA-X rule with hollomon.cluster_id condition.
 *
 * Build:
 *   gcc -O3 -mavx2 -o hscan hscan.c \
 *       -I/home/wessorh/work/ai/holloman5/src/common \
 *       -I/home/wessorh/work/ai/holloman5/src/avx2/hilbert-avx2/include \
 *       /home/wessorh/work/ai/holloman5/lib/libholloman_avx2.a -lm
 *
 * Usage:
 *   ./hscan < file.bin                    # print rule to stdout
 *   ./hscan -out rule.yar < file.bin      # write rule to file
 *   cat malware.exe | ./hscan             # pipe from another tool
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/stat.h>
#include "holloman.h"

#define FP_HEX_LEN 32
#define MAX_INPUT   (1 << 30)  /* 1 GB cap */

/* ─── Read entire stdin into a buffer ────────────────────────────────── */
static uint8_t *slurp(size_t *out_len) {
    size_t cap = 65536;
    uint8_t *buf = malloc(cap);
    if (!buf) return NULL;

    size_t len = 0;
    while (!feof(stdin) && !ferror(stdin)) {
        if (len + 4096 > cap) {
            if (cap >= MAX_INPUT) break;
            size_t new_cap = cap * 2;
            if (new_cap > MAX_INPUT) new_cap = MAX_INPUT;
            uint8_t *nb = realloc(buf, new_cap);
            if (!nb) { free(buf); return NULL; }
            buf = nb;
            cap = new_cap;
        }
        size_t nr = fread(buf + len, 1, cap - len, stdin);
        if (nr == 0) break;
        len += nr;
    }
    *out_len = len;
    return buf;
}

/* ─── Print YARA-X rule ──────────────────────────────────────────────── */
static void print_rule(FILE *out, const uint8_t fp[16], size_t file_len,
                        const char *filename) {
    /* Convert fingerprint to hex */
    char fp_hex[FP_HEX_LEN + 1];
    for (int i = 0; i < 16; i++)
        sprintf(fp_hex + i * 2, "%02x", fp[i]);
    fp_hex[FP_HEX_LEN] = '\0';

    /* Build cluster_id = "k." + fingerprint */
    char cluster_id[64];
    snprintf(cluster_id, sizeof(cluster_id), "k.%s", fp_hex);

    /* Sanitize filename for rule name */
    char rule_name[256];
    const char *bn = filename ? strrchr(filename, '/') : NULL;
    bn = bn ? bn + 1 : (filename ? filename : "stdin");
    /* Remove non-alphanumeric chars */
    int ri = 0;
    for (const char *p = bn; *p && ri < 250; p++) {
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
            (*p >= '0' && *p <= '9') || *p == '_')
            rule_name[ri++] = *p;
    }
    if (ri == 0) { strcpy(rule_name, "unknown"); ri = 7; }
    rule_name[ri] = '\0';

    time_t now = time(NULL);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", gmtime(&now));

    fprintf(out,
        "import \"hollomon\"\n\n"
        "rule hscan_%s_%08lx {\n"
        "    meta:\n"
        "        description = \"Holloman fingerprint YARA-X rule\"\n"
        "        scanner     = \"hscan\"\n"
        "        file_size   = %lu\n"
        "        fingerprint = \"%s\"\n"
        "        cluster_id  = \"%s\"\n"
        "        scanned_at  = \"%s\"\n"
        "        filename    = \"%s\"\n"
        "    condition:\n"
        "        hollomon.cluster_id == \"%s\"\n"
        "}\n",
        rule_name,
        (unsigned long)(file_len ^ (file_len >> 32)),
        file_len,
        fp_hex,
        cluster_id,
        ts,
        bn,
        cluster_id
    );
}

/* ─── Print short cluster ID only (for piping) ──────────────────────── */
static void print_short(FILE *out, const uint8_t fp[16]) {
    fprintf(out, "k.");
    for (int i = 0; i < 16; i++) fprintf(out, "%02x", fp[i]);
    fprintf(out, "\n");
}

/* ─── Main ───────────────────────────────────────────────────────────── */
int main(int argc, char **argv) {
    const char *outpath = NULL;
    const char *filename = NULL;
    int short_mode = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-out") == 0 && i + 1 < argc) {
            outpath = argv[++i];
        } else if (strcmp(argv[i], "-short") == 0) {
            short_mode = 1;
        } else if (strcmp(argv[i], "-name") == 0 && i + 1 < argc) {
            filename = argv[++i];
        } else if (argv[i][0] != '-') {
            filename = argv[i];
        }
    }

    /* Check AVX2 */
    if (!holloman_is_avx2_available()) {
        fprintf(stderr, "hscan: AVX2 not available on this CPU\n");
        return 2;
    }

    /* Read input first (need size to choose Hilbert order) */
    size_t file_len = 0;
    uint8_t *data = slurp(&file_len);
    if (!data) {
        fprintf(stderr, "hscan: failed to read input\n");
        return 1;
    }

    /* Choose Hilbert order: need 4^order >= file_len, minimum 8 */
    uint32_t order = 12;  /* default for stdin (16M cells) */
    if (file_len > 0) {
        /* 4^order >= file_len  →  order >= log4(file_len) = log2(file_len)/2 */
        order = 8;  /* minimum */
        while (((size_t)1 << (2 * order)) < file_len && order < 20)
            order++;
    }
    fprintf(stderr, "hscan: file_len=%lu, order=%u (grid=%lu cells)\n",
            file_len, order, (size_t)1 << (2 * order));

    /* Initialize holloman5 */
    int ret = holloman_init(order);
    if (ret != 0) {
        fprintf(stderr, "hscan: holloman_init failed (%d)\n", ret);
        free(data);
        return 3;
    }

    /* Compute fingerprint */
    uint8_t fp[16];
    ret = holloman_fingerprint_buffer(data, file_len, fp);
    if (ret != 0) {
        fprintf(stderr, "hscan: fingerprint failed (%d)\n", ret);
        free(data);
        holloman_cleanup();
        return 4;
    }
    free(data);

    /* Output */
    FILE *out = stdout;
    if (outpath) {
        out = fopen(outpath, "w");
        if (!out) {
            fprintf(stderr, "hscan: cannot open %s\n", outpath);
            holloman_cleanup();
            return 5;
        }
    }

    if (short_mode) {
        print_short(out, fp);
    } else {
        print_rule(out, fp, file_len, filename);
    }

    if (outpath) fclose(out);
    holloman_cleanup();
    return 0;
}
