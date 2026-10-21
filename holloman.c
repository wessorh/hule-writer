/* holloman.c — holloman3 fingerprint, portable C + libholloman3 SIMD kernels.
 *
 * Hilbert-curve mapping, Lanczos-3 kernel generation, and rotation are
 * implemented here; the two hot scaling passes (vscale/hscale) are delegated to
 * libholloman3. Output is byte-identical to the C/Go/Python implementations. */

#include <math.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

#include "holloman.h"
#include "holloman3.h" /* libholloman3 */

#define BITS 14
#define SCALE_FACTOR (1 << BITS)
#define ROUND_OFFSET (1 << (BITS - 1))
#define PI 3.141592653589793

/* --- Hilbert curve ------------------------------------------------------ */

static uint32_t calculate_order(size_t size) {
    if (size == 0)
        return 0;
    uint64_t n = (uint64_t)size - 1;
    uint32_t order = 0;
    while (n > 0) {
        n >>= 1;
        order++;
    }
    return (order + 1) >> 1;
}

static uint64_t hilbert_d2xy(uint32_t d, uint32_t order) {
    uint32_t x = 0, y = 0, s = 1;
    for (uint32_t i = 0; i < order; i++) {
        uint32_t rx = (d >> 1) & 1;
        uint32_t ry = (d ^ rx) & 1;
        if (ry == 0) {
            if (rx == 1) {
                x = s - 1 - x;
                y = s - 1 - y;
            }
            uint32_t t = x;
            x = y;
            y = t;
        }
        x += s * rx;
        y += s * ry;
        d >>= 2;
        s <<= 1;
    }
    return ((uint64_t)x << 32) | y;
}

static uint64_t *generate_curve(uint32_t order) {
    uint64_t n = 1ULL << (2 * order);
    uint64_t *c = malloc(n * sizeof(uint64_t));
    if (!c)
        return NULL;
    for (uint64_t i = 0; i < n; i++)
        c[i] = hilbert_d2xy((uint32_t)i, order);
    return c;
}

static uint32_t g_order = 0;
static uint64_t *g_curve = NULL;

static uint64_t *curve_for(uint32_t order) {
    if (g_curve && g_order == order)
        return g_curve;
    free(g_curve);
    g_curve = generate_curve(order);
    g_order = order;
    return g_curve;
}

/* --- Lanczos kernel generation ------------------------------------------ */

static double lanczos3(double x) {
    const double alpha = 3.0;
    if (x > alpha)
        return 0.0;
    if (x == 0.0)
        return 1.0;
    double b = x * PI;
    double c = b / alpha;
    return sin(b) * sin(c) / (b * c);
}

typedef struct {
    double weight;
    int offset;
} Weight;

static int weight_compare(const void *a, const void *b) {
    const Weight *wa = (const Weight *)a;
    const Weight *wb = (const Weight *)b;
    double aa = fabs(wa->weight);
    double ab = fabs(wb->weight);
    if (ab < aa)
        return -1;
    if (ab > aa)
        return 1;
    return 0;
}

static void make_double_kernel(int input_size, int output_size,
                               double *weights, double *sums,
                               int16_t *offsets, int *taps_out) {
    double scale = (double)output_size / (double)input_size;
    double step = (scale < 1.0) ? scale : 1.0;
    double support = 3.0 / step;
    int taps = (int)ceil(support) * 2;
    if (taps > input_size)
        taps = input_size & ~1;
    *taps_out = taps;

    double xstep = 1.0 / scale;
    double xmid = (double)(input_size - output_size) / (double)(output_size * 2);

    for (int i = 0; i < output_size; i++) {
        int left = (int)ceil(xmid) - taps / 2;
        int hi = input_size - taps;
        if (hi < 0)
            hi = 0;
        int x = left;
        if (x < 0)
            x = 0;
        else if (x > hi)
            x = hi;
        offsets[i] = (int16_t)x;

        double sum = 0.0;
        double *w = &weights[i * taps];
        for (int j = 0; j < taps; j++)
            w[j] = 0.0;
        for (int j = 0; j < taps; j++) {
            int src = left + j;
            double weight = lanczos3(fabs(xmid - (double)src) * step);
            int sc = src;
            if (sc < x)
                sc = x;
            else if (sc > input_size - 1)
                sc = input_size - 1;
            sc -= x;
            w[sc] += weight;
            sum += weight;
        }
        sums[i] = sum;
        xmid += xstep;
    }
}

static void make_integer_kernel(int taps, int size, const double *weights,
                                const double *sums, int32_t *coeffs) {
    Weight *sorted = malloc(taps * sizeof(Weight));
    if (!sorted)
        return;
    for (int i = 0; i < size; i++) {
        const double *w = &weights[i * taps];
        int32_t *c = &coeffs[i * taps];
        double sum = sums[i];
        for (int j = 0; j < taps; j++) {
            sorted[j].weight = w[j];
            sorted[j].offset = j;
        }
        qsort(sorted, taps, sizeof(Weight), weight_compare);
        double diff = 0.0;
        double scale = (double)SCALE_FACTOR / sum;
        for (int j = 0; j < taps; j++) {
            double wv = sorted[j].weight * scale + diff;
            double iw = floor(wv + 0.5);
            c[sorted[j].offset] = (int32_t)iw;
            diff = wv - iw;
        }
    }
    free(sorted);
}

/* --- kernel cache (per dimension) --------------------------------------- */

typedef struct {
    int32_t *v_coeffs;
    int32_t *h_coeffs;
    int dim;
} Kernel;

static Kernel g_kernel = {NULL, NULL, 0};

static Kernel *kernel_for(int dim) {
    if (g_kernel.v_coeffs && g_kernel.dim == dim)
        return &g_kernel;
    free(g_kernel.v_coeffs);
    free(g_kernel.h_coeffs);

    double *weights = malloc(4 * dim * sizeof(double));
    double *sums = malloc(4 * sizeof(double));
    int16_t *offsets = malloc(4 * sizeof(int16_t));
    int taps;

    make_double_kernel(dim, 4, weights, sums, offsets, &taps);
    g_kernel.v_coeffs = calloc(4 * dim, sizeof(int32_t));
    make_integer_kernel(taps, 4, weights, sums, g_kernel.v_coeffs);

    make_double_kernel(dim, 4, weights, sums, offsets, &taps);
    g_kernel.h_coeffs = calloc(4 * dim, sizeof(int32_t));
    make_integer_kernel(taps, 4, weights, sums, g_kernel.h_coeffs);

    g_kernel.dim = dim;
    free(weights);
    free(sums);
    free(offsets);
    return &g_kernel;
}

/* --- rotation ------------------------------------------------------------ */

static void rotate_matrix_90_clockwise(uint8_t output[16], const uint8_t input[16]) {
    static const int mapping[16] = {12, 8, 4, 0, 13, 9, 5, 1, 14, 10, 6, 2, 15, 11, 7, 3};
    for (int i = 0; i < 16; i++)
        output[i] = input[mapping[i]];
}

/* --- public API ---------------------------------------------------------- */

int holloman_init(uint32_t order) {
    return curve_for(order) ? 0 : -1;
}

int holloman_cleanup(void) {
    free(g_curve);
    g_curve = NULL;
    g_order = 0;
    free(g_kernel.v_coeffs);
    free(g_kernel.h_coeffs);
    g_kernel.v_coeffs = NULL;
    g_kernel.h_coeffs = NULL;
    g_kernel.dim = 0;
    return 0;
}

int holloman_is_avx2_available(void) {
    return holloman3_has_avx2();
}

const char *holloman_version(void) {
    return "0.2.0";
}

int holloman_fingerprint_buffer(const uint8_t *data, size_t size,
                                uint8_t fingerprint[16]) {
    if (!data || size == 0 || !fingerprint)
        return -1;

    uint32_t order = calculate_order(size);
    uint64_t *curve = curve_for(order);
    if (!curve)
        return -5;

    uint32_t dim = 1u << order;
    size_t grid_size = (size_t)dim * dim;
    uint8_t *mapped = calloc(grid_size, 1);
    if (!mapped)
        return -5;

    for (size_t i = 0; i < size; i++) {
        uint64_t p = curve[i];
        uint32_t x = (uint32_t)(p >> 32);
        uint32_t y = (uint32_t)(p & 0xFFFFFFFF);
        mapped[(size_t)y * dim + x] = data[i];
    }

    Kernel *k = kernel_for(dim);

    uint8_t *intermediate = malloc((size_t)dim * 4);
    if (!intermediate) {
        free(mapped);
        return -5;
    }
    holloman3_vscale(intermediate, mapped, k->v_coeffs, dim);

    uint8_t tmp[16];
    holloman3_hscale(tmp, intermediate, k->h_coeffs, dim);

    rotate_matrix_90_clockwise(fingerprint, tmp);

    free(intermediate);
    free(mapped);
    return 0;
}
