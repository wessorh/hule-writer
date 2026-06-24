.PHONY: all clean test

CC       = gcc
CFLAGS   = -O3 -mavx2 -Wall -Wextra
TARGET   = hscan

# Local holloman5 sources (no external library needed)
INC      = -Iholloman5/include -Iholloman5/src -Iholloman5
SRCS     = hscan.c \
           holloman5/src/holloman_avx2.c \
           holloman5/src/lanczos_avx2_optimized.c \
           holloman5/src/hilbert.c \
           holloman5/src/hilbert_mapping.c \
           holloman5/src/hilbert_utils.c \
           holloman5/src/arch_detect.c \
           holloman5/src/hilbert_external_buffer.c

# Assembly sources for AVX2 acceleration
ASM      = holloman5/src/hilbert_avx2.s \
           holloman5/src/hilbert_mapping_avx2.s \
           holloman5/src/hilbert_mapping_avx2_cache_blocking.s \
           holloman5/src/hilbert_utils_avx2.s

OBJS     = $(SRCS:.c=.o)
ASM_OBJS = $(ASM:.s=.o)

LIBS     = -lm

all: $(TARGET)

$(TARGET): $(OBJS) $(ASM_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

%.o: %.s
	$(CC) $(CFLAGS) -c -o $@ $<

test: $(TARGET)
	@echo "=== Determinism test ==="
	@./$(TARGET) -short < /bin/ls > /tmp/hscan1.txt
	@./$(TARGET) -short < /bin/ls > /tmp/hscan2.txt
	@diff /tmp/hscan1.txt /tmp/hscan2.txt && echo "PASS" || echo "FAIL"
	@rm -f /tmp/hscan1.txt /tmp/hscan2.txt
	@echo ""
	@echo "=== Rule generation ==="
	@echo "test" | ./$(TARGET) -t test -T "test rule"
	@echo ""
	@./$(TARGET) -help 2>&1 | head -3

clean:
	rm -f $(TARGET) hscan.o $(OBJS) $(ASM_OBJS)
	find holloman5 -name "*.o" -delete
