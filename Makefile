.PHONY: all clean test

CC       = gcc
CFLAGS   = -O3 -Wall -Wextra -std=c99
TARGET   = hscan
LIBS     = -lm

# libholloman3 (vendored as a git submodule) supplies the SIMD scaling kernels.
LIB_DIR  = third_party/libholloman3
INC      = -I$(LIB_DIR)/include
LIB      = $(LIB_DIR)/libholloman3.a

all: $(TARGET)

$(LIB):
	$(MAKE) -C $(LIB_DIR) libholloman3.a

$(TARGET): hscan.c holloman.c holloman.h $(LIB)
	$(CC) $(CFLAGS) $(INC) -o $@ hscan.c holloman.c $(LIB) $(LIBS)

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
	rm -f $(TARGET) hscan.o holloman.o
	$(MAKE) -C $(LIB_DIR) clean
