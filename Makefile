.PHONY: all clean test install

CC       = gcc
CFLAGS   = -O3 -mavx2 -Wall -Wextra
TARGET   = hscan
SRCS     = hscan.c

HOLLOMAN_DIR = /home/wessorh/work/ai/holloman5
HOLLOMAN_INC = -I$(HOLLOMAN_DIR)/src/common \
               -I$(HOLLOMAN_DIR)/src/avx2/hilbert-avx2/include
HOLLOMAN_LIB = $(HOLLOMAN_DIR)/lib/libholloman_avx2.a
HOLLOMAN_LIBS = $(HOLLOMAN_LIB) -lm

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(HOLLOMAN_INC) -o $@ $< $(HOLLOMAN_LIBS)

test: $(TARGET)
	@echo "=== Determinism test ==="
	@./$(TARGET) -short < /bin/ls > /tmp/hscan1.txt
	@./$(TARGET) -short < /bin/ls > /tmp/hscan2.txt
	@diff /tmp/hscan1.txt /tmp/hscan2.txt && echo "PASS: deterministic" || echo "FAIL"
	@rm -f /tmp/hscan1.txt /tmp/hscan2.txt
	@echo ""
	@echo "=== Rule generation test ==="
	@echo "test" | ./$(TARGET) -t test -T "test rule"
	@echo ""
	@echo "=== -help test ==="
	@./$(TARGET) -help

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/
