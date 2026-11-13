# Test suite for getpid / getpid_raw.
#
#   make -C tests            build everything, then run unit + CLI tests
#   make -C tests unit       unit tests only (fixture files, no live /proc)
#   make -C tests cli        end-to-end tests against the live /proc
#   make -C tests clean
#
# To test another source tree (for example a patched copy):
#
#   make -C tests SRC=/path/to/tree BUILD=build-patched

SRC    ?= ..
BUILD  ?= build
PYTHON ?= python3
# The README builds getpid_raw with musl-gcc; plain gcc takes the same flags.
RAW_CC ?= $(CC)

SRC_ABS   := $(abspath $(SRC))
BUILD_ABS := $(abspath $(BUILD))

LIBC_CFLAGS := -O2 -Wall -Wextra -pedantic -std=gnu11
RAW_CFLAGS  := -O2 -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
               -nostdlib -nostartfiles -static -ffreestanding

BINS := $(BUILD)/getpid $(BUILD)/getpid_raw $(BUILD)/helper \
        $(BUILD)/unit_libc $(BUILD)/unit_raw

.PHONY: test all unit cli clean

# Run both suites even if the first one fails; fail if either did.
# (Kept on one line on purpose: a multi-line recipe becomes an `sh -c` whose
# command line contains newlines, and that process is visible to the tests.)
test: all
	@$(MAKE) --no-print-directory unit; u=$$?; $(MAKE) --no-print-directory cli; c=$$?; [ $$u -eq 0 ] && [ $$c -eq 0 ]

all: $(BINS)

$(BUILD):
	mkdir -p $@

$(BUILD)/getpid: $(SRC)/getpid.c | $(BUILD)
	$(CC) $(LIBC_CFLAGS) -o $@ $<

$(BUILD)/getpid_raw: $(SRC)/getpid_raw.c | $(BUILD)
	$(RAW_CC) $(RAW_CFLAGS) -o $@ $< -lgcc

$(BUILD)/helper: helper.c | $(BUILD)
	$(CC) -O1 -Wall -Wextra -pthread -o $@ $<

# The unit tests #include the program source, so they rebuild when it changes.
$(BUILD)/unit_libc: unit_libc.c $(SRC)/getpid.c | $(BUILD)
	$(CC) -O1 -Wall -Wextra -std=gnu11 \
	      -DGETPID_SRC='"$(SRC_ABS)/getpid.c"' -o $@ unit_libc.c

$(BUILD)/unit_raw: unit_raw.c $(SRC)/getpid_raw.c | $(BUILD)
	$(RAW_CC) $(RAW_CFLAGS) -Wall -Wextra \
	      -DGETPID_RAW_SRC='"$(SRC_ABS)/getpid_raw.c"' -o $@ unit_raw.c -lgcc

unit: all
	@rm -rf $(BUILD)/fx-libc $(BUILD)/fx-raw
	@mkdir -p $(BUILD)/fx-libc $(BUILD)/fx-raw
	@$(BUILD)/unit_libc $(BUILD)/fx-libc; a=$$?; $(BUILD)/unit_raw $(BUILD)/fx-raw; b=$$?; [ $$a -eq 0 ] && [ $$b -eq 0 ]

cli: all
	@GETPID_BUILD=$(BUILD_ABS) $(PYTHON) test_cli.py

clean:
	rm -rf $(BUILD)
