# 🛡️ C4ISR-STRATCOM: SIGINT-V5 MAKEFILE
# Compiles all C implants using Static Linking and Stripping

CC = gcc
CFLAGS = -static -s -O2 -Iinclude -w
OUT_DIR = 03_BUILD_OUTPUT
SRC_DIR = 02_ATTACK_MATRIX

# Find all C files
SOURCES = $(shell find $(SRC_DIR) -name '*.c')
# Create target binary names based on their directories
TARGETS = $(patsubst $(SRC_DIR)/%.c, $(OUT_DIR)/%, $(SOURCES))

all: prebuild obfuscate $(TARGETS) postbuild

prebuild:
	@echo "[*] Initializing STRATCOM Build System..."
	@mkdir -p $(OUT_DIR)

obfuscate:
	@echo "[*] Running YARA Evasion Script..."
	@python3 lib/obfuscate_yara.py

# Rule to compile each C file, placing it flat in out dir
$(OUT_DIR)/%: $(SRC_DIR)/%.c
	@echo "[+] Compiling and Hardening: $<"
	@$(CC) $(CFLAGS) $< -o $(OUT_DIR)/$(notdir $@)

postbuild:
	@echo "[*] Build Complete. Artifacts in $(OUT_DIR)/"

clean:
	@echo "[*] Cleaning up build artifacts..."
	@rm -rf $(OUT_DIR)/*
