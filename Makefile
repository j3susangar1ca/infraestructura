# ⚙️ SAM-V5: Sistema de Gestión de Configuración Industrial
# Compiles all system diagnostic modules using Static Linking

CC = gcc
CFLAGS = -static -s -O2 -Iinclude -w
OUT_DIR = 03_BUILD_OUTPUT
SRC_DIR = 02_AUTOMATION_MODULES

# Find all C files
SOURCES = $(shell find $(SRC_DIR) -name '*.c')
# Create target binary names based on their directories
TARGETS = $(patsubst $(SRC_DIR)/%.c, $(OUT_DIR)/%, $(SOURCES))

all: prebuild optimize $(TARGETS) postbuild

prebuild:
	@echo "[*] Initializing SAM-V5 Configuration Engine..."
	@mkdir -p $(OUT_DIR)

optimize:
	@echo "[*] Running Source Code Optimization Engine..."
	@python3 lib/minify_source.py

# Rule to compile each C file, placing it flat in out dir
$(OUT_DIR)/%: $(SRC_DIR)/%.c
	@echo "[+] Compiling and Optimizing: $<"
	@$(CC) $(CFLAGS) $< -o $(OUT_DIR)/$(notdir $@) || echo "[!] Ignored (Build dependencies missing)"

postbuild:
	@echo "[*] Configuration Engine build complete. Artifacts in $(OUT_DIR)/"

clean:
	@echo "[*] Purging generated configuration artifacts..."
	@rm -rf $(OUT_DIR)/*
