#!/usr/bin/env python3
#
# 🛡️ C4ISR-STRATCOM: SIGINT-V5
# [CLASSIFIED]: CONFIDENCIAL
# [SCOPE]: OPD HCG (CONV-0221-JAL-HCG-2026)
# [TACTIC]: TA0007_Discovery
# [TECHNIQUE]: T1016_System_Network_Config_Discovery
#
# ============================================================================
# SIGV5 — Network Topology Mapper & Service Fingerprinter
# ============================================================================
# Módulo asyncio de descubrimiento topológico de red.
# Realiza enumeración pasiva y activa de:
#   - Interfaces de red locales, tablas ARP, rutas, DNS resolvers
#   - ICMP sweep de subredes adyacentes
#   - Banner grabbing asíncrono en puertos de interés
#   - OS fingerprinting heurístico vía TTL/Window Size
#   - Generación de informe JSON estructurado
#
# Uso:
#   python3 sigv5_t1016_net_topology_mapper.py --cidr 10.2.1.0/24
#   python3 sigv5_t1016_net_topology_mapper.py --cidr 10.2.1.0/24 --ports 22,80,443,445,3389
#   python3 sigv5_t1016_net_topology_mapper.py --passive-only
# ============================================================================

import argparse
import asyncio
import ipaddress
import json
import os
import platform
import re
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple

# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class InterfaceInfo:
    name: str
    mac: str
    ipv4: List[str] = field(default_factory=list)
    ipv6: List[str] = field(default_factory=list)
    mtu: int = 0
    state: str = "unknown"
    flags: List[str] = field(default_factory=list)

@dataclass
class ARPEntry:
    ip: str
    mac: str
    interface: str
    hw_type: str = "ether"
    state: str = ""

@dataclass
class RouteEntry:
    destination: str
    gateway: str
    interface: str
    metric: int = 0
    flags: str = ""

@dataclass
class DNSResolver:
    nameserver: str
    domain: str = ""
    search: List[str] = field(default_factory=list)

@dataclass
class ServiceBanner:
    ip: str
    port: int
    protocol: str = "tcp"
    banner: str = ""
    service_guess: str = ""
    tls: bool = False
    response_time_ms: float = 0.0

@dataclass
class HostProfile:
    ip: str
    mac: str = ""
    hostname: str = ""
    os_guess: str = ""
    ttl: int = 0
    alive: bool = False
    open_ports: List[int] = field(default_factory=list)
    services: List[ServiceBanner] = field(default_factory=list)
    discovery_method: str = ""

@dataclass
class TopologyReport:
    timestamp: str = ""
    hostname: str = ""
    platform_info: str = ""
    interfaces: List[InterfaceInfo] = field(default_factory=list)
    arp_table: List[ARPEntry] = field(default_factory=list)
    routes: List[RouteEntry] = field(default_factory=list)
    dns_resolvers: List[DNSResolver] = field(default_factory=list)
    discovered_hosts: List[HostProfile] = field(default_factory=list)
    scan_stats: Dict = field(default_factory=dict)


# ============================================================================
# PASSIVE ENUMERATION — Local System Intelligence
# ============================================================================

class PassiveEnumerator:
    """Recolección pasiva de configuración de red del host local."""

    @staticmethod
    def enumerate_interfaces() -> List[InterfaceInfo]:
        """Enumera interfaces de red vía /sys/class/net y ip addr."""
        interfaces = []
        try:
            result = subprocess.run(
                ["ip", "-j", "addr", "show"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                for iface in data:
                    info = InterfaceInfo(
                        name=iface.get("ifname", ""),
                        mac=iface.get("address", "00:00:00:00:00:00"),
                        mtu=iface.get("mtu", 0),
                        state=iface.get("operstate", "unknown"),
                        flags=iface.get("flags", [])
                    )
                    for addr_info in iface.get("addr_info", []):
                        family = addr_info.get("family", "")
                        local = addr_info.get("local", "")
                        prefix = addr_info.get("prefixlen", "")
                        addr_str = f"{local}/{prefix}" if prefix else local
                        if family == "inet":
                            info.ipv4.append(addr_str)
                        elif family == "inet6":
                            info.ipv6.append(addr_str)
                    interfaces.append(info)
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            # Fallback: parse /sys/class/net
            net_path = "/sys/class/net"
            if os.path.isdir(net_path):
                for ifname in os.listdir(net_path):
                    info = InterfaceInfo(name=ifname, mac="")
                    mac_path = os.path.join(net_path, ifname, "address")
                    mtu_path = os.path.join(net_path, ifname, "mtu")
                    state_path = os.path.join(net_path, ifname, "operstate")
                    try:
                        with open(mac_path) as f:
                            info.mac = f.read().strip()
                        with open(mtu_path) as f:
                            info.mtu = int(f.read().strip())
                        with open(state_path) as f:
                            info.state = f.read().strip()
                    except (IOError, ValueError):
                        pass
                    interfaces.append(info)
        return interfaces

    @staticmethod
    def enumerate_arp_table() -> List[ARPEntry]:
        """Lee la tabla ARP del kernel vía /proc/net/arp."""
        entries = []
        try:
            with open("/proc/net/arp", "r") as f:
                lines = f.readlines()[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 6:
                        ip_addr = parts[0]
                        hw_type = parts[1]
                        mac_addr = parts[3]
                        iface = parts[5]
                        # Filtrar entradas incompletas (00:00:00:00:00:00)
                        if mac_addr != "00:00:00:00:00:00":
                            entries.append(ARPEntry(
                                ip=ip_addr,
                                mac=mac_addr,
                                interface=iface,
                                hw_type=hw_type
                            ))
        except IOError:
            pass

        # Complementar con ip neigh
        try:
            result = subprocess.run(
                ["ip", "-j", "neigh", "show"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                existing_ips = {e.ip for e in entries}
                data = json.loads(result.stdout)
                for neigh in data:
                    dst = neigh.get("dst", "")
                    if dst and dst not in existing_ips:
                        entries.append(ARPEntry(
                            ip=dst,
                            mac=neigh.get("lladdr", ""),
                            interface=neigh.get("dev", ""),
                            state=neigh.get("state", [""])[0] if isinstance(neigh.get("state"), list) else ""
                        ))
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass
        return entries

    @staticmethod
    def enumerate_routes() -> List[RouteEntry]:
        """Enumera tabla de enrutamiento vía /proc/net/route + ip route."""
        routes = []
        try:
            result = subprocess.run(
                ["ip", "-j", "route", "show"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                for rt in data:
                    routes.append(RouteEntry(
                        destination=rt.get("dst", "default"),
                        gateway=rt.get("gateway", ""),
                        interface=rt.get("dev", ""),
                        metric=rt.get("metric", 0),
                        flags=rt.get("flags", "")
                    ))
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            # Fallback: parse /proc/net/route
            try:
                with open("/proc/net/route", "r") as f:
                    for line in f.readlines()[1:]:
                        parts = line.strip().split("\t")
                        if len(parts) >= 8:
                            iface = parts[0]
                            dst_hex = parts[1]
                            gw_hex = parts[2]
                            metric = int(parts[6]) if parts[6].isdigit() else 0

                            def hex_to_ip(h):
                                addr = int(h, 16)
                                return socket.inet_ntoa(struct.pack("<I", addr))

                            routes.append(RouteEntry(
                                destination=hex_to_ip(dst_hex),
                                gateway=hex_to_ip(gw_hex),
                                interface=iface,
                                metric=metric
                            ))
            except IOError:
                pass
        return routes

    @staticmethod
    def enumerate_dns() -> List[DNSResolver]:
        """Parsea /etc/resolv.conf para obtener nameservers y dominios."""
        resolvers = []
        domain = ""
        search = []
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    parts = line.split()
                    if parts[0] == "nameserver" and len(parts) >= 2:
                        resolvers.append(DNSResolver(
                            nameserver=parts[1],
                            domain=domain,
                            search=list(search)
                        ))
                    elif parts[0] == "domain" and len(parts) >= 2:
                        domain = parts[1]
                    elif parts[0] == "search" and len(parts) >= 2:
                        search = parts[1:]
        except IOError:
            pass

        # Update domain/search en resolvers ya agregados
        for r in resolvers:
            if not r.domain:
                r.domain = domain
            if not r.search:
                r.search = list(search)
        return resolvers


# ============================================================================
# ACTIVE SCANNING — ICMP Sweep & Banner Grabbing
# ============================================================================

class ActiveScanner:
    """Módulo de escaneo activo asíncrono."""

    # Puertos de interés por defecto para banner grabbing
    DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
                     389, 443, 445, 993, 995, 1433, 1521, 3306, 3389,
                     5432, 5900, 5985, 6379, 8080, 8443, 9200, 27017]

    # Patrones de fingerprinting de servicio
    SERVICE_PATTERNS = {
        r"SSH-[\d.]+-OpenSSH": "OpenSSH",
        r"SSH-[\d.]+-dropbear": "Dropbear SSH",
        r"220.*FTP": "FTP Server",
        r"220.*vsFTPd": "vsFTPd",
        r"220.*ProFTPD": "ProFTPD",
        r"220.*Microsoft FTP": "Microsoft FTP",
        r"HTTP/1\.[01]\s+\d{3}": "HTTP Server",
        r"Server:\s*Apache": "Apache HTTPD",
        r"Server:\s*nginx": "Nginx",
        r"Server:\s*Microsoft-IIS": "Microsoft IIS",
        r"Server:\s*lighttpd": "lighttpd",
        r"\+OK.*POP3": "POP3",
        r"\* OK.*IMAP": "IMAP",
        r"220.*SMTP": "SMTP",
        r"220.*Postfix": "Postfix SMTP",
        r"220.*Exim": "Exim SMTP",
        r"mysql_native_password": "MySQL",
        r"MariaDB": "MariaDB",
        r"PostgreSQL": "PostgreSQL",
        r"Microsoft SQL Server": "MSSQL",
        r"redis_version": "Redis",
        r"Elasticsearch": "Elasticsearch",
        r"MongoDB": "MongoDB",
        r"RFB \d{3}\.\d{3}": "VNC",
        r"SMBr": "SMB/CIFS",
    }

    # OS fingerprinting por TTL
    TTL_OS_MAP = {
        (0, 32): "Embedded/IoT",
        (33, 64): "Linux/Unix/macOS",
        (65, 128): "Windows",
        (129, 255): "Network Device (Cisco/Juniper)"
    }

    def __init__(self, ports: Optional[List[int]] = None, timeout: float = 2.0,
                 concurrency: int = 256, banner_timeout: float = 3.0):
        self.ports = ports or self.DEFAULT_PORTS
        self.timeout = timeout
        self.concurrency = concurrency
        self.banner_timeout = banner_timeout
        self._semaphore = None

    @staticmethod
    def guess_os_from_ttl(ttl: int) -> str:
        """Heurística de OS fingerprinting basada en TTL."""
        for (low, high), os_name in ActiveScanner.TTL_OS_MAP.items():
            if low <= ttl <= high:
                return os_name
        return "Unknown"

    def identify_service(self, banner: str) -> str:
        """Identifica servicio a partir del banner recibido."""
        for pattern, service in self.SERVICE_PATTERNS.items():
            if re.search(pattern, banner, re.IGNORECASE):
                return service
        return "Unknown"

    async def icmp_sweep(self, network: ipaddress.IPv4Network) -> List[HostProfile]:
        """ICMP Echo sweep sobre la subred especificada.
        Usa subprocess ping para compatibilidad sin raw sockets."""
        hosts = []
        sem = asyncio.Semaphore(self.concurrency)

        async def ping_host(ip_str: str):
            async with sem:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "ping", "-c", "1", "-W", "1", "-q", ip_str,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.DEVNULL
                    )
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=3.0)
                    if proc.returncode == 0:
                        # Extraer TTL del output
                        ttl = 0
                        output = stdout.decode(errors="ignore")
                        ttl_match = re.search(r"ttl[=\s]+(\d+)", output, re.IGNORECASE)
                        if ttl_match:
                            ttl = int(ttl_match.group(1))
                        host = HostProfile(
                            ip=ip_str,
                            alive=True,
                            ttl=ttl,
                            os_guess=self.guess_os_from_ttl(ttl),
                            discovery_method="icmp_echo"
                        )
                        hosts.append(host)
                except (asyncio.TimeoutError, Exception):
                    pass

        # Excluir network y broadcast
        targets = [str(ip) for ip in network.hosts()]
        tasks = [ping_host(ip) for ip in targets]
        await asyncio.gather(*tasks)
        return hosts

    async def tcp_connect_scan(self, ip: str, port: int) -> Optional[ServiceBanner]:
        """Escaneo TCP connect con banner grabbing."""
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.concurrency)

        async with self._semaphore:
            start = time.monotonic()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.timeout
                )
                elapsed = (time.monotonic() - start) * 1000

                banner = ""
                try:
                    # Intentar leer banner (muchos servicios envían banner al conectar)
                    data = await asyncio.wait_for(
                        reader.read(1024),
                        timeout=self.banner_timeout
                    )
                    banner = data.decode(errors="replace").strip()
                except asyncio.TimeoutError:
                    # Sin banner espontáneo, enviar probe HTTP para puertos web
                    if port in (80, 8080, 8443, 443, 8888, 3000, 9090):
                        try:
                            writer.write(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
                            await writer.drain()
                            data = await asyncio.wait_for(reader.read(2048), timeout=2.0)
                            banner = data.decode(errors="replace").strip()
                        except Exception:
                            pass

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                service = ServiceBanner(
                    ip=ip,
                    port=port,
                    banner=banner[:512],  # Truncar banners largos
                    service_guess=self.identify_service(banner),
                    tls=(port in (443, 993, 995, 636, 8443, 3269)),
                    response_time_ms=round(elapsed, 2)
                )
                return service

            except (asyncio.TimeoutError, ConnectionRefusedError,
                    ConnectionResetError, OSError):
                return None

    async def scan_host_ports(self, host: HostProfile) -> HostProfile:
        """Escanea todos los puertos de interés en un host."""
        tasks = [self.tcp_connect_scan(host.ip, port) for port in self.ports]
        results = await asyncio.gather(*tasks)
        for svc in results:
            if svc is not None:
                host.open_ports.append(svc.port)
                host.services.append(svc)
        host.open_ports.sort()
        return host

    async def resolve_hostname(self, ip: str) -> str:
        """Resolución inversa de DNS."""
        try:
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, ip),
                timeout=2.0
            )
            return result[0]
        except (socket.herror, socket.gaierror, asyncio.TimeoutError, OSError):
            return ""


# ============================================================================
# ORCHESTRATOR
# ============================================================================

class TopologyMapper:
    """Orquestador principal que combina enumeración pasiva y escaneo activo."""

    def __init__(self, cidr: Optional[str] = None, ports: Optional[List[int]] = None,
                 passive_only: bool = False, concurrency: int = 256,
                 timeout: float = 2.0, output_file: str = "sigv5_t1016_topology_report.json"):
        self.cidr = cidr
        self.passive_only = passive_only
        self.output_file = output_file
        self.passive = PassiveEnumerator()
        self.scanner = ActiveScanner(
            ports=ports,
            timeout=timeout,
            concurrency=concurrency
        )
        self.report = TopologyReport()

    def collect_passive(self):
        """Fase 1: Recolección pasiva de inteligencia local."""
        self.report.timestamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        self.report.hostname = socket.gethostname()
        self.report.platform_info = f"{platform.system()} {platform.release()} ({platform.machine()})"

        print("[*] Phase 1: Passive Enumeration")
        print("    [+] Enumerating network interfaces...")
        self.report.interfaces = self.passive.enumerate_interfaces()
        print(f"        Found {len(self.report.interfaces)} interfaces")

        print("    [+] Reading ARP table...")
        self.report.arp_table = self.passive.enumerate_arp_table()
        print(f"        Found {len(self.report.arp_table)} ARP entries")

        print("    [+] Enumerating routes...")
        self.report.routes = self.passive.enumerate_routes()
        print(f"        Found {len(self.report.routes)} routes")

        print("    [+] Parsing DNS resolvers...")
        self.report.dns_resolvers = self.passive.enumerate_dns()
        print(f"        Found {len(self.report.dns_resolvers)} DNS resolvers")

    async def collect_active(self):
        """Fase 2: Escaneo activo de red."""
        if not self.cidr:
            # Auto-detectar CIDR desde interfaces activas
            for iface in self.report.interfaces:
                for addr in iface.ipv4:
                    if not addr.startswith("127."):
                        self.cidr = addr
                        break
                if self.cidr:
                    break

        if not self.cidr:
            print("    [!] No CIDR specified and no non-loopback interface found. Skipping active scan.")
            return

        try:
            network = ipaddress.IPv4Network(self.cidr, strict=False)
        except ValueError as e:
            print(f"    [!] Invalid CIDR: {e}")
            return

        print(f"\n[*] Phase 2: Active Scanning ({network})")

        # ICMP sweep
        print(f"    [+] ICMP sweep on {network} ({network.num_addresses - 2} hosts)...")
        start = time.monotonic()
        alive_hosts = await self.scanner.icmp_sweep(network)
        elapsed = time.monotonic() - start
        print(f"        Discovered {len(alive_hosts)} alive hosts in {elapsed:.1f}s")

        # Complementar con hosts de tabla ARP no descubiertos
        alive_ips = {h.ip for h in alive_hosts}
        for arp in self.report.arp_table:
            try:
                if ipaddress.IPv4Address(arp.ip) in network and arp.ip not in alive_ips:
                    alive_hosts.append(HostProfile(
                        ip=arp.ip,
                        mac=arp.mac,
                        alive=True,
                        discovery_method="arp_cache"
                    ))
            except ValueError:
                pass

        # Port scanning + banner grabbing
        print(f"    [+] Port scanning {len(alive_hosts)} hosts ({len(self.scanner.ports)} ports each)...")
        start = time.monotonic()
        tasks = [self.scanner.scan_host_ports(h) for h in alive_hosts]
        scanned = await asyncio.gather(*tasks)
        elapsed = time.monotonic() - start
        print(f"        Port scan completed in {elapsed:.1f}s")

        # Reverse DNS
        print("    [+] Resolving hostnames...")
        for host in scanned:
            host.hostname = await self.scanner.resolve_hostname(host.ip)

        # Enriquecer MACs desde ARP
        arp_map = {e.ip: e.mac for e in self.report.arp_table}
        for host in scanned:
            if not host.mac and host.ip in arp_map:
                host.mac = arp_map[host.ip]

        self.report.discovered_hosts = sorted(scanned, key=lambda h: list(map(int, h.ip.split("."))))

        total_open = sum(len(h.open_ports) for h in scanned)
        self.report.scan_stats = {
            "network_scanned": str(network),
            "hosts_alive": len(alive_hosts),
            "total_open_ports": total_open,
            "scan_duration_seconds": round(elapsed, 2),
            "ports_per_host": len(self.scanner.ports)
        }

    def generate_report(self) -> str:
        """Genera reporte JSON final."""
        report_dict = asdict(self.report)
        report_json = json.dumps(report_dict, indent=2, ensure_ascii=False)

        # Guardar a disco
        output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), self.output_file)
        with open(output_path, "w") as f:
            f.write(report_json)
        print(f"\n[*] Report saved to: {output_path}")
        return report_json

    def print_summary(self):
        """Imprime resumen formateado en consola."""
        print("\n" + "=" * 72)
        print("  SIGV5 NETWORK TOPOLOGY REPORT")
        print("=" * 72)
        print(f"  Host:      {self.report.hostname}")
        print(f"  Platform:  {self.report.platform_info}")
        print(f"  Timestamp: {self.report.timestamp}")

        print(f"\n  {'─' * 68}")
        print(f"  INTERFACES ({len(self.report.interfaces)})")
        print(f"  {'─' * 68}")
        for iface in self.report.interfaces:
            status = "🟢" if iface.state == "UP" else "🔴"
            addrs = ", ".join(iface.ipv4) if iface.ipv4 else "no IPv4"
            print(f"  {status} {iface.name:<16} {addrs:<24} MAC: {iface.mac}")

        if self.report.routes:
            print(f"\n  {'─' * 68}")
            print(f"  ROUTES ({len(self.report.routes)})")
            print(f"  {'─' * 68}")
            for rt in self.report.routes[:10]:  # Top 10
                print(f"  {rt.destination:<20} via {rt.gateway:<16} dev {rt.interface}")

        if self.report.dns_resolvers:
            print(f"\n  {'─' * 68}")
            print(f"  DNS RESOLVERS ({len(self.report.dns_resolvers)})")
            print(f"  {'─' * 68}")
            for dns in self.report.dns_resolvers:
                print(f"  NS: {dns.nameserver:<16} Domain: {dns.domain}")

        if self.report.discovered_hosts:
            print(f"\n  {'─' * 68}")
            print(f"  DISCOVERED HOSTS ({len(self.report.discovered_hosts)})")
            print(f"  {'─' * 68}")
            print(f"  {'IP':<16} {'Hostname':<28} {'OS Guess':<20} {'Ports'}")
            print(f"  {'─' * 68}")
            for h in self.report.discovered_hosts:
                ports_str = ",".join(str(p) for p in h.open_ports[:8])
                if len(h.open_ports) > 8:
                    ports_str += f" (+{len(h.open_ports)-8})"
                hostname = h.hostname[:26] if h.hostname else "-"
                print(f"  {h.ip:<16} {hostname:<28} {h.os_guess:<20} {ports_str}")

            # Servicios interesantes
            print(f"\n  {'─' * 68}")
            print(f"  SERVICE BANNERS (notable)")
            print(f"  {'─' * 68}")
            for h in self.report.discovered_hosts:
                for svc in h.services:
                    if svc.banner:
                        banner_short = svc.banner[:60].replace("\n", " ").replace("\r", "")
                        print(f"  {h.ip}:{svc.port:<6} [{svc.service_guess}] {banner_short}")

        if self.report.scan_stats:
            print(f"\n  {'─' * 68}")
            print(f"  SCAN STATISTICS")
            print(f"  {'─' * 68}")
            for k, v in self.report.scan_stats.items():
                print(f"  {k}: {v}")
        print("=" * 72)

    async def run(self):
        """Pipeline principal de ejecución."""
        print("=" * 72)
        print("  SIGV5 — Network Topology Mapper v1.0")
        print("  C4ISR-STRATCOM | SIGINT-V5 | T1016")
        print("=" * 72)

        self.collect_passive()

        if not self.passive_only:
            await self.collect_active()

        self.generate_report()
        self.print_summary()


# ============================================================================
# ENTRYPOINT
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="SIGV5 Network Topology Mapper — T1016 System Network Config Discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --cidr 10.2.1.0/24
  %(prog)s --cidr 10.2.1.0/24 --ports 22,80,443,445,3389
  %(prog)s --passive-only
  %(prog)s --cidr 192.168.1.0/24 --concurrency 512 --timeout 1.5
        """
    )
    parser.add_argument("--cidr", type=str, default=None,
                        help="CIDR to scan (e.g., 10.2.1.0/24). Auto-detected if omitted.")
    parser.add_argument("--ports", type=str, default=None,
                        help="Comma-separated ports to scan (default: common ports)")
    parser.add_argument("--passive-only", action="store_true",
                        help="Only perform passive enumeration (no scanning)")
    parser.add_argument("--concurrency", type=int, default=256,
                        help="Max concurrent operations (default: 256)")
    parser.add_argument("--timeout", type=float, default=2.0,
                        help="Connection timeout in seconds (default: 2.0)")
    parser.add_argument("--output", type=str, default="sigv5_t1016_topology_report.json",
                        help="Output JSON report filename")

    args = parser.parse_args()

    ports = None
    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(",")]

    mapper = TopologyMapper(
        cidr=args.cidr,
        ports=ports,
        passive_only=args.passive_only,
        concurrency=args.concurrency,
        timeout=args.timeout,
        output_file=args.output
    )

    asyncio.run(mapper.run())


if __name__ == "__main__":
    main()
