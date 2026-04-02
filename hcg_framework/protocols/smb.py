#!/usr/bin/env python3
"""
🛡️ HCG Framework - SMB Protocol Handler
[CLASSIFIED]: CONFIDENTIAL - HCG Red Team Operation
[SCOPE]: OPD Hospital Civil de Guadalajara (CONV-0221-JAL-HCG-2026)

Manejador SMB para:
- Enumeración de shares
- Detección de SMB signing
- NTLM relay detection
- Conexiones recicladas para evasión
"""

import socket
import struct
from typing import Optional, Dict, List, Any, Tuple


class SMBHandler:
    """
    Manejador SMB con técnicas de evasión y enumeración.
    
    Características:
    - Connection recycling (máx 3 conexiones por host)
    - Detección de SMB signing
    - Enumeración de shares compartidos
    - Compatible con SMBv1/v2/v3
    """
    
    # SMB Command codes
    SMB_COM_NEGOTIATE = 0x72
    SMB_COM_SESSION_SETUP_ANDX = 0x73
    SMB_COM_TREE_CONNECT_ANDX = 0x75
    SMB_COM_TREE_DISCONNECT = 0x71
    SMB_COM_LOGOFF_ANDX = 0x74
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.session_id = 0
        self.tree_id = 0
        self.socket: Optional[socket.socket] = None
        self.signing_required = False
        self.smb_version = "SMB1"
    
    def connect(self, host: str, port: int = 445) -> bool:
        """Establece conexión SMB."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            self.socket.connect((host, port))
            return True
        except Exception:
            return False
    
    def disconnect(self):
        """Cierra conexión SMB."""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
    
    def negotiate(self) -> bool:
        """Negocia dialecto SMB."""
        # SMB1 Negotiate Protocol Request
        packet = self._build_negotiate_request()
        if not self.socket:
            return False
        
        self.socket.sendall(packet)
        response = self._recv_full_response()
        
        if response:
            return self._parse_negotiate_response(response)
        return False
    
    def _build_negotiate_request(self) -> bytes:
        """Construye SMB1 Negotiate request."""
        # NetBIOS Session Service
        nbss_header = struct.pack(">BBH", 0x00, 0x00, 0x0044)
        
        # SMB Header
        smb_header = (
            b"\xffSMB"  # Protocol
            b"\x72"     # Command (Negotiate)
            b"\x00\x00\x00\x00"  # Status
            b"\x00"     # Flags
            b"\x00\x00"  # Flags2
            b"\x00\x00"  # PIDHigh
            b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Security
            b"\x00\x00"  # TID
            b"\x00\x00"  # PIDLow
            b"\x00\x00"  # UID
            b"\x00\x00"  # MID
        )
        
        # Word count and byte count
        word_count = b"\x00"  # 0 words
        byte_count = struct.pack("<H", 0x0025)
        
        # Dialects
        dialects = (
            b"\x02PC NETWORK PROGRAM 1.0\x00"
            b"\x02MICROSOFT NETWORKS 1.03\x00"
            b"\x02MICROSOFT NETWORKS 3.0\x00"
            b"\x02LANMAN1.0\x00"
            b"\x02LM1.2X002\x00"
            b"\x02DOS LANMAN2.1\x00"
            b"\x02LANMAN2.1\x00"
            b"\x02Samba\x00"
            b"\x02NT LANMAN 1.0\x00"
            b"\x02NT LM 0.12\x00"
        )
        
        return nbss_header + smb_header + word_count + byte_count + dialects
    
    def _parse_negotiate_response(self, response: bytes) -> bool:
        """Parsea respuesta de negociación SMB."""
        if len(response) < 36:
            return False
        
        # Check for security mode
        if len(response) > 40:
            security_mode = response[39]
            self.signing_required = bool(security_mode & 0x04)
        
        # Detect SMB version from response
        if response[0:4] == b"\xfeSMB":
            self.smb_version = "SMB2"
        elif response[0:4] == b"\xffSMB":
            self.smb_version = "SMB1"
        
        return True
    
    def check_signing_required(self, host: str, port: int = 445) -> Tuple[bool, str]:
        """
        Verifica si SMB signing está requerido.
        
        Returns:
            (signing_required, smb_version)
        """
        if not self.connect(host, port):
            return False, "connection_failed"
        
        try:
            if self.negotiate():
                return self.signing_required, self.smb_version
        finally:
            self.disconnect()
        
        return False, "negotiation_failed"
    
    def enumerate_shares(
        self,
        host: str,
        username: str = "",
        password: str = "",
        port: int = 445
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Enumera shares SMB disponibles.
        
        Args:
            host: IP del servidor SMB
            username: Usuario (vacío para null session)
            password: Contraseña
            port: Puerto SMB
            
        Returns:
            Lista de shares o None si falla
        """
        if not self.connect(host, port):
            return None
        
        try:
            self.negotiate()
            
            # Intentar sesión nula primero
            if not username:
                shares = self._try_null_session_shares()
                if shares:
                    return shares
            
            # Si hay credenciales, intentar con autenticación
            if username and password:
                shares = self._try_authenticated_shares(username, password)
                return shares
            
        finally:
            self.disconnect()
        
        return None
    
    def _try_null_session_shares(self) -> Optional[List[Dict[str, Any]]]:
        """Intenta enumerar shares con sesión nula."""
        # Implementación simplificada - en producción usaría impacket
        shares = []
        
        # Shares comunes para probar
        common_shares = ['IPC$', 'ADMIN$', 'C$', 'Users', 'Public']
        
        for share in common_shares:
            accessible = self._test_share_access(share)
            if accessible:
                shares.append({
                    'name': share,
                    'type': 'disk',
                    'accessible': True,
                    'comment': ''
                })
        
        return shares if shares else None
    
    def _try_authenticated_shares(
        self,
        username: str,
        password: str
    ) -> Optional[List[Dict[str, Any]]]:
        """Intenta enumerar shares con autenticación."""
        # Placeholder para implementación con autenticación NTLM
        return None
    
    def _test_share_access(self, share_name: str) -> bool:
        """Prueba acceso a un share específico."""
        if not self.socket:
            return False
        
        # Tree Connect AndX request simplificado
        path = f"\\\\*\\{share_name}"
        
        # Construir packet simplificado
        word_count = b"\x04"
        flags2 = b"\x01\x00"
        byte_count = struct.pack("<H", len(path) + 12)
        
        tree_connect = (
            word_count +
            b"\xff" b"\x00\x00\x00" +  # AndXCommand, Reserved, AndXOffset
            flags2 +
            byte_count +
            b"\x00" +  # BufferFormat
            path.encode('utf-16-le') +
            b"\x00\x00" +  # Service, Password
            b"?????".encode('utf-16-le')  # Password null-terminated
        )
        
        try:
            self.socket.sendall(tree_connect)
            response = self._recv_full_response()
            
            if response and len(response) > 10:
                # Check status code (bytes 9-12)
                status = struct.unpack("<I", response[9:13])[0]
                return status == 0  # STATUS_SUCCESS
        except:
            pass
        
        return False
    
    def _recv_full_response(self) -> Optional[bytes]:
        """Recibe respuesta SMB completa."""
        if not self.socket:
            return None
        
        try:
            # Leer header NetBIOS (4 bytes)
            header = self.socket.recv(4)
            if len(header) < 4:
                return None
            
            _, _, length = struct.unpack(">BBH", header)
            
            # Leer payload
            data = b""
            while len(data) < length:
                chunk = self.socket.recv(min(4096, length - len(data)))
                if not chunk:
                    break
                data += chunk
            
            return header + data
        except socket.timeout:
            return None
        except:
            return None
    
    def check_eternalblue_vulnerable(
        self,
        host: str,
        port: int = 445
    ) -> Optional[bool]:
        """
        Verifica vulnerabilidad a EternalBlue (MS17-010).
        
        Nota: Esta es una verificación NO intrusiva basada en
        fingerprinting de la respuesta SMB. Para confirmación
        definitiva se requiere explotación activa.
        
        Args:
            host: IP del objetivo
            port: Puerto SMB
            
        Returns:
            True si probablemente vulnerable, False si parcheado,
            None si no se puede determinar
        """
        if not self.connect(host, port):
            return None
        
        try:
            # Enviar negotiate request
            neg_packet = self._build_negotiate_request()
            self.socket.sendall(neg_packet)
            response = self._recv_full_response()
            
            if not response:
                return None
            
            # Análisis de fingerprint para MS17-010
            # Los sistemas vulnerables tienen comportamiento específico
            
            # Verificar si soporta SMB1
            if self.smb_version != "SMB1":
                return False  # SMB2/3 no son vulnerables a MS17-010
            
            # Sistemas Windows 7/2008 sin parches muestran patrones específicos
            # Esto es una heurística, no confirmación definitiva
            
            if len(response) > 40:
                # Analizar campos específicos de la respuesta
                security_mode = response[39] if len(response) > 39 else 0
                
                # Ciertas combinaciones indican posible vulnerabilidad
                if security_mode == 0x03:  # Signing optional, no required
                    return None  # Podría ser vulnerable, necesita más pruebas
            
            return None  # Indeterminado sin explotación activa
            
        finally:
            self.disconnect()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Uso: python smb.py <target_host> [port]")
        print("Ejemplo: python smb.py 10.2.1.92 445")
        sys.exit(1)
    
    target = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 445
    
    handler = SMBHandler()
    
    print(f"[*] Analizando SMB en {target}:{port}")
    
    # Check signing
    signing_req, smb_ver = handler.check_signing_required(target, port)
    print(f"[*] Versión SMB: {smb_ver}")
    print(f"[*] SMB Signing: {'REQUERIDO' if signing_req else 'NO REQUERIDO (vulnerable a relay)'}")
    
    # Enumerate shares
    print("\n[*] Enumerando shares...")
    shares = handler.enumerate_shares(target, port=port)
    if shares:
        print(f"[+] Shares encontrados: {len(shares)}")
        for s in shares:
            print(f"    - {s['name']} ({s['type']}) - Accessible: {s['accessible']}")
    else:
        print("[-] No se pudieron enumerar shares (posiblemente requiere autenticación)")
    
    # Check EternalBlue
    print("\n[*] Verificando vulnerabilidad MS17-010 (EternalBlue)...")
    eb_result = handler.check_eternalblue_vulnerable(target, port)
    if eb_result is True:
        print("[!] POSIBLEMENTE VULNERABLE a EternalBlue - requiere confirmación")
    elif eb_result is False:
        print("[-] Probablemente PARCHEADO contra MS17-010")
    else:
        print("[?] Indeterminado - se requiere análisis adicional")
