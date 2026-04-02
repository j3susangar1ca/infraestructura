#!/usr/bin/env python3
"""
🛡️ HCG Framework - Differential Response Analyzer
[CLASSIFIED]: CONFIDENTIAL - HCG Red Team Operation

Análisis diferencial de respuestas HTTP para detectar vulnerabilidades
sin depender de firmas conocidas. Compara baseline vs test_response.
"""

import math
import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field


@dataclass
class AnalysisResult:
    """Resultado del análisis diferencial."""
    is_anomalous: bool
    anomalies: List[str]
    confidence: float  # 0.0 a 1.0
    metrics: Dict[str, Any] = field(default_factory=dict)
    classification: str = "normal"  # normal, sqli, xss, lfi, rce, debug


class ResponseAnalyzer:
    """
    Analizador diferencial de respuestas HTTP/HTTPS.
    
    Métricas comparadas:
    1. Status code difference (200→500 = posible SQLi, 200→302 = redirect)
    2. Response length delta (>50% = cambio significativo)
    3. Response time delta (>3s = time-based injection)
    4. Content pattern matching (errores DB, OS, stack traces)
    5. Header differential (nuevos headers, headers eliminados)
    6. Body entropy change (Shannon entropy)
    
    Uso:
        analyzer = ResponseAnalyzer()
        baseline = analyzer.capture_baseline(url)
        result = analyzer.differential_analysis(baseline, test_response)
        
        if result.is_anomalous:
            print(f"Anomalía: {result.anomalies}")
            print(f"Clasificación: {result.classification}")
    """
    
    # Patrones de error por categoría
    PATTERNS = {
        'sqli': [
            r'sql\s*(error|syntax|warning|exception)',
            r'mysql.*error', r'oracle.*error', r'postgres.*error',
            r'sqlite.*error', r'mssql.*error',
            r'ora-\d+', r'pg::', r'odbc.*error',
            r'syntax\s+error.*sql', r'unterminated.*string',
            r'quoted string not properly terminated',
            r'you have an error in your sql syntax',
        ],
        'xss': [
            r'<script[^>]*>alert\s*\(',
            r'javascript:alert',
            r'on(error|load|click|mouse)\s*=',
            r'<svg[^>]*onload',
            r'<img[^>]*onerror',
        ],
        'lfi': [
            r'root:[x*]:0:0:',  # /etc/passwd
            r'/bin/(ba)?sh',
            r'Microsoft Windows.*System32',
            r'\[extensions\]',  # win.ini
            r'driver c=',  # system.ini
        ],
        'rce': [
            r'uid=\d+\([^)]+\) gid=\d+\([^)]+\)',
            r'root:', r'Administrator',
            r'/bin/bash', r'/bin/sh',
            r'ComputerName', r'Username',
        ],
        'debug': [
            r'stack\s*trace',
            r'exception.*at\s+',
            r'file\s+".*"\s+line\s+\d+',
            r'traceback.*most recent',
            r'fatal error',
            r'assertion failed',
            r'undefined variable',
            r'call stack',
        ]
    }
    
    def __init__(self):
        self.compiled_patterns = {}
        for category, patterns in self.PATTERNS.items():
            self.compiled_patterns[category] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]
    
    def capture_baseline(
        self,
        status_code: int,
        length: int,
        response_time: float,
        headers: Dict[str, str],
        content: str
    ) -> Dict[str, Any]:
        """
        Captura respuesta baseline para comparación.
        
        Args:
            status_code: HTTP status code
            length: Longitud de la respuesta en bytes
            response_time: Tiempo de respuesta en segundos
            headers: Diccionario de headers
            content: Contenido de la respuesta
            
        Returns:
            Diccionario con métricas baseline
        """
        return {
            'status_code': status_code,
            'length': length,
            'response_time': response_time,
            'headers': dict(headers),
            'header_count': len(headers),
            'entropy': self._calculate_entropy(content),
            'content_hash': hash(content) % (10**9),
            'word_count': len(content.split()),
            'line_count': content.count('\n')
        }
    
    def differential_analysis(
        self,
        baseline: Dict[str, Any],
        test_status: int,
        test_length: int,
        test_time: float,
        test_headers: Dict[str, str],
        test_content: str
    ) -> AnalysisResult:
        """
        Compara baseline con respuesta de test y detecta anomalías.
        
        Args:
            baseline: Métricas de respuesta baseline
            test_status: Status code del test
            test_length: Longitud del test
            test_time: Tiempo de respuesta del test
            test_headers: Headers del test
            test_content: Contenido del test
            
        Returns:
            AnalysisResult con anomalías detectadas
        """
        anomalies = []
        scores = {'sqli': 0, 'xss': 0, 'lfi': 0, 'rce': 0, 'debug': 0}
        
        # 1. Status code difference
        status_diff = test_status - baseline['status_code']
        if abs(status_diff) >= 100:
            anomalies.append(f'status_change:{baseline["status_code"]}→{test_status}')
            if test_status == 500:
                scores['sqli'] += 0.3
                scores['rce'] += 0.2
            elif test_status == 302 or test_status == 301:
                anomalies.append('possible_redirect_based_vuln')
        
        # 2. Response length delta
        length_diff = test_length - baseline['length']
        length_ratio = length_diff / baseline['length'] if baseline['length'] > 0 else 0
        
        if abs(length_ratio) > 0.5:  # >50% cambio
            anomalies.append(f'size_delta:{length_diff:+d} ({length_ratio*100:+.1f}%)')
            if length_diff > 0:
                scores['sqli'] += 0.2  # Error messages usually add content
                scores['debug'] += 0.2
            else:
                scores['xss'] += 0.1  # XSS might truncate response
        elif abs(length_diff) > 1000:
            anomalies.append(f'size_delta:{length_diff:+d} bytes')
        
        # 3. Response time delta
        time_diff = test_time - baseline['response_time']
        if time_diff > 3.0:
            anomalies.append(f'time_delta:+{time_diff:.2f}s')
            scores['sqli'] += 0.4  # Time-based SQLi
            scores['rce'] += 0.2   # Command execution
        
        # 4. Pattern matching en contenido
        content_lower = test_content.lower()
        for category, patterns in self.compiled_patterns.items():
            matches = []
            for pattern in patterns:
                match = pattern.search(content_lower)
                if match:
                    matches.append(match.group())
            
            if matches:
                anomalies.append(f'{category}_pattern:{matches[0][:50]}')
                scores[category] += 0.5 * min(len(matches), 3)
        
        # 5. Header differential
        baseline_headers = set(baseline.get('headers', {}).keys())
        test_header_set = set(test_headers.keys())
        
        new_headers = test_header_set - baseline_headers
        removed_headers = baseline_headers - test_header_set
        
        if new_headers:
            anomalies.append(f'new_headers:{list(new_headers)[:3]}')
        if removed_headers:
            anomalies.append(f'removed_headers:{list(removed_headers)[:3]}')
        
        # 6. Entropy change
        test_entropy = self._calculate_entropy(test_content)
        entropy_diff = test_entropy - baseline.get('entropy', 0)
        if abs(entropy_diff) > 1.0:
            anomalies.append(f'entropy_delta:{entropy_diff:+.2f}')
            if entropy_diff > 0:
                scores['rce'] += 0.2  # More random content
        
        # Determinar clasificación
        max_score = max(scores.values())
        if max_score > 0.3:
            classification = max(scores, key=scores.get)
        else:
            classification = 'normal'
        
        # Calcular confianza
        confidence = min(1.0, max_score) if anomalies else 0.0
        
        return AnalysisResult(
            is_anomalous=len(anomalies) > 0,
            anomalies=anomalies,
            confidence=confidence,
            metrics={
                'status_diff': status_diff,
                'length_diff': length_diff,
                'length_ratio': length_ratio,
                'time_diff': time_diff,
                'entropy_diff': entropy_diff,
                'scores': scores
            },
            classification=classification
        )
    
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
                entropy -= p * math.log2(p)
        
        return entropy
    
    def classify_error_message(self, content: str) -> Tuple[str, float]:
        """
        Clasifica mensaje de error encontrado.
        
        Args:
            content: Contenido a analizar
            
        Returns:
            (categoria, confianza)
        """
        scores = {}
        content_lower = content.lower()
        
        for category, patterns in self.compiled_patterns.items():
            score = 0
            for pattern in patterns:
                if pattern.search(content_lower):
                    score += 1
            scores[category] = score
        
        if not scores or max(scores.values()) == 0:
            return ('unknown', 0.0)
        
        best = max(scores, key=scores.get)
        confidence = scores[best] / len(self.compiled_patterns[best])
        return (best, min(1.0, confidence))
    
    def generate_report(
        self,
        results: List[AnalysisResult],
        url: str,
        param: str
    ) -> str:
        """
        Genera reporte de hallazgos.
        
        Args:
            results: Lista de resultados de análisis
            url: URL testeada
            param: Parámetro testeado
            
        Returns:
            Reporte formateado
        """
        report = []
        report.append("=" * 60)
        report.append(f"REPORTE DE ANÁLISIS DIFERENCIAL")
        report.append(f"URL: {url}")
        report.append(f"Parámetro: {param}")
        report.append("=" * 60)
        
        anomalous = [r for r in results if r.is_anomalous]
        
        report.append(f"\nTotal tests: {len(results)}")
        report.append(f"Anomalías detectadas: {len(anomalous)}")
        
        if anomalous:
            report.append("\n" + "-" * 40)
            report.append("ANOMALÍAS POR CATEGORÍA:")
            report.append("-" * 40)
            
            by_category = {}
            for r in anomalous:
                cat = r.classification
                if cat not in by_category:
                    by_category[cat] = []
                by_category[cat].append(r)
            
            for cat, cat_results in sorted(by_category.items(), 
                                           key=lambda x: len(x[1]), 
                                           reverse=True):
                report.append(f"\n{cat.upper()} ({len(cat_results)} casos):")
                for r in cat_results[:5]:  # Top 5
                    report.append(f"  - Confianza: {r.confidence:.2f}")
                    report.append(f"    Anomalías: {', '.join(r.anomalies[:3])}")
        
        return '\n'.join(report)


if __name__ == "__main__":
    print("=" * 60)
    print("HCG Framework - Differential Response Analyzer")
    print("=" * 60)
    
    analyzer = ResponseAnalyzer()
    
    # Ejemplo de baseline
    baseline = analyzer.capture_baseline(
        status_code=200,
        length=5000,
        response_time=0.5,
        headers={'Content-Type': 'text/html', 'Server': 'Apache'},
        content="<html><body>Normal page content...</body></html>" * 100
    )
    
    print("\n[*] Baseline capturada:")
    print(f"    Status: {baseline['status_code']}")
    print(f"    Length: {baseline['length']} bytes")
    print(f"    Time: {baseline['response_time']}s")
    print(f"    Entropy: {baseline['entropy']:.3f}")
    
    # Ejemplo de respuesta con SQL error
    test_content_error = """
    <b>Warning</b>: mysql_query(): You have an error in your SQL syntax; 
    check the manual that corresponds to your MySQL server version for 
    the right syntax to use near ''' at line 1
    """
    
    result = analyzer.differential_analysis(
        baseline=baseline,
        test_status=500,
        test_length=8000,
        test_time=4.5,
        test_headers={'Content-Type': 'text/html', 'Server': 'Apache'},
        test_content=test_content_error
    )
    
    print("\n[*] Análisis de respuesta con error:")
    print(f"    Anómala: {result.is_anomalous}")
    print(f"    Clasificación: {result.classification}")
    print(f"    Confianza: {result.confidence:.2f}")
    print(f"    Anomalías:")
    for a in result.anomalies:
        print(f"      - {a}")
    
    print("\n[*] Métricas:")
    for k, v in result.metrics.items():
        print(f"    {k}: {v}")
