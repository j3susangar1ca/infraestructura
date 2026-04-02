#!/usr/bin/env python3
"""
🛡️ HCG Framework - Traffic Evasion Engine
[CLASSIFIED]: CONFIDENTIAL - HCG Red Team Operation

Evasión a nivel de tráfico para evadir rate limiting y simular
comportamiento humano. NO es para evadir EDR (no hay EDR detectado).
"""

import functools
import time
import random
from typing import Callable, Any, Dict, List, Optional


class EvasionEngine:
    """
    Motor de evasión de tráfico con técnicas de normalización.
    
    Técnicas implementadas:
    1. User-Agent rotation (Chrome, Firefox, Safari)
    2. Header order específico de navegador real
    3. Timing con jitter log-normal (no uniforme)
    4. Request ordering (GET antes de POST en login flows)
    5. Connection recycling para SMB
    """
    
    # User-Agents reales por plataforma
    USER_AGENTS = {
        'chrome_win': [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        ],
        'firefox_linux': [
            'Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0',
        ],
        'safari_mac': [
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        ]
    }
    
    # Orden de headers por navegador (crítico para fingerprinting)
    HEADER_ORDERS = {
        'chrome': [
            'Host', 'Connection', 'Cache-Control', 'sec-ch-ua',
            'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'Upgrade-Insecure-Requests',
            'User-Agent', 'Accept', 'Sec-Fetch-Site', 'Sec-Fetch-Mode',
            'Sec-Fetch-User', 'Sec-Fetch-Dest', 'Accept-Encoding', 'Accept-Language'
        ],
        'firefox': [
            'Host', 'User-Agent', 'Accept', 'Accept-Language', 'Accept-Encoding',
            'Connection', 'Upgrade-Insecure-Requests', 'Sec-Fetch-Dest',
            'Sec-Fetch-Mode', 'Sec-Fetch-Site', 'Cache-Control'
        ]
    }
    
    def __init__(self):
        self._connection_pools: Dict[str, List[Any]] = {}
        self._request_counts: Dict[str, int] = {}
    
    @staticmethod
    def jitter_timer(min_s: float = 0.5, max_s: float = 3.0) -> float:
        """
        Genera delay con distribución log-normal.
        
        La distribución log-normal modela mejor el comportamiento humano
        que la distribución uniforme (que es detectable estadísticamente).
        
        Args:
            min_s: Delay mínimo en segundos
            max_s: Delay máximo en segundos
            
        Returns:
            Delay en segundos
        """
        try:
            import numpy as np
            delay = np.random.lognormal(0, 0.5)
            return float(np.clip(delay, min_s, max_s))
        except ImportError:
            # Fallback sin numpy
            return random.uniform(min_s, max_s)
    
    def get_random_user_agent(self, browser: Optional[str] = None) -> str:
        """
        Retorna User-Agent aleatorio de navegador real.
        
        Args:
            browser: 'chrome', 'firefox', 'safari', o None para aleatorio
            
        Returns:
            String de User-Agent
        """
        if browser and browser in self.USER_AGENTS:
            key = list(self.USER_AGENTS.keys())[0]
            for k in self.USER_AGENTS:
                if browser in k:
                    key = k
                    break
            return random.choice(self.USER_AGENTS[key])
        
        # Aleatorio entre todos
        all_agents = []
        for agents in self.USER_AGENTS.values():
            all_agents.extend(agents)
        return random.choice(all_agents)
    
    def get_ordered_headers(
        self,
        browser: str = 'chrome',
        custom_headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        """
        Retorna headers en orden específico de navegador.
        
        El orden de headers es un vector de fingerprinting importante.
        Las herramientas automatizadas suelen enviar headers en orden
        alfabético o de inserción, lo cual es detectable.
        
        Args:
            browser: 'chrome' o 'firefox'
            custom_headers: Headers adicionales a incluir
            
        Returns:
            Diccionario de headers en orden correcto
        """
        order = self.HEADER_ORDERS.get(browser, self.HEADER_ORDERS['chrome'])
        
        # Headers base simulados
        base_headers = {
            'Host': 'example.com',
            'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0',
            'sec-ch-ua': '"Chromium";v="122", "Not(A:Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': self.get_random_user_agent(browser),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'es-MX,es;q=0.9,en;q=0.8'
        }
        
        # Construir diccionario ordenado
        result = {}
        for h in order:
            if h in base_headers:
                result[h] = base_headers[h]
        
        # Agregar custom headers al final
        if custom_headers:
            result.update(custom_headers)
        
        return result
    
    def traffic_normalizer(self, func: Callable) -> Callable:
        """
        Decorador que normaliza tráfico saliente.
        
        Aplica automáticamente:
        1. User-Agent rotation
        2. Header ordering
        3. Jitter timing
        
        Uso:
            @traffic_normalizer
            async def make_request(url):
                ...
        """
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Jitter antes del request
            await asyncio.sleep(self.jitter_timer(0.5, 2.0))
            
            # Rotar User-Agent si no está especificado
            if 'headers' not in kwargs:
                kwargs['headers'] = self.get_ordered_headers('chrome')
            elif 'User-Agent' not in kwargs.get('headers', {}):
                kwargs['headers']['User-Agent'] = self.get_random_user_agent()
            
            result = await func(*args, **kwargs)
            
            # Jitter después del request
            await asyncio.sleep(self.jitter_timer(0.3, 1.5))
            
            return result
        
        return wrapper
    
    @staticmethod
    def smb_connection_recycler(
        max_per_host: int = 3,
        cooldown_seconds: float = 10.0
    ):
        """
        Decorador para reciclar conexiones SMB.
        
        Limita conexiones SMB simultáneas por host para simular
        comportamiento normal de usuario accediendo a sus shares.
        
        Args:
            max_per_host: Máximo conexiones simultáneas por host
            cooldown_seconds: Espera entre cerrar y abrir nuevas conexiones
        """
        def decorator(func: Callable) -> Callable:
            _pools: Dict[str, List[Any]] = {}
            _last_close: Dict[str, float] = {}
            
            @functools.wraps(func)
            def wrapper(host: str, *args, **kwargs):
                if host not in _pools:
                    _pools[host] = []
                
                # Verificar cooldown
                if host in _last_close:
                    elapsed = time.time() - _last_close[host]
                    if elapsed < cooldown_seconds:
                        time.sleep(cooldown_seconds - elapsed)
                
                # Limpiar conexiones viejas
                _pools[host] = [c for c in _pools[host] if not getattr(c, 'closed', True)]
                
                # Verificar límite
                if len(_pools[host]) >= max_per_host:
                    # Cerrar la más vieja
                    old_conn = _pools[host].pop(0)
                    try:
                        old_conn.close()
                    except:
                        pass
                    _last_close[host] = time.time()
                
                return func(host, *args, **kwargs)
            
            return wrapper
        return decorator
    
    def simulate_human_typing(self, text: str, min_delay: float = 0.05, max_delay: float = 0.3) -> List[float]:
        """
        Genera delays que simulan tecleo humano.
        
        Los humanos no teclean a intervalos uniformes. Hay variación
        basada en:
        - Longitud de palabras
        - Caracteres especiales (más lentos)
        - Mayúsculas (ligeramente más lentas)
        
        Args:
            text: Texto a "teclear"
            min_delay: Delay mínimo entre teclas
            max_delay: Delay máximo entre teclas
            
        Returns:
            Lista de delays por carácter
        """
        delays = []
        
        for i, char in enumerate(text):
            # Base delay
            base = random.uniform(min_delay, max_delay)
            
            # Ajustar por tipo de carácter
            if char.isupper():
                base *= 1.2  # Mayúsculas más lentas
            elif char in '!@#$%^&*()_+-=[]{}|;:,.<>?':
                base *= 1.5  # Símbolos más lentos
            elif char == ' ':
                base *= 0.8  # Espacio más rápido
            
            # Variación aleatoria adicional
            variation = random.gauss(1.0, 0.2)
            delays.append(base * max(0.5, variation))
        
        return delays


# Import asyncio para el decorador
import asyncio


if __name__ == "__main__":
    print("=" * 60)
    print("HCG Framework - Traffic Evasion Engine")
    print("=" * 60)
    
    engine = EvasionEngine()
    
    print("\n[*] Ejemplos de User-Agents:")
    for _ in range(5):
        print(f"    {engine.get_random_user_agent()}")
    
    print("\n[*] Ejemplo de delays de tecleo humano:")
    text = "Password123!"
    delays = engine.simulate_human_typing(text)
    total_time = sum(delays)
    print(f"    Texto: '{text}'")
    print(f"    Delays por caracter: {[f'{d:.3f}s' for d in delays[:5]]}...")
    print(f"    Tiempo total estimado: {total_time:.2f}s")
    
    print("\n[*] Jitter timer (log-normal distribution):")
    for _ in range(10):
        delay = engine.jitter_timer(0.5, 2.0)
        print(f"    {delay:.3f}s")
