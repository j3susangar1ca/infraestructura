"""
🛡️ HCG Framework - Red Team Automation Platform
[CLASSIFIED]: CONFIDENTIAL - HCG Red Team Operation
[SCOPE]: OPD Hospital Civil de Guadalajara (CONV-0221-JAL-HCG-2026)

Framework de automatización para operaciones Red Team con:
- Orquestación asíncrona de múltiples rutas de ataque
- Grafo de dependencias (DAG) para ejecución ordenada
- Rate limiting y circuit breakers por target
- Detección temprana de objetivos alcanzados
"""

from .orchestration import AsyncOrchestrator, AttackDAG, AttackNode, TokenBucket, CircuitBreaker
from .protocols import AJP13Codec, LDAPProbe, SMBHandler
from .fuzzing import ServiceFuzzer, FuzzResult
from .cracking import DistributedCracker
from .evasion import EvasionEngine
from .analysis import ResponseAnalyzer

__version__ = "1.0.0"
__author__ = "HCG Red Team"

__all__ = [
    # Orchestration
    'AsyncOrchestrator',
    'AttackDAG',
    'AttackNode',
    'TokenBucket',
    'CircuitBreaker',
    
    # Protocols
    'AJP13Codec',
    'LDAPProbe',
    'SMBHandler',
    
    # Fuzzing
    'ServiceFuzzer',
    'FuzzResult',
    
    # Cracking
    'DistributedCracker',
    
    # Evasion
    'EvasionEngine',
    
    # Analysis
    'ResponseAnalyzer',
]
