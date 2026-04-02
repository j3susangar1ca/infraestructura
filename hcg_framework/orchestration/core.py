#!/usr/bin/env python3
"""
🛡️ HCG Framework - Core Orchestration Engine
[CLASSIFIED]: CONFIDENTIAL - HCG Red Team Operation
[SCOPE]: OPD Hospital Civil de Guadalajara (CONV-0221-JAL-HCG-2026)

Motor de orquestación asíncrona para ejecutar múltiples rutas de ataque
en paralelo con control de dependencias, rate limiting y circuit breakers.
"""

import asyncio
import time
from typing import Dict, List, Optional, Callable, Any, Set
from dataclasses import dataclass, field
from enum import Enum


class NodeStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class AttackNode:
    """
    Nodo individual en el grafo de ataque.
    
    Cada nodo representa un paso ejecutable con:
    - Acción asíncrona a ejecutar
    - Prioridad para scheduling
    - Timeout máximo
    - Verificación de prerequisitos
    - Callbacks de éxito/fracaso
    """
    id: str
    action: Callable[..., Any]
    priority: int = 5
    timeout: float = 300.0
    prereq_check: Optional[Callable[[], bool]] = None
    on_success: Optional[Callable[[Any], None]] = None
    on_failure: Optional[Callable[[Exception], None]] = None
    target: str = ""
    description: str = ""
    is_objective_node: bool = False
    
    # Estado interno
    status: NodeStatus = NodeStatus.PENDING
    remaining_deps: int = 0
    children: List['AttackNode'] = field(default_factory=list)
    result: Any = None
    error: Optional[Exception] = None
    reached_objective: bool = False
    
    async def execute(self) -> Any:
        """Ejecuta la acción del nodo con manejo de errores."""
        # Verificar prerequisitos
        if self.prereq_check and not self.prereq_check():
            self.status = NodeStatus.SKIPPED
            self.log("Prerequisitos no cumplidos - SKIP")
            return None
        
        self.status = NodeStatus.RUNNING
        self.log("Ejecutando...")
        
        try:
            if asyncio.iscoroutinefunction(self.action):
                result = await asyncio.wait_for(self.action(), timeout=self.timeout)
            else:
                loop = asyncio.get_event_loop()
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, self.action),
                    timeout=self.timeout
                )
            
            self.result = result
            self.status = NodeStatus.COMPLETED
            
            if self.on_success:
                self.on_success(result)
            
            self.log("COMPLETADO")
            return result
            
        except asyncio.TimeoutError:
            self.error = asyncio.TimeoutError(f"Timeout after {self.timeout}s")
            self.status = NodeStatus.FAILED
            self.log(f"TIMEOUT ({self.timeout}s)")
            if self.on_failure:
                self.on_failure(self.error)
            raise
            
        except Exception as e:
            self.error = e
            self.status = NodeStatus.FAILED
            self.log(f"ERROR: {e}")
            if self.on_failure:
                self.on_failure(e)
            raise
    
    def log(self, message: str):
        """Loguea mensaje con contexto del nodo."""
        timestamp = time.strftime("%H:%M:%S")
        print(f"[{timestamp}] [{self.id}] {message}")


class TokenBucket:
    """
    Rate limiter basado en token bucket algorithm.
    
    Previene sobrecargar targets con demasiadas requests simultáneas.
    Configuración por tipo de servicio:
    - WHM/cPanel: 1 req/s (evitar detección de brute force)
    - MySQL: 5 intentos/s
    - LDAP: 10 consultas/s
    - SMB: 3 conexiones/s
    """
    
    def __init__(self, rate: float = 1.0, capacity: int = 10):
        """
        Args:
            rate: Tokens por segundo de recarga
            capacity: Capacidad máxima del bucket
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = float(capacity)
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()
    
    async def acquire(self, tokens: int = 1) -> bool:
        """
        Adquiere tokens, esperando si es necesario.
        
        Args:
            tokens: Número de tokens a consumir
            
        Returns:
            True cuando se obtienen los tokens
        """
        async with self._lock:
            while True:
                self._refill()
                
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return True
                
                # Calcular tiempo de espera
                wait_time = (tokens - self.tokens) / self.rate
                await asyncio.sleep(wait_time)
    
    def _refill(self):
        """Recarga tokens basados en tiempo transcurrido."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_refill = now


class CircuitBreaker:
    """
    Circuit breaker pattern para pausar targets problemáticos.
    
    Estados:
    - CLOSED: Operación normal
    - OPEN: Demasiados fallos consecutivos, pausar operaciones
    - HALF-OPEN: Período de prueba tras cooldown
    
    Configuración típica:
    - 5 fallos consecutivos → OPEN
    - 300s cooldown antes de HALF-OPEN
    - 1 éxito en HALF-OPEN → CLOSED
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        cooldown_seconds: float = 300.0,
        half_open_max_calls: int = 1
    ):
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self.half_open_max_calls = half_open_max_calls
        
        self.failures = 0
        self.successes = 0
        self.state = "CLOSED"
        self.last_failure_time = 0.0
        self.half_open_calls = 0
        self._lock = asyncio.Lock()
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Ejecuta función respetando estado del circuit breaker."""
        async with self._lock:
            if self.state == "OPEN":
                if time.time() - self.last_failure_time > self.cooldown_seconds:
                    self.state = "HALF-OPEN"
                    self.half_open_calls = 0
                else:
                    raise Exception("Circuit breaker OPEN")
            
            if self.state == "HALF-OPEN" and self.half_open_calls >= self.half_open_max_calls:
                raise Exception("Circuit breaker HALF-OPEN limit reached")
            
            self.half_open_calls += 1
        
        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(None, lambda: func(*args, **kwargs))
            
            async with self._lock:
                self._on_success()
            
            return result
            
        except Exception as e:
            async with self._lock:
                self._on_failure()
            raise
    
    def _on_success(self):
        """Registra éxito y posiblemente cierra circuit breaker."""
        self.failures = 0
        self.successes += 1
        
        if self.state == "HALF-OPEN":
            self.state = "CLOSED"
            self.half_open_calls = 0
    
    def _on_failure(self):
        """Registra fallo y posiblemente abre circuit breaker."""
        self.failures += 1
        self.last_failure_time = time.time()
        
        if self.failures >= self.failure_threshold:
            self.state = "OPEN"
    
    def is_open(self) -> bool:
        """Verifica si circuit breaker está abierto."""
        if self.state == "OPEN":
            if time.time() - self.last_failure_time > self.cooldown_seconds:
                self.state = "HALF-OPEN"
                return False
            return True
        return False
    
    def record_success(self):
        """Registra éxito manualmente."""
        self._on_success()
    
    def record_failure(self):
        """Registra fallo manualmente."""
        self._on_failure()


class AttackDAG:
    """
    Grafo Acíclico Dirigido de pasos de ataque.
    
    Permite definir dependencias complejas entre pasos:
    
    Ejemplo de DAG para HCG:
    
    [OSINT] ──→ [WHM_Fingerprint] ──→ [WHM_Exploit] ──→ [PostExploit] ──→ [OBJETIVO]
       │                                          │
       ├──→ [MySQL_Fingerprint] ──→ [MySQL_Brute] ─┘
       │
       ├──→ [Handshake_Capture] ──→ [PSK_Crack] ──→ [WiFi_Recon] ──→ [Ghostcat] ──→ [OBJETIVO]
       │                                                      │
       │                                                      ├──→ [LDAP_Anony] ──→ [Kerberoast] ──→ [OBJETIVO]
       │                                                      └──→ [LLMNR_Poison] ──→ [NTLM_Relay] ──→ [OBJETIVO]
       │
       └──→ [Phishing_Prep] ──→ [Send_Campaign] ──→ [Cred_Capture] ──→ [SMB_Enum] ──→ [OBJETIVO]
                                                                    │
                                                                    └──→ [Kerberoast] ──→ [DCSync] ──→ [OBJETIVO]
    """
    
    def __init__(self):
        self.nodes: Dict[str, AttackNode] = {}
        self.edges: List[tuple] = []
        self.objective_nodes: Set[str] = set()
    
    def add_node(
        self,
        node_id: str,
        action: Callable,
        priority: int = 5,
        timeout: float = 300.0,
        prereq_check: Optional[Callable] = None,
        on_success: Optional[Callable] = None,
        on_failure: Optional[Callable] = None,
        target: str = "",
        description: str = "",
        is_objective: bool = False
    ) -> AttackNode:
        """Agrega nodo al grafo."""
        node = AttackNode(
            id=node_id,
            action=action,
            priority=priority,
            timeout=timeout,
            prereq_check=prereq_check,
            on_success=on_success,
            on_failure=on_failure,
            target=target,
            description=description,
            is_objective_node=is_objective
        )
        self.nodes[node_id] = node
        
        if is_objective:
            self.objective_nodes.add(node_id)
        
        return node
    
    def add_dependency(self, from_id: str, to_id: str):
        """
        Establece dependencia: to_id depende de from_id.
        to_id solo se ejecutará después que from_id complete exitosamente.
        """
        if from_id not in self.nodes or to_id not in self.nodes:
            raise ValueError(f"Node not found: {from_id} or {to_id}")
        
        self.edges.append((from_id, to_id))
        self.nodes[from_id].children.append(self.nodes[to_id])
        self.nodes[to_id].remaining_deps += 1
    
    def get_ready_nodes(self) -> List[AttackNode]:
        """Retorna nodos listos para ejecutar (sin dependencias pendientes)."""
        return [n for n in self.nodes.values() if n.remaining_deps == 0 and n.status == NodeStatus.PENDING]
    
    def any_objective_reached(self) -> bool:
        """Verifica si algún nodo objetivo fue alcanzado."""
        for node_id in self.objective_nodes:
            node = self.nodes.get(node_id)
            if node and node.status == NodeStatus.COMPLETED:
                return True
        return False
    
    def get_completion_status(self) -> Dict[str, Any]:
        """Retorna estado de completitud del DAG."""
        total = len(self.nodes)
        completed = sum(1 for n in self.nodes.values() if n.status == NodeStatus.COMPLETED)
        failed = sum(1 for n in self.nodes.values() if n.status == NodeStatus.FAILED)
        pending = sum(1 for n in self.nodes.values() if n.status == NodeStatus.PENDING)
        
        return {
            'total': total,
            'completed': completed,
            'failed': failed,
            'pending': pending,
            'progress': completed / total if total > 0 else 0,
            'objective_reached': self.any_objective_reached()
        }


class AsyncOrchestrator:
    """
    Orquestador asíncrono para ejecución paralela de ataques.
    
    Características:
    - Ejecución de hasta N workers concurrentes
    - Priority queue para scheduling inteligente
    - Rate limiting por target (TokenBucket)
    - Circuit breaker por target
    - Detección temprana de objetivo alcanzado
    - Graceful shutdown
    
    Uso típico:
        dag = AttackDAG()
        dag.add_node("recon", recon_action, priority=10)
        dag.add_node("exploit", exploit_action, priority=8)
        dag.add_dependency("recon", "exploit")
        
        orchestrator = AsyncOrchestrator(max_workers=10)
        results = await orchestrator.run(dag)
    """
    
    def __init__(
        self,
        max_workers: int = 10,
        default_rate_limit: float = 5.0,
        default_circuit_breaker_threshold: int = 5
    ):
        self.max_workers = max_workers
        self.default_rate_limit = default_rate_limit
        self.default_cb_threshold = default_circuit_breaker_threshold
        
        self.priority_queue: asyncio.PriorityQueue = None
        self.rate_limiters: Dict[str, TokenBucket] = {}
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.semaphores: Dict[str, asyncio.Semaphore] = {}
        self.results: Dict[str, Any] = {}
        self.running = False
        self.dag: Optional[AttackDAG] = None
    
    def get_rate_limiter(self, target: str) -> TokenBucket:
        """Obtiene o crea rate limiter para target."""
        if target not in self.rate_limiters:
            self.rate_limiters[target] = TokenBucket(
                rate=self.default_rate_limit,
                capacity=10
            )
        return self.rate_limiters[target]
    
    def get_circuit_breaker(self, target: str) -> CircuitBreaker:
        """Obtiene o crea circuit breaker para target."""
        if target not in self.circuit_breakers:
            self.circuit_breakers[target] = CircuitBreaker(
                failure_threshold=self.default_cb_threshold,
                cooldown_seconds=300.0
            )
        return self.circuit_breakers[target]
    
    async def run(self, dag: AttackDAG) -> Dict[str, Any]:
        """
        Ejecuta el DAG de ataque completo.
        
        Args:
            dag: AttackDAG con nodos y dependencias configuradas
            
        Returns:
            Diccionario con resultados de todos los nodos
        """
        self.dag = dag
        self.running = True
        self.priority_queue = asyncio.PriorityQueue()
        
        # Inicializar workers
        workers = [
            asyncio.create_task(self._worker(i))
            for i in range(self.max_workers)
        ]
        
        # Encolar nodos iniciales
        for node in dag.get_ready_nodes():
            await self.priority_queue.put((-node.priority, node.id, node))
        
        # Monitorear progreso
        progress_interval = 30.0
        last_progress_report = time.time()
        
        while self.running:
            # Verificar si hay nodos objetivos alcanzados
            if dag.any_objective_reached():
                print("\n[!] OBJETIVO ALCANZADO - Deteniendo ejecución temprana")
                self.running = False
                break
            
            # Verificar si todos los nodos fueron procesados
            all_done = all(
                n.status in (NodeStatus.COMPLETED, NodeStatus.FAILED, NodeStatus.SKIPPED)
                for n in dag.nodes.values()
            )
            if all_done:
                break
            
            # Reportar progreso periódico
            if time.time() - last_progress_report > progress_interval:
                status = dag.get_completion_status()
                print(f"\n[*] Progreso: {status['completed']}/{status['total']} "
                      f"({status['progress']*100:.1f}%) - "
                      f"Fallos: {status['failed']} - "
                      f"Pendientes: {status['pending']}")
                last_progress_report = time.time()
            
            # Encolar nuevos nodos listos
            for node in dag.get_ready_nodes():
                await self.priority_queue.put((-node.priority, node.id, node))
            
            await asyncio.sleep(0.1)
        
        # Cancelar workers
        for w in workers:
            w.cancel()
        
        await asyncio.gather(*workers, return_exceptions=True)
        
        return self.results
    
    async def _worker(self, worker_id: int):
        """Worker que consume nodos de la priority queue."""
        while self.running:
            try:
                # Obtener nodo de la cola
                try:
                    _, _, node = await asyncio.wait_for(
                        self.priority_queue.get(),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                
                # Verificar circuit breaker
                if node.target:
                    cb = self.get_circuit_breaker(node.target)
                    if cb.is_open():
                        node.log(f"Circuit breaker OPEN para {node.target} - SKIP")
                        node.status = NodeStatus.SKIPPED
                        self.priority_queue.task_done()
                        continue
                    
                    # Aplicar rate limiting
                    limiter = self.get_rate_limiter(node.target)
                    await limiter.acquire()
                
                # Ejecutar nodo
                try:
                    result = await node.execute()
                    self.results[node.id] = {
                        'status': 'success',
                        'result': result
                    }
                    
                    if node.target:
                        self.get_circuit_breaker(node.target).record_success()
                    
                    # Actualizar dependencias de hijos
                    for child in node.children:
                        child.remaining_deps -= 1
                        if child.remaining_deps == 0:
                            await self.priority_queue.put((-child.priority, child.id, child))
                            
                except Exception as e:
                    self.results[node.id] = {
                        'status': 'failed',
                        'error': str(e)
                    }
                    
                    if node.target:
                        self.get_circuit_breaker(node.target).record_failure()
                    
                    # Marcar hijos como skipped si dependen de este nodo fallido
                    for child in node.children:
                        child.remaining_deps -= 1
                        if child.remaining_deps == 0:
                            # Solo encolar si puede ejecutarse sin el padre
                            if child.prereq_check is None or child.prereq_check():
                                await self.priority_queue.put((-child.priority, child.id, child))
                            else:
                                child.status = NodeStatus.SKIPPED
                                child.log("Padre fallido - SKIP")
                
                self.priority_queue.task_done()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[Worker {worker_id}] Error: {e}")
                await asyncio.sleep(1.0)


async def main():
    """Ejemplo de uso del framework."""
    print("=" * 60)
    print("HCG Framework - Demo de Orquestación")
    print("=" * 60)
    
    # Crear DAG de ejemplo
    dag = AttackDAG()
    
    async def dummy_recon():
        await asyncio.sleep(1)
        return {"hosts": ["10.2.1.1", "10.2.1.140"]}
    
    async def dummy_exploit():
        await asyncio.sleep(2)
        return {"shell": True}
    
    async def dummy_postexploit():
        await asyncio.sleep(1)
        return {"admin": True}
    
    # Agregar nodos
    dag.add_node("recon", dummy_recon, priority=10, target="10.2.1.1", description="Reconocimiento")
    dag.add_node("exploit", dummy_exploit, priority=8, target="10.2.1.1", description="Explotación")
    dag.add_node("post", dummy_postexploit, priority=5, target="10.2.1.1", 
                 description="Post-explotación", is_objective=True)
    
    # Agregar dependencias
    dag.add_dependency("recon", "exploit")
    dag.add_dependency("exploit", "post")
    
    # Ejecutar
    orchestrator = AsyncOrchestrator(max_workers=5)
    results = await orchestrator.run(dag)
    
    print("\n" + "=" * 60)
    print("Resultados:")
    for node_id, result in results.items():
        status = result['status']
        print(f"  {node_id}: {status}")
    
    print("\nEstado final:", dag.get_completion_status())


if __name__ == "__main__":
    asyncio.run(main())
