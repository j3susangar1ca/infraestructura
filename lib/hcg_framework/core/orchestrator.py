#
# 🛡️ C4ISR-STRATCOM-IMPLANT-SIGINT-V5: Core Orchestrator
# [CLASSIFIED]: CONFIDENCIAL
# [MODULE]: AsyncOrchestrator
#

import asyncio
import time
import collections
import logging

# Configure operational logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s] SIGV5: %(message)s')
logger = logging.getLogger("SIGINT_V5")

class TokenBucket:
    """
    Rate limiter for specific targets to prevent IDS/WAF triggers.
    Configurable rate (tokens/sec) and burst capacity.
    """
    def __init__(self, rate, capacity):
        self.rate = float(rate)
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.last_refill = time.time()
        self.lock = asyncio.Lock()

    async def acquire(self):
        async with self.lock:
            self._refill()
            if self.tokens < 1.0:
                wait_time = (1.0 - self.tokens) / self.rate
                logger.debug(f"Rate limit hit, waiting {wait_time:.2f}s")
                await asyncio.sleep(wait_time)
                self._refill()
            self.tokens -= 1.0

    def _refill(self):
        now = time.time()
        delta = (now - self.last_refill) * self.rate
        self.tokens = min(self.capacity, self.tokens + delta)
        self.last_refill = now

class CircuitBreaker:
    """
    Implements CLOSED -> OPEN -> HALF-OPEN cycle.
    Prevents execution on targets that are unresponsive or protected by aggressive WAFs.
    """
    def __init__(self, failure_threshold=5, cooldown_seconds=300):
        self.failure_threshold = failure_threshold
        self.cooldown = cooldown_seconds
        self.failures = 0
        self.state = 'CLOSED'
        self.last_failure_time = 0

    def is_open(self):
        if self.state == 'OPEN':
            if time.time() - self.last_failure_time > self.cooldown:
                self.state = 'HALF-OPEN'
                logger.info("CircuitBreaker state: HALF-OPEN")
                return False
            return True
        return False

    def record_success(self):
        if self.state != 'CLOSED':
            logger.info(f"CircuitBreaker state: CLOSED (Success recovered)")
        self.failures = 0
        self.state = 'CLOSED'

    def record_failure(self):
        self.failures += 1
        self.last_failure_time = time.time()
        if self.failures >= self.failure_threshold:
            self.state = 'OPEN'
            logger.warning(f"CircuitBreaker state: OPEN (Threshold {self.failure_threshold} reached)")

class AsyncOrchestrator:
    """
    Central orchestration engine for modular Red Team operations.
    Manages priorities, rate limits, and tactical path fallbacks.
    """
    def __init__(self, worker_count=10):
        self.priority_queue = asyncio.PriorityQueue()
        self.rate_limiters = collections.defaultdict(lambda: TokenBucket(rate=1, capacity=5)) 
        self.circuit_breakers = collections.defaultdict(lambda: CircuitBreaker())
        self.results = {}
        self.worker_count = worker_count
        self.running = False
        self._loop = None

    async def _worker(self, worker_id):
        logger.debug(f"Worker {worker_id} initialized.")
        while self.running:
            try:
                # Fetch next tactical node from priority queue
                priority, node = await asyncio.wait_for(self.priority_queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            target = node.get_target_host()
            limiter = self.rate_limiters[target]
            breaker = self.circuit_breakers[target]

            if breaker.is_open():
                logger.warning(f"Target {target} suspended by CircuitBreaker. Skipping node {node.id}.")
                self.priority_queue.task_done()
                continue

            await limiter.acquire()

            try:
                logger.info(f"Worker {worker_id} executing tactical module: {node.id} on {target}")
                result = await asyncio.wait_for(node.execute(), timeout=node.timeout)
                self.results[node.id] = result
                breaker.record_success()
                
                # Signal completion to offspring nodes in the AttackDAG
                await node.signal_success(self.priority_queue)
                
            except Exception as e:
                logger.error(f"Execution failed for {node.id}: {e}")
                breaker.record_failure()
                await node.signal_failure(self.priority_queue)
            finally:
                self.priority_queue.task_done()

    async def run(self, dag):
        """Orchestrate the execution of an AttackDAG."""
        self.running = True
        self._loop = asyncio.get_running_loop()
        
        # Load initially ready nodes (the roots of the DAG)
        ready_nodes = dag.get_ready_nodes()
        for node in ready_nodes:
            await self.priority_queue.put((node.priority, node))

        # Spawn operational workers
        workers = [asyncio.create_task(self._worker(i)) for i in range(self.worker_count)]
        
        # Await completion of all tasks in the queue
        await self.priority_queue.join()
        
        self.running = False
        for w in workers:
            w.cancel()
        
        logger.info("Operational cycle complete. Results aggregated.")
        return self.results
