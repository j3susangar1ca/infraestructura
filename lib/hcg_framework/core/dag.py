#
# 🛡️ C4ISR-STRATCOM-IMPLANT-SIGINT-V5: Attack Directed Acyclic Graph
# [CLASSIFIED]: CONFIDENCIAL
# [MODULE]: AttackDAG
#

import asyncio
import logging

logger = logging.getLogger("SIGINT_V5")

class AttackNode:
    """
    Represents a single tactical step in the Attack Matrix.
    """
    def __init__(self, id, action, target, priority=5, timeout=300, 
                 is_objective=False, prereq_check=None):
        self.id = id
        self.action = action  # An awaitable function or object with execute()
        self.target = target
        self.priority = priority
        self.timeout = timeout
        self.is_objective = is_objective
        self.prereq_check = prereq_check
        
        self.children = []
        self.dependencies = []
        self.remaining_deps = 0
        self.reached_objective = False
        self.status = "PENDING"  # PENDING, RUNNING, SUCCESS, FAILURE, SKIPPED

    def get_target_host(self):
        return self.target

    async def execute(self):
        self.status = "RUNNING"
        if self.prereq_check:
            if not await self.prereq_check():
                self.status = "SKIPPED"
                raise Exception(f"Prerequisite check failed for {self.id}")
        
        # Action is expected to be an awaitable or a callable that returns an awaitable
        if asyncio.iscoroutinefunction(self.action):
            result = await self.action()
        elif hasattr(self.action, 'execute'):
            result = await self.action.execute()
        else:
            result = self.action()
            
        self.status = "SUCCESS"
        if self.is_objective:
            self.reached_objective = True
            logger.info(f"🎯 OBJECTIVE REACHED: {self.id}")
        return result

    async def signal_success(self, queue):
        """Notifies children that a dependency has been met."""
        for child in self.children:
            child.remaining_deps -= 1
            if child.remaining_deps == 0:
                logger.debug(f"Dependency met for child: {child.id}")
                await queue.put((child.priority, child))

    async def signal_failure(self, queue):
        """Handles path failure and potential fallbacks."""
        self.status = "FAILURE"
        # In a real scenario, we might trigger alternative paths here
        logger.warning(f"Tactical node {self.id} failed. Checking for fallbacks...")

class AttackDAG:
    """
    Manages the lifecycle and dependencies of a complex attack campaign.
    """
    def __init__(self):
        self.nodes = {}

    def add_node(self, node):
        self.nodes[node.id] = node
        return node

    def add_dependency(self, parent_id, child_id):
        if parent_id not in self.nodes or child_id not in self.nodes:
            raise ValueError(f"Nodes {parent_id} and {child_id} must be added first.")
        
        parent = self.nodes[parent_id]
        child = self.nodes[child_id]
        
        if child not in parent.children:
            parent.children.append(child)
            child.dependencies.append(parent)
            child.remaining_deps += 1
            logger.debug(f"Dependency added: {parent_id} -> {child_id}")

    def get_ready_nodes(self):
        """Returns nodes that have no unmet dependencies."""
        return [n for n in self.nodes.values() if n.remaining_deps == 0 and n.status == "PENDING"]

    def any_objective_reached(self):
        return any(n.reached_objective for n in self.nodes.values() if n.is_objective)
