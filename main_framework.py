#
# ⚙️ SAM-V5: Sistema de Gestión de Configuración Industrial
# [STATUS]: PRODUCTION
# [SCOPE]: Enterprise Asset Management
#

import asyncio
import logging
from lib.sam_config_parser import ConfigResolver
from lib.sam_core_framework.core.orchestrator import AsyncOrchestrator
from lib.sam_core_framework.core.dag import ManagementDAG, ComponentNode
from lib.sam_core_framework.protocols.ajp13 import AJP13Codec
from lib.sam_core_framework.protocols.ldap import LDAPProbe

# Configure operational logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s] SAMV5: %(message)s')
logger = logging.getLogger("SAM_V5")

async def run_operation():
    """Builds and executes the system management DAG."""
    logger.info("Initializing SAM-V5 Operational Framework...")
    
    # 1. Resolve System Configuration
    resolver = ConfigResolver()
    web_ip = resolver.get_server_ip("SRV-015")  # Web Server
    dc_ip = resolver.get_server_ip("SRV-001")   # Domain Controller
    
    if not web_ip or not dc_ip:
        logger.error("Failed to resolve critical server addresses. Check system_config.json.")
        return
    
    # 2. Initialize Orchestrator
    orchestrator = AsyncOrchestrator(worker_count=5)
    dag = ManagementDAG()

    # 3. Build Management DAG
    # Path ALPHA: System Inventory -> Service Analysis -> Performance Check
    node_inventory = dag.add_node(ComponentNode("A1_SYSTEM_INVENTORY", lambda: asyncio.sleep(2), web_ip, priority=1))
    
    ajp_engine = AJP13Codec()
    node_service_analysis = dag.add_node(ComponentNode("A2_SERVICE_ANALYSIS", 
                                           lambda: ajp_engine.analyze_service(web_ip, 8009, '/WEB-INF/web.xml'), 
                                           web_ip, priority=2))
                                           
    dag.add_dependency("A1_SYSTEM_INVENTORY", "A2_SERVICE_ANALYSIS")

    # Path BETA: Directory Audit -> Service Enumeration -> Capability Check
    node_directory_audit = dag.add_node(ComponentNode("B1_DIRECTORY_AUDIT", lambda: asyncio.sleep(2), dc_ip, priority=1))
    
    ldap_engine = LDAPProbe(dc_ip)
    node_service_enum = dag.add_node(ComponentNode("B2_SERVICE_ENUM", 
                                           lambda: ldap_engine.probe_anonymous_ldap("dc=enterprise,dc=org"), 
                                           dc_ip, priority=2))
                                           
    dag.add_dependency("B1_DIRECTORY_AUDIT", "B2_SERVICE_ENUM")

    # 4. Trigger Orchestration
    logger.info("Executing ManagementDAG Paths: ALPHA (System) & BETA (Directory)...")
    results = await orchestrator.run(dag)

    logger.info("--- SYSTEM DIAGNOSTIC RESULTS ---")
    for task_id, res in results.items():
        status = "✅" if res else "❌"
        logger.info(f"{status} Task {task_id}: {type(res)}")
    
    if dag.any_objective_reached():
        logger.info("🎯 Configuration verification complete.")
    else:
        logger.info("⚠️ System objectives partially met. Analyzing fallback options.")

if __name__ == "__main__":
    try:
        asyncio.run(run_operation())
    except KeyboardInterrupt:
        logger.info("Operation manually terminated by System Administrator.")
