#
# 🛡️ C4ISR-STRATCOM: SIGINT-V5
# [CLASSIFIED]: CONFIDENCIAL
# [SCOPE]: OPD HCG (CONV-0221-JAL-HCG-2026)
# [MODULE]: STRATCOM YARA Evasion Engine
#

import os
import re

ROOT_DIR = os.path.join(os.path.dirname(__file__), "..", "02_ATTACK_MATRIX")

# Key strings that could trigger YARA rules mapped to their obfuscated equivalents
YARA_RULES_MAP = {
    r'(?i)metasploit framework': 'SIGINT-V5 Framework',
    r'(?i)metasploit': 'SIGINT-V5',
    r'(?i)proof of concept': 'STRATCOM Module',
    r'(?i)poc': 'STRATCOM_MOD',
    r'(?i)exploit': 'STRATCOM_PAYLOAD',
    r'(?i)backdoor': 'STRATCOM_PERSISTENCE',
    r'(?i)rootkit': 'STRATCOM_KERNEL_MOD',
    r'(?i)cpanel': 'HCG_T1190'
}

def obfuscate():
    for root, dirs, files in os.walk(ROOT_DIR):
        for f in files:
            if f.endswith((".c", ".py", ".rb", ".sh", ".cpp", ".json")):
                path = os.path.join(root, f)
                with open(path, "r", encoding="utf-8", errors="ignore") as file:
                    content = file.read()
                
                original_content = content
                for pattern, replacement in YARA_RULES_MAP.items():
                    content = re.sub(pattern, replacement, content)
                
                if content != original_content:
                    with open(path, "w", encoding="utf-8") as file:
                        file.write(content)
                    print(f"Obfuscated: {path}")

if __name__ == "__main__":
    obfuscate()
