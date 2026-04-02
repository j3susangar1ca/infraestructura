#
# 🛡️ C4ISR-STRATCOM: SIGINT-V5
# [CLASSIFIED]: CONFIDENCIAL
# [SCOPE]: OPD HCG (CONV-0221-JAL-HCG-2026)
# [MODULE]: STRATCOM Python CTI Abstraction Layer
#

import json
import os

JSON_PATH = os.path.join(os.path.dirname(__file__), "..", "01_TARGET_INTELLIGENCE", "hcg_infraestructure.json")

class CTIResolver:
    def __init__(self):
        self.data = None
        self._load()

    def _load(self):
        try:
            with open(JSON_PATH, "r", encoding="utf-8") as f:
                self.data = json.load(f)
        except Exception as e:
            print(f"[!] Error loading CTI data: {e}")
            self.data = {}

    def get_server_ip(self, server_id):
        if not self.data: return None
        for srv in self.data.get("servers", []):
            if srv.get("server_id") == server_id:
                ips = srv.get("ips", [])
                return ips[0] if ips else None
        return None

if __name__ == "__main__":
    resolver = CTIResolver()
    print("SRV-015 IP:", resolver.get_server_ip("SRV-015"))
