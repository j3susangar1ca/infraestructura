#
# 🛡️ C4ISR-STRATCOM: SIGINT-V5
# [CLASSIFIED]: CONFIDENCIAL
# [SCOPE]: OPD HCG (CONV-0221-JAL-HCG-2026)
# [TACTIC]: TA0004_Priv_Escalation
# [TECHNIQUE]: T1068_Exploitation_for_Priv_Escalation
#
# Exploit Title: PolicyKit-1 0.105-31 - Privilege Escalation (PwnKit)
# Exploit Author: Lance Biggerstaff
# Original Author: ryaagard (https://github.com/ryaagard)
# CVE ID: CVE-2021-4034
# Date: 27-01-2022
# Github Repo: https://github.com/ryaagard/CVE-2021-4034
# References: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
#
# Description:
# The exploit consists of three source files: Makefile, evil-so.c, and exploit.c.
# It exploits a memory corruption vulnerability in polkit's pkexec to gain
# full root privileges on Linux systems.

[+] Build:
    Run 'make' to compile the shared object (evil.so) and the exploit binary.

[+] Usage:
    Run './exploit' to execute the attack. If successful, you will receive a root shell.

[+] Clean:
    Run 'make clean' to remove temporary directories and binaries.
