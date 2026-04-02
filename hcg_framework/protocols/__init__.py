"""
🛡️ HCG Framework - Protocol Implementation Layer
[CLASSIFIED]: CONFIDENTIAL - HCG Red Team Operation
[SCOPE]: OPD Hospital Civil de Guadalajara (CONV-0221-JAL-HCG-2026)

Protocol handlers for AJP13, LDAP, SMB with byte-level control.
"""

from .ajp13 import AJP13Codec
from .ldap import LDAPProbe
from .smb import SMBHandler

__all__ = ['AJP13Codec', 'LDAPProbe', 'SMBHandler']
