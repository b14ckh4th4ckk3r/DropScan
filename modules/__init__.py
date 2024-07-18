# modules/__init__.py

from .network import resolve_domain_to_ip, run_nmap_scan, print_scan_results, search_cve_by_cpe
from .sql_injection import scan_sql_injection
from .xss import scan_xss
from .rce import remote_code_execution
from .security_misconfig import security_misconfiguration
from .broken_authentication import broken_auth
from .csrf import csrf_scan
