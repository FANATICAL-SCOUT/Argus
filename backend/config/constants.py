"""Static constants shared across the package."""

# Default scan parameters
DEFAULT_START_PORT: int = 1
DEFAULT_END_PORT: int = 1024
DEFAULT_TIMEOUT: float = 1.0
DEFAULT_THREADS: int = 100
DEFAULT_DECOYS: int = 5

# Common well-known ports (used for service-name heuristics)
HTTP_PORTS = (80, 8080)
HTTPS_PORTS = (443, 8443)
SMB_PORTS = (139, 445)

# Risk levels used by the web dashboard
RISK_LEVELS = ("Critical", "High", "Medium", "Low", "Info")
