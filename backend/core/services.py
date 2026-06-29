"""Service name lookup utilities."""
import socket


def get_service_name(port: int) -> str:
    """Return the IANA service name for a port, or 'unknown'."""
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"
