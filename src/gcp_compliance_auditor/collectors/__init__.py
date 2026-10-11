"""Read-only data collectors for compliance scans."""

from .gcp import (
    GCPAPIError,
    GCPAuthenticationError,
    GCPCollector,
    GCPCollectorError,
    GCPDependencyError,
    collect_gcp_snapshot,
)

__all__ = [
    "GCPAPIError",
    "GCPAuthenticationError",
    "GCPCollector",
    "GCPCollectorError",
    "GCPDependencyError",
    "collect_gcp_snapshot",
]
