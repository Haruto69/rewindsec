"""RewindSec 2.0 isolated technical-state boundary.

The deterministic domain never imports this package.  A workstation service may
be given the narrow port exposed here; Docker remains an operational projection
of already-persisted synthetic file facts, never a source of simulation truth.
"""

from .coordinator import SandboxCoordinator
from .docker_adapter import DockerSandboxAdapter, DockerSandboxConfig
from .ports import (SandboxConfigurationError, SandboxOperationalError,
                    SandboxPort, SandboxProjection, SyntheticFileState)

__all__ = [
    "DockerSandboxAdapter", "DockerSandboxConfig", "SandboxConfigurationError",
    "SandboxCoordinator", "SandboxOperationalError", "SandboxPort",
    "SandboxProjection", "SyntheticFileState",
]
