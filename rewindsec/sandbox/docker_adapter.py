"""Docker CLI adapter for the narrow RewindSec 2.0 sandbox port.

All calls use argument arrays with ``shell=False``.  The public surface accepts
only typed projections or a one-way session key; it has no command, path,
mount, network, privilege, binary, URL, or container-name parameter.
"""

from dataclasses import dataclass
import json
import re
import shutil
import subprocess

from .ports import (SandboxConfigurationError, SandboxOperationalError,
                    SandboxPort)

DEFAULT_IMAGE = "rewindsec2-ransomware-sandbox:2.0"
CONTAINER_PREFIX = "rewindsec2-rw-"
OWNER_LABEL = "com.rewindsec.sandbox=2.0"
SESSION_LABEL = "com.rewindsec.session"
_KEY = re.compile(r"^[0-9a-f]{32}$")


@dataclass(frozen=True)
class DockerSandboxConfig:
    image: str = DEFAULT_IMAGE
    network: str = "none"
    user: str = "10001:10001"
    read_only: bool = True
    cap_drop: tuple = ("ALL",)
    no_new_privileges: bool = True
    privileged: bool = False
    mounts: tuple = ()
    tmpfs: str = "/workspace:rw,noexec,nosuid,nodev,uid=10001,gid=10001,size=8m"
    memory: str = "64m"
    pids: int = 32
    cpus: str = "0.50"
    timeout_seconds: int = 45

    def __post_init__(self):
        if self.network != "none" or self.user != "10001:10001":
            raise SandboxConfigurationError("network and numeric user are fixed")
        if not self.read_only or self.cap_drop != ("ALL",):
            raise SandboxConfigurationError("read-only root and cap-drop ALL are required")
        if not self.no_new_privileges or self.privileged or self.mounts:
            raise SandboxConfigurationError("unsafe privilege or mount configuration refused")
        required = ("/workspace:", "noexec", "nosuid", "nodev", "size=8m")
        if any(part not in self.tmpfs for part in required):
            raise SandboxConfigurationError("the bounded hardened tmpfs is fixed")
        if self.memory != "64m" or self.pids != 32 or self.cpus != "0.50":
            raise SandboxConfigurationError("resource bounds are fixed")
        if not isinstance(self.timeout_seconds, int) or not 1 <= self.timeout_seconds <= 120:
            raise SandboxConfigurationError("invalid Docker timeout")
        if not isinstance(self.image, str) or not self.image or len(self.image) > 200:
            raise SandboxConfigurationError("invalid image reference")


class DockerSandboxAdapter(SandboxPort):
    def __init__(self, config=None, docker_binary="docker"):
        self.config = config or DockerSandboxConfig()
        self.docker_binary = docker_binary

    @staticmethod
    def _validate_key(session_key):
        if not isinstance(session_key, str) or not _KEY.fullmatch(session_key):
            raise SandboxOperationalError("invalid sandbox session key")
        return session_key

    def _name(self, session_key):
        return CONTAINER_PREFIX + self._validate_key(session_key)

    def _run(self, args, input_text=None, check=True):
        try:
            completed = subprocess.run(
                [self.docker_binary] + list(args), input=input_text,
                capture_output=True, text=True, shell=False,
                timeout=self.config.timeout_seconds, check=False)
        except FileNotFoundError as exc:
            raise SandboxOperationalError("Docker CLI is unavailable") from exc
        except subprocess.TimeoutExpired as exc:
            raise SandboxOperationalError("bounded Docker operation timed out") from exc
        if check and completed.returncode != 0:
            # Deliberately does not expose command lines, container names, or
            # raw daemon output to callers.
            raise SandboxOperationalError(
                "Docker sandbox operation failed with exit %d" % completed.returncode)
        return completed

    def is_available(self):
        if shutil.which(self.docker_binary) is None:
            return False
        return self._run(["info", "--format", "{{.ServerVersion}}"],
                         check=False).returncode == 0

    def image_available(self):
        return self._run(["image", "inspect", "--", self.config.image],
                         check=False).returncode == 0

    def _owned_inspect(self, session_key):
        name = self._name(session_key)
        result = self._run(["inspect", "--format", "{{json .}}", "--", name],
                           check=False)
        if result.returncode != 0:
            return None
        try:
            doc = json.loads(result.stdout)
        except ValueError as exc:
            raise SandboxOperationalError("Docker inspect returned malformed state") from exc
        labels = ((doc.get("Config") or {}).get("Labels") or {})
        if labels.get("com.rewindsec.sandbox") != "2.0" \
                or labels.get(SESSION_LABEL) != session_key:
            raise SandboxOperationalError("container name is not owned by this session")
        return doc

    def _create(self, session_key):
        name = self._name(session_key)
        if not self.is_available():
            raise SandboxOperationalError("Docker daemon is unavailable")
        if not self.image_available():
            raise SandboxOperationalError("RewindSec 2.0 sandbox image is missing")
        self._run([
            "run", "--detach", "--pull", "never", "--name", name,
            "--network", self.config.network,
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--read-only", "--tmpfs", self.config.tmpfs,
            "--user", self.config.user, "--memory", self.config.memory,
            "--pids-limit", str(self.config.pids), "--cpus", self.config.cpus,
            "--label", OWNER_LABEL,
            "--label", "%s=%s" % (SESSION_LABEL, session_key),
            self.config.image,
        ])

    def reconcile(self, projection):
        session_key = self._validate_key(projection.session_key)
        existing = self._owned_inspect(session_key)
        if existing is None:
            self._create(session_key)
        elif (existing.get("State") or {}).get("Running") is not True:
            self.destroy(session_key)
            self._create(session_key)

        payload = json.dumps(projection.to_state(), sort_keys=True,
                             separators=(",", ":"))
        result = self._run([
            "exec", "--interactive", "--", self._name(session_key),
            "python", "/opt/rewindsec2/runner.py", "reconcile",
        ], input_text=payload)
        try:
            observed = json.loads(result.stdout)
        except ValueError as exc:
            raise SandboxOperationalError("sandbox returned malformed state") from exc
        if not isinstance(observed, dict):
            raise SandboxOperationalError("sandbox returned malformed state")
        return observed

    def inspect(self, session_key):
        self._validate_key(session_key)
        if self._owned_inspect(session_key) is None:
            return {"session_key": session_key, "state": "absent"}
        result = self._run([
            "exec", "--", self._name(session_key), "python",
            "/opt/rewindsec2/runner.py", "inspect", session_key,
        ])
        try:
            return json.loads(result.stdout)
        except ValueError as exc:
            raise SandboxOperationalError("sandbox returned malformed state") from exc

    def destroy(self, session_key):
        self._validate_key(session_key)
        owned = self._owned_inspect(session_key)
        if owned is None:
            return {"session_key": session_key, "state": "absent"}
        self._run(["rm", "--force", "--", self._name(session_key)])
        return {"session_key": session_key, "state": "absent"}

    def list_owned(self):
        result = self._run([
            "ps", "--all", "--filter", "label=" + OWNER_LABEL,
            "--format", "{{.Names}}",
        ], check=False)
        if result.returncode != 0:
            raise SandboxOperationalError("could not enumerate owned sandboxes")
        out = []
        for name in result.stdout.splitlines():
            if not name.startswith(CONTAINER_PREFIX):
                continue
            key = name[len(CONTAINER_PREFIX):]
            if _KEY.fullmatch(key):
                # A matching prefix is not enough: verify both strict labels.
                if self._owned_inspect(key) is not None:
                    out.append(key)
        return tuple(sorted(out))
