"""Secret reference resolver for multiple secret managers and sources.

Supports resolving secrets from:
- env:NAME or ${NAME}
- file:/path/to/secret
- op://<vault>/<item>/<field> via 1Password CLI (`op read`)
- aws-sm://[region/]secret_id[#json_key] via AWS CLI
- vault://path[#field] via HashiCorp Vault CLI
- sops://path[#json.key] via SOPS CLI (expects JSON; YAML not supported)

Notes:
- This module shells out to CLIs if present. It does not manage login flows.
- It avoids logging or printing secret values. Errors are concise.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Optional

_ENV_PATTERN = re.compile(r"^\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)\}$")


def _sh(cmd: list[str], env: Optional[dict] = None) -> str:
    """Run a command and return stdout as text (stripped)."""
    result = subprocess.run(cmd, capture_output=True, text=True, env=env, check=False)
    if result.returncode != 0:
        # Don't include stdout/stderr as it may contain sensitive info
        head = " ".join(shlex.quote(c) for c in cmd[:2])
        raise RuntimeError(f"Command failed: {head} ... (exit {result.returncode})")
    return result.stdout.strip()


def is_reference(value: str | None) -> bool:
    """Return True if the string looks like a secret reference.

    Supports env/file/op/aws-sm/vault/sops schemes or ${ENV} syntax.
    """
    if not value:
        return False
    return value.startswith(("env:", "file:", "op://", "aws-sm://", "vault://", "sops://")) or bool(
        _ENV_PATTERN.match(value)
    )


def resolve_secret(value: Optional[str]) -> Optional[str]:
    """Resolve a secret value or reference.

    Returns the original value when it is not a supported reference.
    Returns None when input is None or empty string.
    Raises RuntimeError on explicit reference failures.
    """
    if value is None:
        return None
    value = str(value)
    if value == "":
        return None

    # ${ENV} syntax
    m = _ENV_PATTERN.match(value)
    if m:
        return os.getenv(m.group("name"))

    # env:NAME
    if value.startswith("env:"):
        name = value.split(":", 1)[1]
        return os.getenv(name)

    # file:/path or file:relative
    if value.startswith("file:"):
        path = value.split(":", 1)[1]
        p = Path(path)
        data = p.read_text(encoding="utf-8")
        return data.rstrip("\n")

    # 1Password: op://vault/item/field
    if value.startswith("op://"):
        # Use op read which supports secret references directly
        return _sh(["op", "read", value])

    # AWS Secrets Manager: aws-sm://[region/]secret_id[#json_key]
    if value.startswith("aws-sm://"):
        body = value[len("aws-sm://") :]
        region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
        if "/" in body and not body.startswith("/"):
            # Potentially region/secret_id...
            maybe_region, rest = body.split("/", 1)
            if maybe_region and "." in maybe_region or maybe_region.count("-") >= 2:
                region = maybe_region
                body = rest
        secret_id, _, key = body.partition("#")
        if not secret_id:
            raise RuntimeError("aws-sm reference missing secret_id")
        cmd = [
            "aws",
            "secretsmanager",
            "get-secret-value",
            "--secret-id",
            secret_id,
            "--query",
            "SecretString",
            "--output",
            "text",
        ]
        if region:
            cmd += ["--region", region]
        secret = _sh(cmd)
        if key:
            try:
                obj = json.loads(secret)
            except json.JSONDecodeError as e:
                raise RuntimeError(f"aws-sm secret is not JSON (needed for key '{key}')") from e
            if key not in obj:
                raise RuntimeError(f"aws-sm key '{key}' not found in secret")
            return str(obj[key])
        return secret

    # HashiCorp Vault: vault://path[#field] (KV v2 preferred)
    if value.startswith("vault://"):
        spec = value[len("vault://") :]
        path, _, field = spec.partition("#")
        if field:
            # vault kv get -field=FIELD path
            return _sh(["vault", "kv", "get", f"-field={field}", path])
        else:
            # Try to fetch JSON and best-effort pick data.data or data
            raw = _sh(["vault", "kv", "get", "-format=json", path])
            try:
                obj = json.loads(raw)
                data = obj.get("data", {})
                # KV v2 nests under data.data
                if isinstance(data, dict) and "data" in data and isinstance(data["data"], dict):
                    return json.dumps(data["data"])  # Caller can parse
                return json.dumps(data)
            except Exception:
                return raw

    # SOPS: sops://path[#json.key]
    if value.startswith("sops://"):
        spec = value[len("sops://") :]
        path, _, pointer = spec.partition("#")
        dec = _sh(["sops", "-d", "-o", "/dev/stdout", path])
        if not pointer:
            return dec
        try:
            obj = json.loads(dec)
        except json.JSONDecodeError as e:
            raise RuntimeError("sops decrypted data is not JSON; use a JSON file or omit #key") from e
        # Support dot.notation path
        cur = obj
        for part in pointer.split("."):
            if not part:
                continue
            if not isinstance(cur, dict) or part not in cur:
                raise RuntimeError(f"sops key '{pointer}' not found")
            cur = cur[part]
        return cur if isinstance(cur, str) else json.dumps(cur)

    # Not a reference; return as-is
    return value


def set_env_if_ref(env: dict, var: str, value: Optional[str]) -> Optional[str]:
    """If `value` is a reference or non-empty literal, resolve and set env[var].

    Returns the resolved secret or None if not set.
    """
    if value is None:
        return None
    resolved = resolve_secret(value)
    if resolved is not None:
        env[var] = str(resolved)
    return resolved
