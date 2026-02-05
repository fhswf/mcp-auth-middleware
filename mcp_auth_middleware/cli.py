#!/usr/bin/env python3
"""MCP Secrets CLI - Key management for JWE authentication."""

import argparse
import base64
import json
import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

try:
    from jwcrypto import jwk
except ImportError:
    print("Error: 'jwcrypto' library is required.", file=sys.stderr)
    print("Please run: pip install jwcrypto", file=sys.stderr)
    sys.exit(1)

KEY_SIZE = 4096
KEY_FILES = ("mcp-private.json", "mcp-public.json")


def generate_keys(output_dir: Path) -> tuple[Path, Path]:
    """Generate an RSA JWKS key pair and write to output_dir."""
    output_dir.mkdir(parents=True, exist_ok=True)

    key = jwk.JWK.generate(kty="RSA", size=KEY_SIZE)
    key["kid"] = key.thumbprint()

    private_jwks = {"keys": [json.loads(key.export_private())]}
    public_jwks = {"keys": [json.loads(key.export_public())]}

    private_key_path = output_dir / "mcp-private.json"
    public_key_path = output_dir / "mcp-public.json"

    with open(private_key_path, "w") as f:
        json.dump(private_jwks, f, indent=2)

    try:
        os.chmod(private_key_path, 0o600)
    except OSError:
        pass

    with open(public_key_path, "w") as f:
        json.dump(public_jwks, f, indent=2)

    return private_key_path, public_key_path


def secure_delete(file_path: Path) -> None:
    """Securely delete a file using shred or overwrite fallback."""
    if not file_path.exists():
        return

    if shutil.which("shred"):
        subprocess.run(
            ["shred", "--remove", "--zero", "--iterations=3", str(file_path)],
            check=True,
        )
        return

    try:
        size = file_path.stat().st_size
        with open(file_path, "r+b") as f:
            f.write(secrets.token_bytes(size))
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass

    file_path.unlink()


def clean_keys(key_dir: Path) -> list[str]:
    """Remove key files from key_dir. Returns list of removed paths."""
    removed = []
    for name in KEY_FILES:
        key_file = key_dir / name
        if not key_file.exists():
            continue

        if "private" in name:
            secure_delete(key_file)
        else:
            key_file.unlink()

        removed.append(str(key_file))
    return removed


def cmd_generate(args: argparse.Namespace) -> None:
    output_dir = args.output.resolve()
    private_key, public_key = generate_keys(output_dir)

    print(f"Keys generated (JWKS format):")
    print(f"  Private: {private_key}")
    print(f"  Public:  {public_key}")
    print(f"\nFor local development, add to .env:")
    print(f"  MCP_KEY_FILE_PATH={private_key}")
    print(f"\nAdd to .gitignore:")
    print(f"  .keys/")


def cmd_k8s(args: argparse.Namespace) -> None:
    output_dir = args.output.resolve()
    private_key, _ = generate_keys(output_dir)

    with open(private_key, "rb") as f:
        b64_key = base64.b64encode(f.read()).decode("utf-8")

    k8s_yaml = f"""\
apiVersion: v1
kind: Secret
metadata:
  name: {args.secret_name}
  namespace: {args.namespace}
type: Opaque
data:
  mcp_jwks: {b64_key}
"""
    print(k8s_yaml)
    print(f"# Apply: mcp-secrets k8s | kubectl apply -f -", file=sys.stderr)
    print(f"# Then clean local keys: mcp-secrets clean", file=sys.stderr)


def cmd_clean(args: argparse.Namespace) -> None:
    removed = clean_keys(args.output.resolve())
    if removed:
        print("Removed:\n  " + "\n  ".join(removed))
    else:
        print(f"No keys found in {args.output}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="mcp-secrets", description="MCP Secrets - Key Management (JWKS)"
    )
    subs = parser.add_subparsers(dest="command", required=True)

    commands = [
        ("generate", "Generate RSA JWKS key pair", cmd_generate),
        ("k8s", "Generate keys and output Kubernetes secret YAML", cmd_k8s),
        ("clean", "Remove keys securely", cmd_clean),
    ]

    for name, help_text, handler in commands:
        p = subs.add_parser(name, help=help_text)
        p.add_argument(
            "-o",
            "--output",
            type=Path,
            default=Path(".keys"),
            help="Key directory (default: .keys)",
        )
        p.set_defaults(func=handler)

    k8s = subs.choices["k8s"]
    k8s.add_argument(
        "-n", "--namespace", default="default", help="Kubernetes namespace"
    )
    k8s.add_argument(
        "-s", "--secret-name", default="mcp-server-keys", help="Secret name"
    )

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
