import argparse
import base64
import json
import sys
import types
from pathlib import Path

import mcp_auth_middleware.cli as cli


class FakeJWK(dict):
    @classmethod
    def generate(cls, kty: str, size: int):
        inst = cls()
        inst["kty"] = kty
        inst["size"] = size
        return inst

    def thumbprint(self) -> str:
        return "thumbprint"

    def export_private(self) -> str:
        return json.dumps({"kty": "RSA", "kid": self["kid"], "private": True})

    def export_public(self) -> str:
        return json.dumps({"kty": "RSA", "kid": self["kid"]})


def test_generate_keys_writes_jwks_files(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(cli, "jwk", types.SimpleNamespace(JWK=FakeJWK))

    private_path, public_path = cli.generate_keys(tmp_path)

    assert private_path.exists()
    assert public_path.exists()
    assert json.loads(private_path.read_text())["keys"][0]["kid"] == "thumbprint"
    assert json.loads(public_path.read_text())["keys"][0]["kid"] == "thumbprint"


def test_secure_delete_uses_shred(monkeypatch, tmp_path) -> None:
    file_path = tmp_path / "secret.txt"
    file_path.write_text("secret")

    called = {}

    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/shred")

    def fake_run(cmd, check):
        called["cmd"] = cmd
        called["check"] = check

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    cli.secure_delete(file_path)

    assert called["cmd"][0] == "shred"
    assert called["check"] is True


def test_secure_delete_fallback_removes_file(monkeypatch, tmp_path) -> None:
    file_path = tmp_path / "secret.txt"
    file_path.write_text("secret")

    monkeypatch.setattr(cli.shutil, "which", lambda name: None)

    cli.secure_delete(file_path)

    assert not file_path.exists()


def test_clean_keys_removes_private_and_public(monkeypatch, tmp_path) -> None:
    private_key = tmp_path / "mcp-private.json"
    public_key = tmp_path / "mcp-public.json"
    private_key.write_text("private")
    public_key.write_text("public")

    deleted = []

    def fake_secure_delete(path: Path) -> None:
        deleted.append(path)
        path.unlink()

    monkeypatch.setattr(cli, "secure_delete", fake_secure_delete)

    removed = cli.clean_keys(tmp_path)

    assert str(private_key) in removed
    assert str(public_key) in removed
    assert deleted == [private_key]
    assert not private_key.exists()
    assert not public_key.exists()


def test_cmd_k8s_prints_secret(monkeypatch, tmp_path, capsys) -> None:
    private_key = tmp_path / "mcp-private.json"
    private_key.write_bytes(b"secret")

    def fake_generate_keys(output_dir: Path):
        return private_key, tmp_path / "mcp-public.json"

    monkeypatch.setattr(cli, "generate_keys", fake_generate_keys)

    args = argparse.Namespace(output=tmp_path, namespace="dev", secret_name="mcp-key")
    cli.cmd_k8s(args)

    captured = capsys.readouterr()
    expected_b64 = base64.b64encode(b"secret").decode("utf-8")

    assert "kind: Secret" in captured.out
    assert "name: mcp-key" in captured.out
    assert "namespace: dev" in captured.out
    assert expected_b64 in captured.out


def test_cmd_generate_prints_paths(monkeypatch, tmp_path, capsys) -> None:
    private_key = tmp_path / "private.json"
    public_key = tmp_path / "public.json"

    def fake_generate_keys(output_dir: Path):
        return private_key, public_key

    monkeypatch.setattr(cli, "generate_keys", fake_generate_keys)

    args = argparse.Namespace(output=tmp_path)
    cli.cmd_generate(args)

    output = capsys.readouterr().out

    assert str(private_key) in output
    assert str(public_key) in output
    assert "MCP_KEY_FILE_PATH" in output


def test_cmd_clean_prints_removed(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setattr(cli, "clean_keys", lambda path: [str(path / "mcp-private.json")])

    args = argparse.Namespace(output=tmp_path)
    cli.cmd_clean(args)

    output = capsys.readouterr().out

    assert "Removed:" in output


def test_main_dispatches_generate(monkeypatch, tmp_path) -> None:
    called = {}

    def fake_cmd_generate(args):
        called["args"] = args

    monkeypatch.setattr(cli, "cmd_generate", fake_cmd_generate)
    monkeypatch.setattr(sys, "argv", ["mcp-secrets", "generate", "-o", str(tmp_path)])

    cli.main()

    assert called["args"].output == Path(str(tmp_path))
