import io
import os
import subprocess
import tarfile
from pathlib import Path

import pytest

from backup_rotation.cli import main
from backup_rotation.core import CheckFailed, LocalDirCloud, LocalDirRemote, Rotator


def make_backup(path: Path, content: bytes) -> None:
    with tarfile.open(path, "w:gz") as t:
        info = tarfile.TarInfo("homedir/file.txt")
        info.size = len(content)
        t.addfile(info, io.BytesIO(content))


@pytest.fixture
def env(tmp_path):
    host, local, cloud = tmp_path / "host", tmp_path / "local", tmp_path / "cloud"
    host.mkdir(); local.mkdir()
    for i, day in enumerate(["2026-01-01", "2026-01-08", "2026-01-15"]):
        make_backup(host / f"backup-{day}.tar.gz", f"data {i}".encode() * 100)
    pw = tmp_path / "pass"
    pw.write_text("example-test-passphrase")
    pw.chmod(0o600)
    cfg = tmp_path / "rotation.ini"
    cfg.write_text(f"""[remote]
type = local
path = {host}
retry_wait = 0
[local]
path = {local}
[cloud]
type = local
path = {cloud}
[encryption]
iterations = 1000
passphrase_source = file
passphrase_file = {pw}
""")
    return host, local, cloud, cfg, pw


def names(d):
    return sorted(p.name for p in d.iterdir()) if d.exists() else []


def test_full_rotation(env):
    host, local, cloud, cfg, pw = env
    assert main(["-c", str(cfg)]) == 0
    assert names(host) == ["backup-2026-01-15.tar.gz"]
    assert names(local) == ["backup-2026-01-08.tar.gz"]
    assert names(cloud) == ["backup-2026-01-01.tar.gz.enc"]
    out = cloud.parent / "dec.tar.gz"
    subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "1000",
                    "-in", str(cloud / "backup-2026-01-01.tar.gz.enc"), "-out", str(out),
                    "-pass", f"file:{pw}"], check=True)
    subprocess.run(["tar", "-tzf", str(out)], check=True, capture_output=True)


def test_dry_run_changes_nothing(env):
    host, local, cloud, cfg, _ = env
    before = names(host)
    assert main(["-c", str(cfg), "--dry-run"]) == 0
    assert names(host) == before and names(local) == [] and names(cloud) == []


def test_corrupt_tar_keeps_host_copy(env):
    host, local, cloud, cfg, _ = env
    (host / "backup-2026-01-01.tar.gz").write_bytes(b"not a tarball")
    assert main(["-c", str(cfg)]) == 2
    assert "backup-2026-01-01.tar.gz" in names(host)


def test_sha_mismatch_keeps_host_copy(env, monkeypatch):
    host, local, cloud, cfg, _ = env
    monkeypatch.setattr(LocalDirRemote, "sha256", lambda self, n: "0" * 64)
    assert main(["-c", str(cfg)]) == 2
    assert len(names(host)) == 3


def test_retry_then_success(env, monkeypatch):
    host, local, cloud, cfg, _ = env
    real = LocalDirRemote.fetch
    calls = {"n": 0}

    def flaky(self, name, dest):
        calls["n"] += 1
        if calls["n"] == 1:
            raise subprocess.CalledProcessError(1, "rsync")
        real(self, name, dest)

    monkeypatch.setattr(LocalDirRemote, "fetch", flaky)
    assert main(["-c", str(cfg)]) == 0
    assert calls["n"] >= 2


def test_cloud_md5_mismatch_keeps_local(env, monkeypatch):
    host, local, cloud, cfg, _ = env
    monkeypatch.setattr(LocalDirCloud, "md5", lambda self, n: "bad")
    assert main(["-c", str(cfg)]) == 2
    assert "backup-2026-01-01.tar.gz" in names(local)


def test_passphrase_file_must_be_private(env):
    host, local, cloud, cfg, pw = env
    pw.chmod(0o644)
    assert main(["-c", str(cfg)]) == 2
    assert "backup-2026-01-01.tar.gz" in names(local)
