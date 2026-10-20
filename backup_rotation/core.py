"""3-tier rotation: newest on host, previous on local disk, oldest encrypted in the cloud.

Nothing is deleted until every check for that tier has passed.
"""
from __future__ import annotations

import fnmatch
import hashlib
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


class CheckFailed(Exception):
    pass


def log(msg: str) -> None:
    print(f"[rotate] {msg}", flush=True)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def md5_file(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


# ---------------------------------------------------------------- remote host
class SshRemote:
    """Backups on a host reached over SSH; pulled with rsync --partial."""

    def __init__(self, host: str, user: str, path: str, port: int = 22):
        self.target = f"{user}@{host}"
        self.path = path.rstrip("/")
        self.ssh = ["ssh", "-p", str(port), "-o", "BatchMode=yes", self.target]
        self.port = port

    def list(self) -> list[str]:
        out = run(self.ssh + [f"ls -1 {self.path}"]).stdout
        return [l.strip() for l in out.splitlines() if l.strip()]

    def sha256(self, name: str) -> str:
        return run(self.ssh + [f"sha256sum {self.path}/{name}"]).stdout.split()[0]

    def fetch(self, name: str, dest: Path) -> None:
        run(["rsync", "--partial", "--times", "-e", f"ssh -p {self.port} -o BatchMode=yes",
             f"{self.target}:{self.path}/{name}", str(dest)])

    def delete(self, name: str) -> None:
        run(self.ssh + [f"rm -f -- {self.path}/{name}"])


class LocalDirRemote:
    """A plain directory standing in for the host (tests, or a mounted share)."""

    def __init__(self, path: str):
        self.path = Path(path)

    def list(self) -> list[str]:
        return [p.name for p in self.path.iterdir() if p.is_file()]

    def sha256(self, name: str) -> str:
        return sha256_file(self.path / name)

    def fetch(self, name: str, dest: Path) -> None:
        shutil.copy2(self.path / name, dest)

    def delete(self, name: str) -> None:
        (self.path / name).unlink()


# ---------------------------------------------------------------- cloud
class RcloneCloud:
    def __init__(self, dest: str):
        self.dest = dest.rstrip("/")

    def upload(self, src: Path) -> None:
        run(["rclone", "copyto", str(src), f"{self.dest}/{src.name}"])

    def size(self, name: str) -> int:
        return int(run(["rclone", "size", "--json", f"{self.dest}/{name}"]).stdout.split('"bytes":')[1].split(",")[0].strip(" }\n"))

    def md5(self, name: str) -> str:
        return run(["rclone", "md5sum", f"{self.dest}/{name}"]).stdout.split()[0]


class LocalDirCloud:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=True)

    def upload(self, src: Path) -> None:
        shutil.copy2(src, self.path / src.name)

    def size(self, name: str) -> int:
        return (self.path / name).stat().st_size

    def md5(self, name: str) -> str:
        return md5_file(self.path / name)


# ---------------------------------------------------------------- passphrase
def passphrase_file(cfg: dict) -> Path:
    """Return a path to a chmod-600 file holding the passphrase (never printed)."""
    src = cfg.get("passphrase_source", "file")
    if src == "file":
        p = Path(os.path.expanduser(cfg["passphrase_file"]))
        if p.stat().st_mode & 0o077:
            raise CheckFailed(f"passphrase file {p} must be chmod 600")
        return p
    if src == "keychain":
        secret = run(["security", "find-generic-password", "-s", cfg["keychain_service"],
                      "-a", cfg["keychain_account"], "-w"]).stdout.rstrip("\n")
        tmp = Path(cfg["work_dir"]) / ".pass.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secret)
        return tmp
    raise CheckFailed(f"unknown passphrase_source {src!r}")


def encrypt(src: Path, dst: Path, passfile: Path, iters: int) -> None:
    run(["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", str(iters), "-salt",
         "-in", str(src), "-out", str(dst), "-pass", f"file:{passfile}"])


def decrypt(src: Path, dst: Path, passfile: Path, iters: int) -> None:
    run(["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", str(iters),
         "-in", str(src), "-out", str(dst), "-pass", f"file:{passfile}"])


# ---------------------------------------------------------------- rotation
@dataclass
class Rotator:
    remote: object
    cloud: object
    local_dir: Path
    pattern: str = "backup-*.tar.gz"
    retries: int = 3
    retry_wait: float = 5.0
    iterations: int = 200000
    dry_run: bool = False
    pass_cfg: dict | None = None

    def _matching(self, names):
        return sorted(n for n in names if fnmatch.fnmatch(n, self.pattern))

    # tier 2: host -> local
    def pull_previous(self) -> str | None:
        remote = self._matching(self.remote.list())
        if len(remote) < 2:
            log(f"host has {len(remote)} backup(s); newest stays, nothing to pull")
            return None
        log(f"newest stays on host: {remote[-1]}")
        for name in remote[:-1]:
            dest = self.local_dir / name
            if self.dry_run:
                log(f"DRY-RUN would pull {name}, verify sha256 + tar -tzf, then delete from host")
                continue
            for attempt in range(1, self.retries + 1):
                try:
                    self.remote.fetch(name, dest)
                    break
                except subprocess.CalledProcessError:
                    log(f"pull {name} failed (attempt {attempt}/{self.retries})")
                    if attempt == self.retries:
                        raise CheckFailed(f"could not pull {name}")
                    time.sleep(self.retry_wait)
            if self.remote.sha256(name) != sha256_file(dest):
                raise CheckFailed(f"sha256 mismatch for {name}; host copy kept")
            try:
                run(["tar", "-tzf", str(dest)])
            except subprocess.CalledProcessError:
                raise CheckFailed(f"tar -tzf failed for {name}; host copy kept")
            log(f"verified {name} (sha256 + tar); deleting host copy")
            self.remote.delete(name)
        return remote[-2]

    # tier 3: local -> encrypted cloud
    def archive_oldest(self) -> None:
        local = self._matching(p.name for p in self.local_dir.iterdir() if p.is_file())
        if len(local) < 2:
            log(f"local has {len(local)} backup(s); keeping it")
            return
        for name in local[:-1]:
            src = self.local_dir / name
            enc = self.local_dir / (name + ".enc")
            if self.dry_run:
                log(f"DRY-RUN would encrypt {name}, decrypt-test, upload, check size + md5, then delete local")
                continue
            passfile = passphrase_file(self.pass_cfg or {})
            try:
                encrypt(src, enc, passfile, self.iterations)
                test = self.local_dir / (name + ".dectest")
                decrypt(enc, test, passfile, self.iterations)
                ok = sha256_file(test) == sha256_file(src)
                test.unlink()
                if not ok:
                    raise CheckFailed(f"decrypt test failed for {name}")
            finally:
                if passfile.name == ".pass.tmp":
                    passfile.unlink(missing_ok=True)
            log(f"encrypted + decrypt-tested {name}; uploading")
            self.cloud.upload(enc)
            if self.cloud.size(enc.name) != enc.stat().st_size:
                raise CheckFailed(f"cloud size mismatch for {enc.name}; local kept")
            if self.cloud.md5(enc.name) != md5_file(enc):
                raise CheckFailed(f"cloud md5 mismatch for {enc.name}; local kept")
            log(f"cloud copy verified (size + md5); deleting local {name}")
            src.unlink()
            enc.unlink()

    def rotate(self) -> None:
        self.local_dir.mkdir(parents=True, exist_ok=True)
        self.pull_previous()
        self.archive_oldest()
        log("done" + (" (dry run, nothing changed)" if self.dry_run else ""))
