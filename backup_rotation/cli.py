import argparse
import configparser
import os
import sys
from pathlib import Path

from .core import CheckFailed, LocalDirCloud, LocalDirRemote, RcloneCloud, Rotator, SshRemote, log


def build(cfg_path: str, dry_run: bool) -> Rotator:
    cp = configparser.ConfigParser()
    if not cp.read(cfg_path):
        raise SystemExit(f"cannot read config {cfg_path}")
    r, l, c, e = cp["remote"], cp["local"], cp["cloud"], cp["encryption"]
    if r.get("type", "ssh") == "local":
        remote = LocalDirRemote(r["path"])
    else:
        remote = SshRemote(r["host"], r["user"], r["path"], r.getint("port", 22))
    cloud = LocalDirCloud(c["path"]) if c.get("type", "rclone") == "local" else RcloneCloud(c["dest"])
    local_dir = Path(os.path.expanduser(l["path"]))
    pass_cfg = dict(e)
    pass_cfg.setdefault("work_dir", str(local_dir))
    return Rotator(remote=remote, cloud=cloud, local_dir=local_dir,
                   pattern=r.get("pattern", "backup-*.tar.gz"),
                   retries=r.getint("retries", 3), retry_wait=r.getfloat("retry_wait", 5.0),
                   iterations=e.getint("iterations", 200000), dry_run=dry_run, pass_cfg=pass_cfg)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="backup_rotation", description=__doc__)
    ap.add_argument("-c", "--config", default="rotation.ini")
    ap.add_argument("-n", "--dry-run", action="store_true", help="show what would happen, change nothing")
    a = ap.parse_args(argv)
    try:
        build(a.config, a.dry_run).rotate()
    except CheckFailed as exc:
        log(f"STOPPED: {exc}")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
