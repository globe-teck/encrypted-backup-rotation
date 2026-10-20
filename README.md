# encrypted-backup-rotation

[![CI](https://github.com/leighsrodney-prog/encrypted-backup-rotation/actions/workflows/ci.yml/badge.svg)](https://github.com/leighsrodney-prog/encrypted-backup-rotation/actions/workflows/ci.yml)

A small, dependency-free Python tool for a **3-tier rotation of cPanel-style full backups**
(`backup-YYYY-MM-DD.tar.gz`). The newest stays on the host, the previous one moves to local disk, and
the oldest goes to the cloud **encrypted**. **Nothing is deleted until every check for that step passes.**

## Design
```
host (newest)  --rsync --partial + retry-->  local (previous)  --openssl + rclone-->  cloud (oldest, .enc)
               verify: sha256 host == local                    verify: decrypt test (sha256 round trip)
                       tar -tzf                                        cloud size == local size
               then delete host copy                                   cloud md5 == local md5
                                                               then delete local copy + .enc
```
| Step | Check | On failure |
|---|---|---|
| Pull | rsync `--partial` with a retry loop | stop, host copy kept |
| Verify pull | remote `sha256sum` vs local sha256, `tar -tzf` | stop, host copy kept |
| Encrypt | `openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt` | stop |
| Decrypt test | decrypt to a temp file, sha256 must match the original | stop, local kept |
| Upload | `rclone copyto`, then size and `rclone md5sum` | stop, local kept |

Exit codes: `0` ok, `2` a check failed (message says which, and what was kept).

## Passphrase
- **macOS:** login Keychain, read with `security find-generic-password -s SERVICE -a ACCOUNT -w`.
  Add it once: `security add-generic-password -s backup-rotation -a backupuser -w` (prompts).
- **Linux:** a `chmod 600` file. The tool refuses to run if the file is readable by group or others.

The passphrase is passed to openssl via `-pass file:` (never on the command line, never printed).
A Keychain passphrase is written to a temporary `0600` file in the work dir and removed after use.

## Usage
```bash
cp rotation.example.ini rotation.ini     # edit host, paths, rclone remote (rotation.ini is git-ignored)
python -m backup_rotation -c rotation.ini --dry-run   # show what would happen
python -m backup_rotation -c rotation.ini
```
Needs `ssh`, `rsync`, `openssl`, `tar` and `rclone` on PATH (plus `security` on macOS). Set up SSH key
auth to the host first; the tool uses `BatchMode=yes` and never prompts.

Restore:
```bash
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -in backup-2026-01-01.tar.gz.enc -out backup.tar.gz -pass file:PASSFILE
```

## Tests
```bash
pip install -r requirements.txt && pytest -q
```
Tests mock the host and the cloud with local directories (`type = local` in the config) and cover the
full rotation, dry run, corrupt tarball, sha256 mismatch, retry, cloud md5 mismatch and a
world-readable passphrase file.

## License
MIT
