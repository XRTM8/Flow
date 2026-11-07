"""Create and verify a self-contained Git binary patch without staging user files."""
from __future__ import annotations
import argparse
import hashlib
import io
import os
from pathlib import Path
import subprocess
import uuid
import zipfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
VERSION = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["package"]["version"]

def git(*args: str, cwd: Path = ROOT, accepted=(0,), env=None) -> bytes:
    result = subprocess.run(["git", *args], cwd=cwd, capture_output=True, env=env)
    if result.returncode not in accepted:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))
    return result.stdout

def included_new(path: str) -> bool:
    return path in {"VALIDATION.md", f"release_notes_v{VERSION}.md"} or path.startswith(
        ("src/", "ui/", "tests/", "assets/fonts/", "assets/android/", "scripts/")
    )

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="HEAD")
    parser.add_argument("--output", default=f"dist/Flow-v{VERSION}.patch")
    args = parser.parse_args()
    base = git("rev-parse", args.base).decode().strip()
    tracked = [p.decode() for p in git("diff", "--name-only", "-z", base).split(b"\0") if p]
    untracked = [p.decode() for p in git("ls-files", "--others", "--exclude-standard", "-z").split(b"\0") if p]
    new = sorted(p for p in untracked if included_new(p))
    patch = git("diff", "--binary", "--full-index", base, "--", *tracked) if tracked else b""
    for path in new:
        patch += git("diff", "--no-index", "--binary", "--full-index", "--", "NUL" if os.name == "nt" else "/dev/null", path, accepted=(0, 1))
    if not patch:
        raise RuntimeError("No changes to package")
    output = (ROOT / args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(patch)
    # Verify against an untouched archive. No index, branch or existing worktree is modified.
    check_dir = ROOT / "target" / f"patch-validation-{uuid.uuid4()}"
    check_dir.mkdir(parents=True)
    with zipfile.ZipFile(io.BytesIO(git("archive", "--format=zip", base))) as archive:
        archive.extractall(check_dir)
    env = os.environ.copy()
    env["GIT_CEILING_DIRECTORIES"] = str(check_dir.parent)
    git("apply", "--no-index", "--check", str(output), cwd=check_dir, env=env)
    git("apply", "--no-index", str(output), cwd=check_dir, env=env)
    changed = sorted(set(tracked + new))
    for path in changed:
        actual = check_dir / path
        expected = ROOT / path
        if not expected.exists():
            if actual.exists():
                raise RuntimeError(f"Deleted file still exists after patch: {path}")
            continue
        expected_hash = git("hash-object", f"--path={path}", str(expected)).strip()
        actual_hash = git("hash-object", f"--path={path}", str(actual), cwd=check_dir, env=env).strip()
        if actual_hash != expected_hash:
            raise RuntimeError(f"Patched content differs: {path}")
    print(f"Base: {base}\nPatch: {output}\nVerified files: {len(changed)}")
    print(f"SHA256: {hashlib.sha256(patch).hexdigest()}")
    print("Pre-existing release_notes_v2.3.0.md and ignored artifacts are excluded.")

if __name__ == "__main__":
    main()
