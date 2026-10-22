"""Private, invocation-scoped pack inventory for projection preparation."""

from __future__ import annotations

import hashlib
import json
import tempfile
from contextlib import contextmanager
from pathlib import Path

import build_native_command_packs as packs
from command_pack_store import PackReader
from core_command_build_inputs import implementation_digest


class ProjectionInventory:
    """Share validated packs without accepting a cache path or skipping checks."""

    def __init__(self, root: Path, compiler: Path):
        if root.is_symlink():
            raise ValueError("projection inventory root cannot be a symlink")
        self.root = root.resolve(strict=True)
        self.compiler = compiler.resolve(strict=True)
        self._scratch = None
        self._directory = None
        self._release = None
        self._identity = None

    def _fingerprint(self) -> bytes:
        digest = hashlib.sha256()

        def record(name: str, content: bytes) -> None:
            for value in (name.encode(), content):
                digest.update(len(value).to_bytes(8, "big"))
                digest.update(value)

        if self.compiler.is_symlink() or not self.compiler.is_file():
            raise ValueError("projection inventory compiler must remain a regular file")
        record("compiler", self.compiler.read_bytes())
        record("implementation", implementation_digest(self.root).encode())
        for relative in ("contributions/command-sources", "contributions/mcp-servers", "contracts/extensions/trust"):
            directory = self.root / relative
            if directory.is_symlink():
                raise ValueError("projection inventory inputs cannot be symlinks")
            for path in sorted(directory.glob("*.json")):
                if path.name != "migration-manifest.json":
                    record(path.relative_to(self.root).as_posix(), packs.legacy.read_source_bytes(path, root=self.root))
        return digest.digest()

    def validate(self) -> None:
        if self._scratch is None or self._fingerprint() != self._identity:
            raise ValueError("projection inventory inputs changed or invocation expired")
        if self._release is not None and (self._directory / "release.json").read_bytes() != self._release:
            raise ValueError("projection inventory release changed")

    def __enter__(self):
        if self._scratch is not None:
            raise ValueError("projection inventory is already active")
        self._identity = self._fingerprint()
        self._scratch = tempfile.TemporaryDirectory(prefix="hol-guard-projections-")
        self._directory = Path(self._scratch.name).resolve(strict=True)
        return self

    def __exit__(self, *exc):
        try:
            if exc[0] is None:
                self.validate()
        finally:
            self._scratch.cleanup()
            self._scratch = None
            self._directory = None
            self._release = None

    @contextmanager
    def open(self, compiler: Path, *, root: Path):
        if root.resolve(strict=True) != self.root or compiler.resolve(strict=True) != self.compiler:
            raise ValueError("projection inventory belongs to different inputs")
        self.validate()
        if self._release is None:
            packs.stage(self.compiler, self._directory, source_root=self.root)
            self.validate()
            self._release = (self._directory / "release.json").read_bytes()
        try:
            yield self._directory, PackReader(self._directory / "objects"), json.loads(self._release)
        finally:
            self.validate()
