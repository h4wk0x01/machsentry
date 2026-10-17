"""Own source admission, stable reads and explicit ZIP member selection."""

from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO
import os
from pathlib import Path
import stat
import zipfile


class AnalysisError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code

    def as_dict(self) -> dict:
        return {"code": self.code, "message": str(self)}


@dataclass(frozen=True)
class Limits:
    # Memory budgets apply before parsing/retention; exhaustion is never a clean verdict.
    max_file_bytes: int = 32 * 1024 * 1024
    max_strings: int = 20_000
    max_string_bytes: int = 2 * 1024 * 1024
    max_instructions: int = 2_000_000
    max_references: int = 50_000
    max_functions: int = 100_000
    max_symbols: int = 100_000
    max_expanded_symbol_bytes: int = 8 * 1024 * 1024


@dataclass(frozen=True)
class Source:
    data: bytes
    path: str
    sha256: str
    carrier_sha256: str
    member: str | None

    def identity(self) -> dict:
        return {"path": self.path, "sha256": self.sha256, "size_bytes": len(self.data),
                "carrier_sha256": self.carrier_sha256, "archive_member": self.member,
                "offset_space": "uncompressed-member" if self.member else "file"}


def read_regular(path: Path, limit: int) -> bytes:
    try:
        with path.open("rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise AnalysisError("invalid_input", "Input must be a regular file")
            if before.st_size > limit:
                raise AnalysisError("resource_limit", f"Input exceeds {limit} bytes")
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns) or len(data) != before.st_size:
            raise AnalysisError("source_changed", "Source changed during read")
        return data
    except OSError as error:
        raise AnalysisError("io_error", str(error)) from error


def load_source(path: Path, limits: Limits, member: str | None = None,
                password: str | None = None) -> Source:
    raw = read_regular(path, limits.max_file_bytes)
    carrier_hash = sha256(raw).hexdigest()
    data = raw
    if member is not None:
        try:
            with zipfile.ZipFile(BytesIO(raw)) as archive:
                matches = [entry for entry in archive.infolist() if entry.filename == member]
                if len(matches) != 1 or matches[0].is_dir():
                    raise AnalysisError("invalid_input", "Select exactly one regular ZIP member")
                entry = matches[0]
                if entry.file_size > limits.max_file_bytes:
                    raise AnalysisError("resource_limit", "Uncompressed member exceeds byte budget")
                if stat.S_ISLNK(entry.external_attr >> 16):
                    raise AnalysisError("invalid_input", "ZIP symlink members are unsupported")
                with archive.open(entry, pwd=password.encode() if password else None) as stream:
                    data = stream.read(limits.max_file_bytes + 1)
                if len(data) > limits.max_file_bytes or len(data) != entry.file_size:
                    raise AnalysisError("resource_limit", "Member size violates admission bounds")
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError) as error:
            raise AnalysisError("archive_error", str(error)) from error
    elif password is not None:
        raise AnalysisError("invalid_input", "ZIP password requires an explicit --member")
    return Source(data, str(path.absolute()), sha256(data).hexdigest(), carrier_hash, member)
