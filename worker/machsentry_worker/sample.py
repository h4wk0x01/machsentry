"""Download the sealed sample through its presigned GET and admit it like the site does.

`inspect_macho` mirrors Unpacked `lib/analysis/file.ts` (`inspectMachO`): 64-bit thin files or
FAT/FAT64 universals whose slices are arm64/x86_64. The bytes are only read, never executed.
"""

from hashlib import sha256
import http.client
import os
from pathlib import Path
import re
import struct
import time
import urllib.error
import urllib.parse
import urllib.request

from . import USER_AGENT

MAX_SAMPLE_BYTES = 32 * 1024 * 1024
_ARCHIVE_NAME = re.compile(r'\.(zip|dmg|pkg|rar|7z|gz|tar)$', re.IGNORECASE)
_CPU = {0x0100000C: 'arm64', 0x01000007: 'x86_64'}
_CHUNK = 1024 * 1024


class SampleRejected(Exception):
    """`code` is a contract error code: invalid_format, architecture, digest_mismatch, upload_missing."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class DownloadUnavailable(Exception):
    """Network or storage failure on the worker side; the attempt may be retried."""


def inspect_macho(size: int, name: str, read) -> list[str]:
    """`read(offset, length)` returns up to `length` bytes. Returns deduplicated architectures."""
    if not size or size > MAX_SAMPLE_BYTES or _ARCHIVE_NAME.search(name):
        raise SampleRejected('invalid_format')
    head = read(0, min(4096, size))
    if len(head) < 32:
        raise SampleRejected('invalid_format')

    def thin(offset: int, length: int) -> str:
        if length < 32 or offset < 0 or offset + length > size:
            raise SampleRejected('invalid_format')
        header = read(offset, 32)
        if len(header) < 32:
            raise SampleRejected('invalid_format')
        magic = struct.unpack_from('<I', header)[0]
        if magic not in (0xFEEDFACF, 0xCFFAEDFE):
            raise SampleRejected('invalid_format')
        order = '<' if magic == 0xFEEDFACF else '>'
        architecture = _CPU.get(struct.unpack_from(order + 'I', header, 4)[0])
        if architecture is None:
            raise SampleRejected('architecture')
        if struct.unpack_from(order + 'I', header, 20)[0] + 32 > length:
            raise SampleRejected('invalid_format')
        return architecture

    magic = struct.unpack_from('>I', head)[0]
    if magic not in (0xCAFEBABE, 0xCAFEBABF):
        return [thin(0, size)]
    entries = struct.unpack_from('>I', head, 4)[0]
    wide = magic == 0xCAFEBABF
    stride = 32 if wide else 20
    if not entries or entries > 16 or 8 + entries * stride > len(head):
        raise SampleRejected('invalid_format')
    names = []
    for index in range(entries):
        at = 8 + index * stride
        cpu = _CPU.get(struct.unpack_from('>I', head, at)[0])
        if cpu is None:
            raise SampleRejected('architecture')
        offset, length = struct.unpack_from('>QQ' if wide else '>II', head, at + 8)
        if offset < 8 + entries * stride:
            raise SampleRejected('invalid_format')
        if thin(offset, length) != cpu:
            raise SampleRejected('invalid_format')
        if cpu not in names:
            names.append(cpu)
    return names


def inspect_file(path: Path, name: str) -> list[str]:
    with open(path, 'rb') as stream:
        size = os.fstat(stream.fileno()).st_size

        def read(offset: int, length: int) -> bytes:
            stream.seek(offset)
            return stream.read(length)

        return inspect_macho(size, name, read)


def _require_transport(url: str):
    parsed = urllib.parse.urlsplit(url)
    loopback = parsed.hostname in ('127.0.0.1', 'localhost', '::1')
    if parsed.scheme != 'https' and not (parsed.scheme == 'http' and loopback):
        raise SampleRejected('upload_missing')


def download(url: str, destination: Path, expected_size: int, expected_sha256: str, *,
             timeout: float = 20.0, total_seconds: float = 180.0, clock=time.monotonic) -> None:
    """Streams into a new file, never past min(expected size, 32 MiB), then checks size and SHA-256."""
    _require_transport(url)
    if not isinstance(expected_size, int) or not 0 < expected_size <= MAX_SAMPLE_BYTES:
        raise SampleRejected('digest_mismatch')
    from .site_api import opener
    request = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    digest, received, deadline = sha256(), 0, clock() + total_seconds
    try:
        with opener().open(request, timeout=timeout) as response, open(destination, 'xb') as output:
            while True:
                chunk = response.read(_CHUNK)
                if not chunk:
                    break
                received += len(chunk)
                if received > expected_size:
                    raise SampleRejected('digest_mismatch')
                if clock() > deadline:
                    raise DownloadUnavailable('download_deadline')
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
    except urllib.error.HTTPError as error:
        error.close()
        if error.code in (403, 404):
            raise SampleRejected('upload_missing') from None
        raise DownloadUnavailable(f'http_{error.code}') from None
    except (urllib.error.URLError, OSError, http.client.HTTPException) as error:
        raise DownloadUnavailable(type(error).__name__) from None
    if received != expected_size or digest.hexdigest() != expected_sha256:
        raise SampleRejected('digest_mismatch')
