"""Per-attempt job directory: `jobs/<jobId>-<attempt>/` with the input file and a 4 GiB ext4 loop
image mounted `nodev,nosuid` at `work/`. Engine outputs are copied out to `results/<jobId>-<attempt>/`
before the job directory is destroyed, so sample, image and mount are gone before the AI stage.

The supervisor owns these paths. Removal is reported as confirmed only after the mount is gone,
the loop device is detached and the directory no longer exists. A failed unmount keeps the tree.
"""

import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time

ANALYZER_UID = ANALYZER_GID = 10001
WORK_BYTES = 4 * 1024 * 1024 * 1024
JOB_ID = re.compile(r'^[A-Za-z0-9_-]{1,128}$')
# Engine outputs copied out of the loop image before it is destroyed, with contract size caps.
OUTPUT_CAPS = {
    'report.json': 32 * 1024 * 1024,
    'report-view.json': 4 * 1024 * 1024,
    'report.html': 4 * 1024 * 1024,
    'detection.yar': 256 * 1024,
    'candidate-rejected.yar.txt': 256 * 1024,
}


class HostOpError(Exception):
    pass


class HostOps:
    """Privileged host operations (root on the worker); tests substitute a fake."""

    def __init__(self, run=subprocess.run, sleep=time.sleep):
        self._run, self._sleep = run, sleep

    def _command(self, argv: list[str], timeout: float = 60):
        try:
            completed = self._run(argv, capture_output=True, timeout=timeout, check=False)
        except (OSError, subprocess.SubprocessError) as error:
            raise HostOpError(f'{argv[0]}: {type(error).__name__}') from None
        if completed.returncode != 0:
            raise HostOpError(f'{argv[0]}: exit {completed.returncode}')
        return completed.stdout.decode(errors='replace')

    def allocate(self, path: Path, size: int):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.posix_fallocate(descriptor, 0, size)
        finally:
            os.close(descriptor)

    def mkfs(self, image: Path):
        self._command(['mkfs.ext4', '-q', '-F', '-m', '0', '-E',
                       f'root_owner={ANALYZER_UID}:{ANALYZER_GID}', str(image)], timeout=120)

    def mount(self, image: Path, target: Path):
        self._command(['mount', '-t', 'ext4', '-o', 'loop,nodev,nosuid', str(image), str(target)])

    def unmount(self, target: Path):
        self._command(['umount', str(target)])

    def is_mounted(self, target: Path) -> bool:
        resolved = os.path.realpath(target)
        try:
            with open('/proc/self/mountinfo', encoding='utf-8', errors='replace') as mounts:
                points = {line.split()[4].encode().decode('unicode_escape') for line in mounts if len(line.split()) > 4}
        except OSError:
            return os.path.ismount(resolved)
        return resolved in points

    def loop_devices(self, image: Path) -> list[str]:
        output = self._command(['losetup', '-j', str(image)])
        return [line.split(':', 1)[0] for line in output.splitlines() if line.strip()]

    def detach(self, device: str):
        self._command(['losetup', '-d', device])

    def chown(self, path: Path, uid: int, gid: int):
        os.chown(path, uid, gid, follow_symlinks=False)

    def usage(self, target: Path) -> int:
        info = os.statvfs(target)
        return (info.f_blocks - info.f_bfree) * info.f_frsize

    def sleep(self, seconds: float):
        self._sleep(seconds)


def _read_capped(directory: Path, name: str, cap: int, dir_fd: int | None) -> bytes | None:
    """Opens without following links or blocking on FIFOs; only regular files are read."""
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0)
    try:
        if dir_fd is not None:
            descriptor = os.open(name, flags, dir_fd=dir_fd)
        else:
            if stat.S_ISLNK(os.lstat(directory / name).st_mode):
                return None
            descriptor = os.open(directory / name, flags)
    except FileNotFoundError:
        return None
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            return None
        chunks, total = [], 0
        while total <= cap:
            chunk = os.read(descriptor, min(1024 * 1024, cap + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b''.join(chunks)
    finally:
        os.close(descriptor)


class JobDir:
    def __init__(self, jobs_root: Path, results_root: Path, job_id: str, attempt: int, ops: HostOps):
        if not isinstance(job_id, str) or not JOB_ID.match(job_id) or not isinstance(attempt, int) or attempt < 1:
            raise ValueError('invalid job identity')
        self.job_id, self.attempt, self.ops = job_id, attempt, ops
        self.path = Path(jobs_root) / f'{job_id}-{attempt}'
        self.input_file = self.path / 'input' / 'sample.macho'
        self.image = self.path / 'work.img'
        self.work = self.path / 'work'
        self.results = Path(results_root) / f'{job_id}-{attempt}'

    def create(self):
        for root in (self.path.parent, self.results.parent):
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path.mkdir(mode=0o700)
        self.input_file.parent.mkdir(mode=0o700)
        self.results.mkdir(mode=0o700)

    def protect_input(self):
        self.ops.chown(self.input_file, ANALYZER_UID, ANALYZER_GID)
        os.chmod(self.input_file, 0o400)

    def prepare_work(self, size: int = WORK_BYTES):
        self.ops.allocate(self.image, size)
        self.ops.mkfs(self.image)
        self.work.mkdir(mode=0o700)
        self.ops.mount(self.image, self.work)
        if not self.ops.is_mounted(self.work):
            raise HostOpError('work image did not mount')
        for name in ('home', 'tmp', 'out'):
            directory = self.work / name
            directory.mkdir(mode=0o700)
            self.ops.chown(directory, ANALYZER_UID, ANALYZER_GID)

    def work_usage(self) -> int | None:
        try:
            return self.ops.usage(self.work) if self.ops.is_mounted(self.work) else None
        except (OSError, HostOpError):
            return None

    def collect_outputs(self) -> tuple[dict[str, Path], list[str]]:
        """Copies the engine outputs into results/. Returns (copied, oversized names)."""
        report_dir = self.work / 'out' / 'report'
        copied, oversized, descriptors = {}, [], []
        dir_fd = None
        try:
            # The container owns everything under work/: each component is opened without following links.
            try:
                if os.open in os.supports_dir_fd:
                    flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)
                    descriptors.append(os.open(self.work, flags))
                    for part in ('out', 'report'):
                        descriptors.append(os.open(part, flags, dir_fd=descriptors[-1]))
                    dir_fd = descriptors[-1]
                elif any(stat.S_ISLNK(os.lstat(path).st_mode) or not stat.S_ISDIR(os.lstat(path).st_mode)
                         for path in (self.work / 'out', report_dir)):
                    return {}, []
            except OSError:
                return {}, []
            for name, cap in OUTPUT_CAPS.items():
                data = _read_capped(report_dir, name, cap, dir_fd)
                if data is None:
                    continue
                if len(data) > cap:
                    oversized.append(name)
                    continue
                target = self.results / name
                with open(target, 'xb') as output:
                    output.write(data)
                copied[name] = target
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)
        return copied, oversized

    def delete_sample(self) -> bool:
        try:
            _unlink(self.input_file)
        except FileNotFoundError:
            pass
        except OSError:
            return False
        return not os.path.lexists(self.input_file)

    def remove_work(self) -> bool:
        """Unmounts work/, detaches the loop device and deletes the image."""
        try:
            for _ in range(5):
                if not (self.work.exists() and self.ops.is_mounted(self.work)):
                    break
                try:
                    self.ops.unmount(self.work)
                except HostOpError:
                    self.ops.sleep(1)
            if self.work.exists() and self.ops.is_mounted(self.work):
                return False
            if self.image.exists():
                for device in self.ops.loop_devices(self.image):
                    self.ops.detach(device)
                if self.ops.loop_devices(self.image):
                    return False
                self.image.unlink()
            if self.work.exists():
                self.work.rmdir()
        except (OSError, HostOpError):
            return False
        return not self.image.exists() and not self.work.exists()

    def remove(self) -> bool:
        """Removes the job directory (sample, image, mount point); results/ is separate."""
        if not self.remove_work():
            return False
        return _remove_tree(self.path)

    def remove_results(self) -> bool:
        return _remove_tree(self.results)


def _unlink(path: Path):
    """The input file is read-only (0400); platforms that refuse to delete such files get it writable first."""
    try:
        os.unlink(path)
    except PermissionError:
        if os.path.islink(path):
            raise
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        os.unlink(path)


def _remove_tree(path: Path) -> bool:
    def retry(function, target, error):
        if function not in (os.unlink, os.remove):
            raise error
        _unlink(Path(target))
    try:
        if os.path.lexists(path):
            if path.is_symlink() or not path.is_dir():
                _unlink(path)
            else:
                shutil.rmtree(path, onexc=retry)
    except OSError:
        return False
    return not os.path.lexists(path)


def parse_name(name: str) -> tuple[str, int] | None:
    job_id, separator, attempt = name.rpartition('-')
    if separator and JOB_ID.match(job_id) and attempt.isdigit() and int(attempt) >= 1:
        return job_id, int(attempt)
    return None


def sweep(jobs_root: Path, results_root: Path, ops: HostOps) -> list[dict]:
    """Boot sweep: removes leftover job and result directories. Returns each attempt and its outcome;
    entries whose name is not `<jobId>-<attempt>` are removed too and reported with jobId None."""
    outcomes = {}
    for root, is_job in ((Path(jobs_root), True), (Path(results_root), False)):
        try:
            entries = sorted(root.iterdir())
        except FileNotFoundError:
            continue
        for entry in entries:
            identity = parse_name(entry.name)
            if identity is not None and is_job:
                removed = JobDir(jobs_root, results_root, identity[0], identity[1], ops).remove()
            elif entry.is_dir() and not entry.is_symlink() and ops.is_mounted(entry):
                removed = False
            else:
                removed = _remove_tree(entry)
            key = identity or (None, entry.name)
            previous = outcomes.get(key, True)
            outcomes[key] = previous and removed
    return [{'jobId': key[0], 'attempt': key[1] if key[0] else None, 'removed': removed}
            for key, removed in outcomes.items()]
