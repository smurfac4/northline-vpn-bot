"""Start the local backend and, when a token is configured, the bot."""
import os
import fcntl
import secrets
import signal
import subprocess
import sys
import time

START_ENV = dict(os.environ)

import settings


class RestartRequested(Exception):
    pass


def acquire_instance_lock():
    """Hold one application instance without terminating any other process."""
    directory = settings.ROOT / 'data'
    directory.mkdir(exist_ok=True)
    path = directory / 'application.lock'
    inherited = os.getenv('NORTHLINE_RUN_LOCK_FD', '')
    fd = None
    if inherited.isdigit():
        try:
            candidate = int(inherited)
            current = os.fstat(candidate)
            target = path.stat()
            if (current.st_dev, current.st_ino) == (target.st_dev, target.st_ino):
                fd = candidate
        except (OSError, ValueError):
            pass
    if fd is None:
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(fd)
            raise
    os.set_inheritable(fd, True)
    START_ENV['NORTHLINE_RUN_LOCK_FD'] = str(fd)
    return fd


def main():
    def stop(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    env = dict(os.environ)
    env.pop('NORTHLINE_RUN_LOCK_FD', None)
    env['NORTHLINE_SUPERVISED'] = '1'
    if not env.get("BOT_API_KEY"):
        env["BOT_API_KEY"] = secrets.token_urlsafe(32)
    modules = ["backend.main"]
    if settings.TOKEN:
        modules.append("bot.main")
    processes = []
    restart_stamp = settings.RESTART_FILE.read_text() if settings.RESTART_FILE.exists() else None
    try:
        for module in modules:
            processes.append(subprocess.Popen(
                [sys.executable, "-m", module], cwd=settings.ROOT, env=env,
                start_new_session=env.get('NORTHLINE_MANAGED') != '1',
            ))
        while all(process.poll() is None for process in processes):
            stamp = settings.RESTART_FILE.read_text() if settings.RESTART_FILE.exists() else None
            if stamp != restart_stamp:
                raise RestartRequested
            time.sleep(0.25)
        return next(process.returncode for process in processes if process.returncode is not None) or 1
    except KeyboardInterrupt:
        return 0
    except RestartRequested:
        return 75
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        for process in processes:
            if process.poll() is None:
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
        for process in processes:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)


if __name__ == "__main__":
    try:
        instance_lock = acquire_instance_lock()
    except BlockingIOError:
        raise SystemExit('Northline is already running. Stop that instance before starting another.')
    result = main()
    if result != 0:
        if result != 75:
            print('A project process exited unexpectedly; restarting in 3 seconds.', flush=True)
            try:
                time.sleep(3)
            except KeyboardInterrupt:
                raise SystemExit(0)
        os.execve(sys.executable, [sys.executable, str(settings.ROOT / 'run.py')], START_ENV)
    os.close(instance_lock)
    raise SystemExit(result)
