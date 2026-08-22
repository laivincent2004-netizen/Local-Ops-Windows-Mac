"""Lazy Windows primitives for the durable supervisor.

This module deliberately has no top-level pywin32 imports.  The macOS source
tree and non-Windows tests can import it, while a Windows production launch
fails closed unless all required Windows bindings are available.
"""

from __future__ import annotations

import ctypes
import os
import re
import time
from types import SimpleNamespace


PIPE_PREFIX = r"\\.\pipe\LocalOps.Supervisor"
JOB_PREFIX = r"Local\LocalOps.Supervisor"
MAX_PIPE_MESSAGE = 64 * 1024
_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9_-]{1,96}$")


class WindowsRuntimeUnavailable(RuntimeError):
    """Raised when a production Windows security primitive is unavailable."""


def _modules():
    if os.name != "nt":
        raise WindowsRuntimeUnavailable("Windows supervisor requires Windows")
    try:
        import psutil
        import pywintypes
        import win32api
        import win32con
        import win32file
        import win32job
        import win32pipe
        import win32process
        import win32security
    except ImportError as exc:
        raise WindowsRuntimeUnavailable(
            "Windows supervisor dependencies are incomplete: %s" % exc
        ) from exc
    return SimpleNamespace(
        psutil=psutil,
        pywintypes=pywintypes,
        win32api=win32api,
        win32con=win32con,
        win32file=win32file,
        win32job=win32job,
        win32pipe=win32pipe,
        win32process=win32process,
        win32security=win32security,
    )


def validate_runtime():
    """Import every production dependency before a supervisor is spawned."""
    mods = _modules()
    current_user_sid(mods)
    return True


def current_user_sid(mods=None):
    mods = mods or _modules()
    token = mods.win32security.OpenProcessToken(
        mods.win32api.GetCurrentProcess(), mods.win32con.TOKEN_QUERY
    )
    try:
        sid = mods.win32security.GetTokenInformation(
            token, mods.win32security.TokenUser
        )[0]
        return mods.win32security.ConvertSidToStringSid(sid)
    finally:
        token.Close()


def process_identity(pid, mods=None):
    """Return the immutable identity used to reject PID reuse/cross-user use."""
    mods = mods or _modules()
    pid = int(pid)
    process = mods.psutil.Process(pid)
    create_time = float(process.create_time())
    handle = mods.win32api.OpenProcess(
        getattr(mods.win32con, "PROCESS_QUERY_LIMITED_INFORMATION", 0x1000),
        False,
        pid,
    )
    try:
        token = mods.win32security.OpenProcessToken(
            handle, mods.win32con.TOKEN_QUERY
        )
        try:
            sid = mods.win32security.GetTokenInformation(
                token, mods.win32security.TokenUser
            )[0]
            owner_sid = mods.win32security.ConvertSidToStringSid(sid)
        finally:
            token.Close()
    finally:
        handle.Close()
    return {
        "pid": pid,
        "createTime": create_time,
        "ownerSid": owner_sid,
    }


def identity_matches(expected, actual, tolerance=0.05):
    try:
        return (
            int(expected["pid"]) == int(actual["pid"])
            and expected["ownerSid"] == actual["ownerSid"]
            and abs(float(expected["createTime"])
                    - float(actual["createTime"])) <= tolerance
        )
    except (KeyError, TypeError, ValueError):
        return False


def _sid_objects(mods):
    user = mods.win32security.ConvertStringSidToSid(current_user_sid(mods))
    system = mods.win32security.CreateWellKnownSid(
        mods.win32security.WinLocalSystemSid, None
    )
    return user, system


def security_attributes(inheritable=False, mods=None):
    """Build a protected DACL granting access only to this SID and SYSTEM."""
    mods = mods or _modules()
    user, system = _sid_objects(mods)
    acl = mods.win32security.ACL()
    acl.AddAccessAllowedAce(
        mods.win32security.ACL_REVISION, mods.win32con.GENERIC_ALL, user
    )
    acl.AddAccessAllowedAce(
        mods.win32security.ACL_REVISION, mods.win32con.GENERIC_ALL, system
    )
    descriptor = mods.win32security.SECURITY_DESCRIPTOR()
    descriptor.SetSecurityDescriptorDacl(1, acl, 0)
    attributes = mods.pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    attributes.bInheritHandle = bool(inheritable)
    return attributes


def secure_path(path, directory=False, mods=None):
    """Replace a path DACL with current-user + SYSTEM, protected from inheritance."""
    mods = mods or _modules()
    user, system = _sid_objects(mods)
    acl = mods.win32security.ACL()
    ace_flags = 0
    if directory:
        ace_flags = (
            getattr(mods.win32con, "OBJECT_INHERIT_ACE", 0x1)
            | getattr(mods.win32con, "CONTAINER_INHERIT_ACE", 0x2)
        )
    acl.AddAccessAllowedAceEx(
        mods.win32security.ACL_REVISION,
        ace_flags,
        mods.win32con.GENERIC_ALL,
        user,
    )
    acl.AddAccessAllowedAceEx(
        mods.win32security.ACL_REVISION,
        ace_flags,
        mods.win32con.GENERIC_ALL,
        system,
    )
    security_information = (
        mods.win32security.DACL_SECURITY_INFORMATION
        | getattr(mods.win32security, "PROTECTED_DACL_SECURITY_INFORMATION", 0x80000000)
    )
    mods.win32security.SetNamedSecurityInfo(
        os.path.abspath(path),
        mods.win32security.SE_FILE_OBJECT,
        security_information,
        None,
        None,
        acl,
        None,
    )


def names(run_id, token_hash):
    if not _SAFE_COMPONENT.fullmatch(str(run_id)):
        raise ValueError("invalid run id")
    token_component = str(token_hash)[:20]
    if not re.fullmatch(r"[0-9a-f]{20}", token_component):
        raise ValueError("invalid token hash")
    suffix = "%s.%s" % (run_id, token_component)
    return "%s.%s" % (PIPE_PREFIX, suffix), "%s.%s" % (JOB_PREFIX, suffix)


def create_job(job_name, mods=None):
    mods = mods or _modules()
    try:
        mods.win32api.SetLastError(0)
    except AttributeError:
        pass
    job = mods.win32job.CreateJobObject(security_attributes(mods=mods), job_name)
    try:
        already_exists = int(mods.win32api.GetLastError()) == 183
    except AttributeError:
        already_exists = False
    if already_exists:
        job.Close()
        raise RuntimeError("managed Job name already exists")
    info_class = mods.win32job.JobObjectExtendedLimitInformation
    info = mods.win32job.QueryInformationJobObject(job, info_class)
    basic = info["BasicLimitInformation"]
    kill_flag = getattr(mods.win32job, "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE", 0x2000)
    basic["LimitFlags"] = int(basic.get("LimitFlags", 0)) & ~kill_flag
    info["BasicLimitInformation"] = basic
    mods.win32job.SetInformationJobObject(job, info_class, info)
    return job


def open_job(job_name, mods=None):
    """Open an existing token-bound Job for exact startup rollback only."""
    if not re.fullmatch(
            re.escape(JOB_PREFIX) + r"\.[A-Za-z0-9_-]{1,96}\.[0-9a-f]{20}",
            str(job_name)):
        raise ValueError("invalid managed Job name")
    mods = mods or _modules()
    access = (
        getattr(mods.win32job, "JOB_OBJECT_QUERY", 0x0004)
        | getattr(mods.win32job, "JOB_OBJECT_TERMINATE", 0x0008)
    )
    return mods.win32job.OpenJobObject(access, False, str(job_name))


def assign_process(job, pid, mods=None):
    mods = mods or _modules()
    access = (
        getattr(mods.win32con, "PROCESS_SET_QUOTA", 0x0100)
        | getattr(mods.win32con, "PROCESS_TERMINATE", 0x0001)
        | getattr(mods.win32con, "PROCESS_QUERY_LIMITED_INFORMATION", 0x1000)
    )
    handle = mods.win32api.OpenProcess(access, False, int(pid))
    try:
        mods.win32job.AssignProcessToJobObject(job, handle)
    finally:
        handle.Close()


def terminate_job(job, exit_code=130, mods=None):
    mods = mods or _modules()
    mods.win32job.TerminateJobObject(job, int(exit_code))


def job_process_ids(job, mods=None):
    mods = mods or _modules()
    value = mods.win32job.QueryInformationJobObject(
        job, mods.win32job.JobObjectBasicProcessIdList
    )
    if isinstance(value, dict):
        value = value.get("ProcessIdList", value.get("ProcessIds", ()))
    if not isinstance(value, (list, tuple)):
        raise WindowsRuntimeUnavailable("cannot read managed Job process list")
    return sorted({int(pid) for pid in value if int(pid) > 0})


def job_process_identities(job, expected_owner_sid=None, mods=None):
    """Return immutable identities for processes stably attached to ``job``.

    A Job PID list is only a point-in-time observation.  A member may exit and
    its PID may be reused between that observation and ``process_identity``.
    Querying the Job again after collecting identities makes such a reused PID
    fail closed: only PIDs present in both Job snapshots are returned.  The
    console performs one more create-time/SID check against its own live
    process snapshot before treating any returned member as managed.
    """
    mods = mods or _modules()
    before = set(job_process_ids(job, mods))
    identities = {}
    for pid in before:
        try:
            identity = process_identity(pid, mods)
        except Exception:
            # Normal process-exit and AccessDenied races are safe omissions.
            continue
        owner_sid = identity.get("ownerSid")
        if (expected_owner_sid is not None
                and str(owner_sid).casefold()
                != str(expected_owner_sid).casefold()):
            continue
        identities[pid] = identity
    after = set(job_process_ids(job, mods))
    return [
        identities[pid]
        for pid in sorted(before & after & set(identities))
    ]


def hidden_process_options():
    """Return Popen options for a hidden, initially suspended control group."""
    if os.name != "nt":
        return {}
    startup = subprocess_startupinfo()
    flags = (
        getattr(__import__("subprocess"), "CREATE_NEW_PROCESS_GROUP", 0)
        | getattr(__import__("subprocess"), "CREATE_SUSPENDED", 0x4)
    )
    return {"creationflags": flags, "startupinfo": startup}


def _console_process_ids(kernel32, wintypes):
    capacity = 8
    while True:
        values = (wintypes.DWORD * capacity)()
        count = int(kernel32.GetConsoleProcessList(values, capacity))
        if count <= 0:
            return []
        if count <= capacity:
            return [int(values[index]) for index in range(count)]
        if count > 4096:
            return []
        capacity = count


def _current_console_is_private(kernel32, wintypes):
    """Prove that an inherited console was created for this supervisor."""
    if not kernel32.GetConsoleCP():
        return False
    process_ids = set(_console_process_ids(kernel32, wintypes))
    current_pid = os.getpid()
    if process_ids == {current_pid}:
        return True
    if current_pid not in process_ids:
        return False
    try:
        import sys
        mods = _modules()
        current = mods.psutil.Process(current_pid)
        current_exe = os.path.normcase(os.path.realpath(current.exe()))
        current_name = os.path.basename(current_exe).casefold()
        current_tail = tuple(str(part).casefold()
                             for part in current.cmdline()[1:])
        chain = {current_pid}
        cursor = current
        while cursor.ppid() in process_ids:
            cursor = mods.psutil.Process(cursor.ppid())
            parent_exe = os.path.normcase(os.path.realpath(cursor.exe()))
            parent_tail = tuple(str(part).casefold()
                                for part in cursor.cmdline()[1:])
            same_frozen_image = (
                bool(getattr(sys, "frozen", False))
                and parent_exe == current_exe
            )
            same_source_bootstrap = (
                os.path.basename(parent_exe).casefold() == current_name
                and parent_tail == current_tail
            )
            if not (same_frozen_image or same_source_bootstrap):
                return False
            chain.add(cursor.pid)
        # No sibling or unrelated terminal client may share the console. The
        # accepted extra PIDs are only the contiguous venv/PyInstaller
        # bootstrap chain for this exact supervisor invocation.
        return chain == process_ids
    except Exception:
        return False


def ensure_private_console(expect_preallocated=False):
    """Give the durable supervisor a private hidden console for its children.

    CREATE_NEW_PROCESS_GROUP is ignored when combined with
    CREATE_NEW_CONSOLE.  The supervisor therefore owns the private console,
    while each managed root inherits it as a real new process group.  This is
    what makes a targeted CTRL_BREAK_EVENT reliable without displaying a
    console window.
    """
    if os.name != "nt":
        raise WindowsRuntimeUnavailable("private consoles are Windows-only")
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32.FreeConsole.argtypes = []
    kernel32.FreeConsole.restype = wintypes.BOOL
    kernel32.AllocConsole.argtypes = []
    kernel32.AllocConsole.restype = wintypes.BOOL
    kernel32.GetConsoleCP.argtypes = []
    kernel32.GetConsoleCP.restype = wintypes.UINT
    kernel32.GetConsoleProcessList.argtypes = [
        ctypes.POINTER(wintypes.DWORD), wintypes.DWORD
    ]
    kernel32.GetConsoleProcessList.restype = wintypes.DWORD
    kernel32.GetConsoleWindow.argtypes = []
    kernel32.GetConsoleWindow.restype = wintypes.HWND
    user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    user32.ShowWindow.restype = wintypes.BOOL

    private_console = _current_console_is_private(kernel32, wintypes)
    if expect_preallocated and not private_console:
        association_deadline = time.monotonic() + 2.0
        while time.monotonic() < association_deadline:
            # A non-empty list containing this PID proves association has
            # completed. If that console is shared, stop waiting and detach;
            # the CLI hint never overrides the membership proof.
            process_ids = set(_console_process_ids(kernel32, wintypes))
            if process_ids and os.getpid() in process_ids:
                private_console = _current_console_is_private(
                    kernel32, wintypes)
                break
            time.sleep(0.025)
    if not private_console:
        # A direct development invocation may have inherited the caller's
        # terminal. Detach before allocating a supervisor-only console. The
        # normal launcher uses CREATE_NEW_CONSOLE, so this is only a bounded
        # compatibility fallback for direct/older invocations.
        kernel32.FreeConsole()
        deadline = time.monotonic() + 2.0
        last_error = 0
        while True:
            ctypes.set_last_error(0)
            if kernel32.AllocConsole() or kernel32.GetConsoleCP():
                break
            last_error = ctypes.get_last_error()
            if time.monotonic() >= deadline:
                raise ctypes.WinError(last_error or 31)  # ERROR_GEN_FAILURE
            time.sleep(0.05)
    window = kernel32.GetConsoleWindow()
    if window:
        user32.ShowWindow(window, 0)  # SW_HIDE
    return True


def subprocess_startupinfo():
    import subprocess
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = getattr(subprocess, "SW_HIDE", 0)
    return startup


def resume_process(pid):
    """Resume all initial threads after safe Job assignment.

    Python's Popen intentionally closes the primary thread handle. Use the
    documented Toolhelp thread snapshot API instead of racing the child or
    relying on an undocumented NT routine.
    """
    if os.name != "nt":
        raise WindowsRuntimeUnavailable("process resume is Windows-only")
    from ctypes import wintypes

    class THREADENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", wintypes.LONG),
            ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
    kernel32.Thread32First.restype = wintypes.BOOL
    kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
    kernel32.Thread32Next.restype = wintypes.BOOL
    kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenThread.restype = wintypes.HANDLE
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    invalid_handle = ctypes.c_void_p(-1).value
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000004, 0)  # TH32CS_SNAPTHREAD
    if snapshot == invalid_handle:
        raise ctypes.WinError(ctypes.get_last_error())
    resumed = 0
    entry = THREADENTRY32()
    entry.dwSize = ctypes.sizeof(entry)
    try:
        has_entry = kernel32.Thread32First(snapshot, ctypes.byref(entry))
        while has_entry:
            if int(entry.th32OwnerProcessID) == int(pid):
                thread = kernel32.OpenThread(0x0002, False, entry.th32ThreadID)
                if not thread:
                    raise ctypes.WinError(ctypes.get_last_error())
                try:
                    previous = kernel32.ResumeThread(thread)
                    if previous == 0xFFFFFFFF:
                        raise ctypes.WinError(ctypes.get_last_error())
                    resumed += 1
                finally:
                    kernel32.CloseHandle(thread)
            has_entry = kernel32.Thread32Next(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    if not resumed:
        raise RuntimeError("suspended process has no resumable thread")


def send_ctrl_break(process_group_id, expected_process_ids):
    """Target the original managed group on the private console.

    A Windows console process-group ID is permanently the PID of the process
    created with ``CREATE_NEW_PROCESS_GROUP``.  That root may exit while its
    descendants (and therefore the process group) remain alive, so the group
    ID is not required to be a currently attached PID.  Instead, prove that at
    least one process from the current Job snapshot is still attached to this
    supervisor-only console before signalling the immutable original ID.
    """
    if os.name != "nt":
        raise WindowsRuntimeUnavailable("CTRL_BREAK is Windows-only")
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetConsoleProcessList.argtypes = [
        ctypes.POINTER(wintypes.DWORD), wintypes.DWORD
    ]
    kernel32.GetConsoleProcessList.restype = wintypes.DWORD
    kernel32.GenerateConsoleCtrlEvent.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.GenerateConsoleCtrlEvent.restype = wintypes.BOOL
    group_id = int(process_group_id)
    if group_id <= 1:
        raise RuntimeError("refusing an unsafe Windows process-group ID")
    expected = {
        int(pid) for pid in expected_process_ids
        if not isinstance(pid, bool) and int(pid) > 0
    }
    if not expected:
        raise RuntimeError("managed Job has no process to receive CTRL_BREAK")
    capacity = 64
    while True:
        process_ids = (wintypes.DWORD * capacity)()
        count = int(kernel32.GetConsoleProcessList(process_ids, capacity))
        if count <= 0:
            raise ctypes.WinError(ctypes.get_last_error())
        if count <= capacity:
            attached_pids = {
                int(process_ids[index]) for index in range(count)
            }
            break
        if count > 4096:
            raise RuntimeError("supervisor console process list is unexpectedly large")
        capacity = count
    if not (attached_pids & expected):
        raise RuntimeError("no managed Job process is attached to the supervisor console")
    # The root inherited this private console and CREATE_NEW_PROCESS_GROUP was
    # not combined with CREATE_NEW_CONSOLE, so the root PID is a valid group ID.
    if not kernel32.GenerateConsoleCtrlEvent(1, group_id):
        raise ctypes.WinError(ctypes.get_last_error())


def create_pipe(pipe_name, mods=None):
    mods = mods or _modules()
    mode = (
        mods.win32pipe.PIPE_TYPE_MESSAGE
        | mods.win32pipe.PIPE_READMODE_MESSAGE
        | mods.win32pipe.PIPE_WAIT
        | getattr(mods.win32pipe, "PIPE_REJECT_REMOTE_CLIENTS", 0x8)
    )
    return mods.win32pipe.CreateNamedPipe(
        pipe_name,
        mods.win32pipe.PIPE_ACCESS_DUPLEX
        | getattr(mods.win32file, "FILE_FLAG_FIRST_PIPE_INSTANCE", 0x00080000),
        mode,
        4,
        MAX_PIPE_MESSAGE,
        MAX_PIPE_MESSAGE,
        5000,
        security_attributes(mods=mods),
    )


def accept_pipe(pipe, mods=None):
    mods = mods or _modules()
    try:
        mods.win32pipe.ConnectNamedPipe(pipe, None)
    except mods.pywintypes.error as exc:
        # A fast client may connect between CreateNamedPipe and ConnectNamedPipe.
        if getattr(exc, "winerror", exc.args[0] if exc.args else None) != 535:
            raise


def read_pipe(pipe, mods=None):
    mods = mods or _modules()
    chunks = []
    total = 0
    while total < MAX_PIPE_MESSAGE:
        try:
            _, data = mods.win32file.ReadFile(pipe, min(4096, MAX_PIPE_MESSAGE - total))
        except mods.pywintypes.error as exc:
            code = getattr(exc, "winerror", exc.args[0] if exc.args else None)
            if code != 234:  # ERROR_MORE_DATA
                raise
            data = exc.args[2] if len(exc.args) > 2 and isinstance(exc.args[2], bytes) else b""
        chunks.append(data)
        total += len(data)
        if b"\n" in data:
            return b"".join(chunks).split(b"\n", 1)[0]
    raise ValueError("request too large")


def write_pipe(pipe, data, mods=None):
    mods = mods or _modules()
    if len(data) > MAX_PIPE_MESSAGE:
        raise ValueError("response too large")
    mods.win32file.WriteFile(pipe, data)
    mods.win32file.FlushFileBuffers(pipe)


def close_pipe(pipe, mods=None):
    mods = mods or _modules()
    try:
        mods.win32pipe.DisconnectNamedPipe(pipe)
    except Exception:
        pass
    pipe.Close()


def pipe_request(pipe_name, data, timeout=6.0, mods=None):
    mods = mods or _modules()
    deadline = time.monotonic() + max(0.1, float(timeout))
    last_error = None
    while time.monotonic() < deadline:
        remaining_ms = max(1, int((deadline - time.monotonic()) * 1000))
        try:
            mods.win32pipe.WaitNamedPipe(pipe_name, remaining_ms)
            handle = mods.win32file.CreateFile(
                pipe_name,
                mods.win32con.GENERIC_READ | mods.win32con.GENERIC_WRITE,
                0,
                None,
                mods.win32con.OPEN_EXISTING,
                0,
                None,
            )
            try:
                mods.win32pipe.SetNamedPipeHandleState(
                    handle, mods.win32pipe.PIPE_READMODE_MESSAGE, None, None
                )
                mods.win32file.WriteFile(handle, data)
                return read_pipe(handle, mods=mods)
            finally:
                handle.Close()
        except mods.pywintypes.error as exc:
            last_error = exc
            code = getattr(exc, "winerror", exc.args[0] if exc.args else None)
            if code not in (2, 121, 231):  # missing, timeout, pipe busy
                # pywintypes.error is not consistently an OSError subclass.
                # Normalize terminal pipe races (for example ERROR_BROKEN_PIPE
                # after a successful stop response) so the platform-neutral
                # client returns a fail-closed result instead of leaking an
                # implementation exception through state/cleanup callers.
                raise OSError(
                    int(code or 1),
                    str(exc),
                ) from exc
            time.sleep(0.025)
    if last_error:
        raise TimeoutError("supervisor pipe unavailable: %s" % last_error)
    raise TimeoutError("supervisor pipe unavailable")
