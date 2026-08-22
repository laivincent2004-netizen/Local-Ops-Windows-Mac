"""Windows current-user identity and private ACL helpers.

The module imports pywin32 lazily so importing the macOS server keeps its
standard-library-only runtime.  Windows release builds include pywin32 and
fail closed when an ACL cannot be applied.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Optional

from .base import AdapterUnavailable


_MODULES: Optional[tuple[Any, Any, Any]] = None


def _pywin32() -> tuple[Any, Any, Any]:
    global _MODULES
    if _MODULES is not None:
        return _MODULES
    try:
        import ntsecuritycon
        import win32api
        import win32security
    except (ImportError, OSError) as exc:
        raise AdapterUnavailable(
            "Windows 私有 ACL 需要随安装包提供 pywin32") from exc
    _MODULES = (win32security, ntsecuritycon, win32api)
    return _MODULES


def current_user_sid() -> str:
    win32security, _ntsecuritycon, win32api = _pywin32()
    token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
    sid = win32security.GetTokenInformation(
        token, win32security.TokenUser)[0]
    return str(win32security.ConvertSidToStringSid(sid))


def sid_for_username(username: str) -> Optional[str]:
    if not isinstance(username, str) or not username.strip():
        return None
    try:
        win32security, _ntsecuritycon, _win32api = _pywin32()
        sid, _domain, _kind = win32security.LookupAccountName(
            None, username.strip())
        return str(win32security.ConvertSidToStringSid(sid))
    except Exception:
        return None


def secure_private_path(path: str, *, directory: bool = False,
                        required: Optional[bool] = None) -> bool:
    """Protect ``path`` so only the current user and SYSTEM have access.

    Development source runs may omit pywin32 and return ``False``.  Frozen
    Windows builds always require the ACL, since config files contain command
    tokens and supervisor control metadata.
    """
    if os.name != "nt":
        return True
    if required is None:
        required = bool(getattr(sys, "frozen", False))
    try:
        win32security, ntsecuritycon, _win32api = _pywin32()
        user_sid_text = current_user_sid()
        user_sid = win32security.ConvertStringSidToSid(user_sid_text)
        system_sid = win32security.CreateWellKnownSid(
            win32security.WinLocalSystemSid, None)
        acl = win32security.ACL()
        access = ntsecuritycon.FILE_ALL_ACCESS
        inheritance = 0
        if directory:
            inheritance = (
                ntsecuritycon.CONTAINER_INHERIT_ACE
                | ntsecuritycon.OBJECT_INHERIT_ACE
            )
        acl.AddAccessAllowedAceEx(
            win32security.ACL_REVISION_DS, inheritance, access, user_sid)
        acl.AddAccessAllowedAceEx(
            win32security.ACL_REVISION_DS, inheritance, access, system_sid)
        flags = (
            win32security.DACL_SECURITY_INFORMATION
            | win32security.PROTECTED_DACL_SECURITY_INFORMATION
        )
        win32security.SetNamedSecurityInfo(
            os.path.abspath(path), win32security.SE_FILE_OBJECT,
            flags, None, None, acl, None)
        return True
    except Exception as exc:
        if required:
            raise AdapterUnavailable(
                "无法为 Windows 私有路径设置当前用户 DACL: %s" % path
            ) from exc
        return False


def private_path_is_secure(path: str) -> Optional[bool]:
    """Return whether a path's protected DACL names only user and SYSTEM.

    ``None`` means ACL inspection is unavailable in a source checkout.  A
    frozen build never treats ``None`` as acceptable when creating paths.
    """
    if os.name != "nt":
        return True
    try:
        win32security, _ntsecuritycon, _win32api = _pywin32()
        allowed = {
            current_user_sid().casefold(),
            str(win32security.ConvertSidToStringSid(
                win32security.CreateWellKnownSid(
                    win32security.WinLocalSystemSid, None))).casefold(),
        }
        descriptor = win32security.GetNamedSecurityInfo(
            os.path.abspath(path), win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION)
        control, _revision = descriptor.GetSecurityDescriptorControl()
        if not (control & win32security.SE_DACL_PROTECTED):
            return False
        dacl = descriptor.GetSecurityDescriptorDacl()
        if dacl is None:
            return False
        present = set()
        for index in range(dacl.GetAceCount()):
            ace = dacl.GetAce(index)
            header = ace[0]
            ace_type = int(header[0])
            sid = ace[2]
            sid_text = str(win32security.ConvertSidToStringSid(sid)).casefold()
            if ace_type == win32security.ACCESS_ALLOWED_ACE_TYPE:
                if sid_text not in allowed:
                    return False
                present.add(sid_text)
        return allowed.issubset(present)
    except Exception:
        return None
