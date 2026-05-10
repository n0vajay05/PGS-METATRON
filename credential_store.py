from __future__ import annotations

import ctypes
import os
from ctypes import wintypes


SERVICE_PREFIX = "PGS-Metatron"
DB_PASSWORD_TARGET = f"{SERVICE_PREFIX}:DatabasePassword"
DB_ROOT_PASSWORD_TARGET = f"{SERVICE_PREFIX}:DatabaseRootPassword"
OPENAI_API_KEY_TARGET = f"{SERVICE_PREFIX}:OpenAIApiKey"
CLAUDE_API_KEY_TARGET = f"{SERVICE_PREFIX}:ClaudeApiKey"


if os.name == "nt":
    CRED_TYPE_GENERIC = 1
    CRED_PERSIST_LOCAL_MACHINE = 2

    class CREDENTIAL_ATTRIBUTE(ctypes.Structure):
        _fields_ = [
            ("Keyword", wintypes.LPWSTR),
            ("Flags", wintypes.DWORD),
            ("ValueSize", wintypes.DWORD),
            ("Value", ctypes.POINTER(wintypes.BYTE)),
        ]

    class CREDENTIAL(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(wintypes.BYTE)),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", ctypes.POINTER(CREDENTIAL_ATTRIBUTE)),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]

    advapi32 = ctypes.WinDLL("Advapi32", use_last_error=True)
    advapi32.CredReadW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.POINTER(CREDENTIAL)),
    ]
    advapi32.CredReadW.restype = wintypes.BOOL
    advapi32.CredWriteW.argtypes = [ctypes.POINTER(CREDENTIAL), wintypes.DWORD]
    advapi32.CredWriteW.restype = wintypes.BOOL
    advapi32.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    advapi32.CredDeleteW.restype = wintypes.BOOL
    advapi32.CredFree.argtypes = [ctypes.c_void_p]
    advapi32.CredFree.restype = None


def read_secret(target_name: str) -> str:
    if os.name != "nt":
        return ""
    credential = ctypes.POINTER(CREDENTIAL)()
    if not advapi32.CredReadW(target_name, CRED_TYPE_GENERIC, 0, ctypes.byref(credential)):
        return ""
    try:
        size = int(credential.contents.CredentialBlobSize)
        if size <= 0:
            return ""
        blob = ctypes.string_at(credential.contents.CredentialBlob, size)
        return blob.decode("utf-16-le")
    finally:
        advapi32.CredFree(credential)


def write_secret(target_name: str, secret: str, username: str = "PGS-Metatron") -> bool:
    if os.name != "nt":
        return False
    secret = str(secret or "")
    blob = secret.encode("utf-16-le")
    blob_buffer = ctypes.create_string_buffer(blob)
    credential = CREDENTIAL()
    credential.Type = CRED_TYPE_GENERIC
    credential.TargetName = target_name
    credential.CredentialBlobSize = len(blob)
    credential.CredentialBlob = ctypes.cast(blob_buffer, ctypes.POINTER(wintypes.BYTE))
    credential.Persist = CRED_PERSIST_LOCAL_MACHINE
    credential.UserName = username
    if not advapi32.CredWriteW(ctypes.byref(credential), 0):
        raise ctypes.WinError(ctypes.get_last_error())
    return True


def delete_secret(target_name: str) -> None:
    if os.name != "nt":
        return
    advapi32.CredDeleteW(target_name, CRED_TYPE_GENERIC, 0)
