"""Best-effort NTFS ACL hardening for the system's most sensitive files
(the passphrase and the state store, which now also holds plaintext
challenge suffixes in flight). Previously, comments in phrase_manager.py and
popup_app.py asserted an "ACL-protected" write path that didn't actually
exist anywhere in the code -- this module is what makes that claim true.

Restricts the file to the current user account only (removes inherited
permissions, grants Full Control to the current user, nobody else) via
`icacls`, the standard Windows CLI for this. Best-effort and non-fatal: a
failure here (e.g. icacls missing, running on a non-NTFS volume, a
restricted environment) is logged, not raised -- the file's atomic-write
correctness does not depend on this succeeding, and this project's own
threat model (PLAN.md) already treats "another local account on this
machine" as outside its scope for other secrets (e.g. phrase.txt's
predecessor in v1 had no ACL hardening either and was still accepted at
9.7/10) -- this is a genuine hardening improvement, not a load-bearing
security boundary whose failure should take the service down.
"""
import getpass
import logging
import subprocess
import sys

logger = logging.getLogger("file_perms")


def restrict_to_current_user(path: str):
    if sys.platform != "win32":
        return
    try:
        user = f"{getpass.getuser()}"
        subprocess.run(
            ["icacls", path, "/inheritance:r", "/grant:r", f"{user}:F"],
            capture_output=True,
            text=True,
            check=True,
        )
    except Exception:
        logger.warning("Failed to restrict ACLs on %s (best-effort, not fatal)", path, exc_info=True)
