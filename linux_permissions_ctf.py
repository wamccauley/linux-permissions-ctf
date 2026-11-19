#!/usr/bin/env python3
"""Install and check a small, state-based Linux permissions CTF."""

import argparse
import grp
import json
import os
import pwd
import secrets
import shutil
import stat
import subprocess
import sys
from pathlib import Path


STATE_DIR = Path("/var/lib/linux-permissions-ctf")
STATE_FILE = STATE_DIR / "lab.json"
MILESTONES = (
    ("account", "Create the jack account"),
    ("groups", "Configure team and administrator group membership"),
    ("report", "Set the report ownership and mode"),
    ("lock", "Lock the contractor account"),
    ("unlock", "Unlock the contractor account"),
    ("final-lock", "Lock the contractor account again"),
    ("umask", "Create a file and directory with restricted default modes"),
    ("sticky", "Configure the shared drop box"),
    ("setgid", "Configure the team directory"),
    ("inheritance", "Create a team file with inherited group ownership"),
)

STUDENT_GUIDE = """Linux permissions CTF

Read this guide with: cat ~/linux-permissions-ctf/INSTRUCTIONS.txt

This lab practices Linux users, groups, and file permissions. After completing
each task, check it and copy the flag from the output:

  sudo python3 ~/linux-permissions-ctf/linux_permissions_ctf.py check MILESTONE

Replace MILESTONE with the ID shown below. List all IDs with:

  python3 ~/linux-permissions-ctf/linux_permissions_ctf.py list

Use your own login and home directory for the participant. In your shell, run:

  LAB_USER=$(whoami)
  PROJECT="$HOME/project"
  export PROJECT

1. account: Create user jack with a home directory, a same-named primary group,
   and /bin/bash as the login shell. Check account.
2. groups: Create developers; append jack to developers and sudo, and append
   $LAB_USER to developers. Check groups. Existing shells do not automatically
   acquire new group memberships.
3. report: Create $PROJECT/secure-report.txt, owned by jack:developers with
   mode 640. Check report.
4. lock: Lock password authentication for contractor with usermod -L; check lock.
5. unlock: Unlock it with usermod -U; check unlock.
6. final-lock: Lock it again and check final-lock. Do not display the password hash.
7. umask: Create $PROJECT/umask-demo, save your current umask, set it to 027,
   and create private-note.txt and private-dir inside it. Restore your original
   umask. The file and directory should have modes 640 and 750. Check umask.
8. sticky: Create /tmp/shared-dropbox with mode 1777. Create jack-note.txt as
   jack and contractor-note.txt as contractor. As jack, try to remove the
   contractor's file; it should be denied. Check sticky.
9. setgid: Create $PROJECT/team-share, owned by jack:developers, with mode
   2770. Check setgid.
10. inheritance: Start a child shell with newgrp developers, then create
    $PROJECT/team-share/labex-note.txt as the participant. It should belong to
    the participant and group developers. Check inheritance, then exit the child
    shell. If newgrp asks for a password, cancel and check your group membership.

The lock, unlock, and final-lock checks must be completed in that order before
changing the account state again. Rechecking a completed milestone still requires
its current state to match. A failed check describes the required state without
revealing the flag.

You can use sudo -u contractor to create a file even while contractor password
authentication is locked. Use stat, id, and groups to inspect results.
"""


class LabError(Exception):
    pass


def account(name):
    try:
        return pwd.getpwnam(name)
    except KeyError:
        return None


def group(name):
    try:
        return grp.getgrnam(name)
    except KeyError:
        return None


def members_group(user, group_name):
    entry = account(user)
    target = group(group_name)
    return bool(entry and target and target.gr_gid in os.getgrouplist(user, entry.pw_gid))


def matches(path, kind, owner=None, group_name=None, mode=None):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if not kind(info.st_mode):
        return False
    if owner is not None:
        entry = account(owner)
        if not entry or info.st_uid != entry.pw_uid:
            return False
    if group_name is not None:
        entry = group(group_name)
        if not entry or info.st_gid != entry.gr_gid:
            return False
    return mode is None or stat.S_IMODE(info.st_mode) == mode


def password_state(name):
    try:
        with open("/etc/shadow", encoding="utf-8") as shadow:
            for line in shadow:
                fields = line.rstrip("\n").split(":")
                if fields[0] == name and len(fields) > 1:
                    value = fields[1]
                    if value.startswith("!"):
                        return "locked"
                    if value and not value.startswith("*"):
                        return "unlocked"
                    return "unusable"
    except OSError as exc:
        raise LabError(f"Cannot read account status from /etc/shadow: {exc}") from exc
    return "missing"


def check_milestone(milestone, lab):
    user = lab["user"]
    project = Path(lab["project"])
    contractor = account("contractor")
    jack = account("jack")
    jack_group = group("jack")
    if milestone == "account":
        return bool(
            jack and jack_group and jack.pw_gid == jack_group.gr_gid
            and jack.pw_shell == "/bin/bash"
            and matches(Path(jack.pw_dir), stat.S_ISDIR, owner="jack", group_name="jack")
        ), "Create jack with a same-named primary group, home directory, and Bash shell."
    if milestone == "groups":
        return bool(
            members_group("jack", "developers")
            and members_group("jack", "sudo")
            and members_group(user, "developers")
        ), f"Add jack to developers and sudo, and add {user} to developers."
    if milestone == "report":
        return matches(
            project / "secure-report.txt", stat.S_ISREG,
            owner="jack", group_name="developers", mode=0o640,
        ), "Set secure-report.txt to jack:developers and mode 640."
    if milestone in ("lock", "unlock", "final-lock"):
        prerequisite = {"unlock": "lock", "final-lock": "unlock"}.get(milestone)
        if prerequisite and prerequisite not in lab["completed"]:
            return False, f"First complete and check the {prerequisite} milestone."
        expected = "unlocked" if milestone == "unlock" else "locked"
        return bool(contractor and password_state("contractor") == expected), (
            f"Set the contractor password authentication state to {expected}."
        )
    if milestone == "umask":
        directory = project / "umask-demo"
        return (
            matches(directory / "private-note.txt", stat.S_ISREG, mode=0o640)
            and matches(directory / "private-dir", stat.S_ISDIR, mode=0o750)
        ), "The umask-demo file must have mode 640 and the directory mode 750."
    if milestone == "sticky":
        dropbox = Path("/tmp/shared-dropbox")
        return (
            matches(dropbox, stat.S_ISDIR, mode=0o1777)
            and matches(dropbox / "jack-note.txt", stat.S_ISREG, owner="jack")
            and matches(dropbox / "contractor-note.txt", stat.S_ISREG, owner="contractor")
        ), "Set the drop box to mode 1777 and create a file owned by each practice account."
    if milestone == "setgid":
        return matches(
            project / "team-share", stat.S_ISDIR,
            owner="jack", group_name="developers", mode=0o2770,
        ), "Set team-share to jack:developers and mode 2770."
    if milestone == "inheritance":
        return (
            matches(project / "team-share", stat.S_ISDIR,
                    owner="jack", group_name="developers", mode=0o2770)
            and matches(project / "team-share" / "labex-note.txt", stat.S_ISREG,
                        owner=user, group_name="developers")
        ), f"Create labex-note.txt in team-share as {user}, with group developers."
    raise LabError(f"Unknown milestone: {milestone}")


def save_lab(lab):
    # The containing directory is root-only; replace avoids partial JSON on interruption.
    temporary = STATE_DIR / "lab.json.tmp"
    fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(lab, stream, indent=2)
        stream.write("\n")
    os.replace(temporary, STATE_FILE)


def load_lab():
    try:
        with STATE_FILE.open(encoding="utf-8") as stream:
            lab = json.load(stream)
        if (not isinstance(lab, dict) or lab.get("version") != 1
                or lab.get("installed") is not True
                or not isinstance(lab.get("user"), str)
                or not isinstance(lab.get("project"), str)
                or not isinstance(lab.get("completed"), list)
                or not isinstance(lab.get("flags"), dict)
                or set(lab.get("flags", {})) != {key for key, _ in MILESTONES}):
            raise LabError("Invalid lab state; do not overwrite it. Ask the administrator to inspect it.")
        return lab
    except FileNotFoundError as exc:
        raise LabError("The lab is not installed. Run the install command first.") from exc
    except (OSError, ValueError, TypeError) as exc:
        raise LabError(f"Cannot read lab state: {exc}") from exc


def require_root():
    if os.geteuid() != 0:
        raise LabError("Run this command as root, for example with sudo.")


def run_command(arguments, input_text=None):
    try:
        subprocess.run(arguments, input=input_text, text=True, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise LabError(f"Command failed: {arguments[0]}: {exc}") from exc


def install(user):
    require_root()
    if STATE_DIR.exists():
        raise LabError(f"{STATE_DIR} already exists; refusing to overwrite the lab.")
    entry = account(user)
    if not entry or entry.pw_uid == 0:
        raise LabError("Choose an existing, non-root Linux account for --user.")
    if not Path(entry.pw_dir).is_dir():
        raise LabError(f"The lab user's home directory does not exist: {entry.pw_dir}")
    if not group("sudo"):
        raise LabError("This lab requires a Debian-style sudo group.")
    for name in ("jack", "contractor"):
        if account(name) or group(name):
            raise LabError(f"User or group {name} already exists; use a fresh, disposable VM.")
        if (Path("/home") / name).exists():
            raise LabError(f"/home/{name} already exists; use a fresh, disposable VM.")
    if group("developers"):
        raise LabError("Group developers already exists; use a fresh, disposable VM.")
    if Path("/tmp/shared-dropbox").exists():
        raise LabError("/tmp/shared-dropbox already exists; use a fresh, disposable VM.")
    project = Path(entry.pw_dir) / "project"
    if project.exists():
        raise LabError(f"{project} already exists; use a fresh, disposable VM.")
    materials = Path(entry.pw_dir) / "linux-permissions-ctf"
    if materials.exists() or materials.is_symlink():
        raise LabError(f"{materials} already exists; refusing to overwrite it.")
    for command in ("useradd", "usermod", "chpasswd"):
        if not shutil.which(command):
            raise LabError(f"Required command not found: {command}")

    lab = {
        "version": 1,
        "installed": False,
        "lab_id": secrets.token_hex(16),
        "user": user,
        "project": str(project),
        "flags": {key: f"FLAG{{{secrets.token_hex(16)}}}" for key, _ in MILESTONES},
        "completed": [],
    }
    try:
        STATE_DIR.mkdir(mode=0o700, parents=True)
        os.chmod(STATE_DIR, 0o700)
        save_lab(lab)
        run_command(["useradd", "-m", "-U", "-d", "/home/contractor", "-s", "/bin/bash", "contractor"])
        # A random, undisclosed password gives the account a lockable password hash.
        run_command(["chpasswd"], f"contractor:{secrets.token_hex(32)}\n")
        run_command(["usermod", "-a", "-G", "sudo", "--", user])
        project.mkdir(mode=0o755)
        os.chown(project, entry.pw_uid, entry.pw_gid)
        materials.mkdir(mode=0o755)
        materials.chmod(0o755)
        checker = materials / "linux_permissions_ctf.py"
        shutil.copyfile(Path(__file__).resolve(), checker)
        checker.chmod(0o644)
        instructions = materials / "INSTRUCTIONS.txt"
        instructions.write_text(STUDENT_GUIDE, encoding="utf-8")
        instructions.chmod(0o644)
        lab["installed"] = True
        save_lab(lab)
    except (OSError, LabError) as exc:
        raise LabError(
            f"Installation failed: {exc}. The VM may contain partial lab state; "
            "inspect it or replace the disposable VM before retrying."
        ) from exc
    print(f"Installed lab {lab['lab_id']} for {user}. Project: {project}")
    print(f"Log in again as {user} to activate sudo group membership.")
    print("Export the answer key privately. The participant can read instructions with:")
    print("  cat ~/linux-permissions-ctf/INSTRUCTIONS.txt")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    install_parser = commands.add_parser("install", help="initialize a fresh disposable lab VM")
    install_parser.add_argument("--user", required=True, help="existing non-root participant account")
    commands.add_parser("list", help="list milestone identifiers")
    check_parser = commands.add_parser("check", help="check a milestone and reveal its flag")
    check_parser.add_argument("milestone", choices=[key for key, _ in MILESTONES])
    commands.add_parser("export", help="print the private JSON answer key")
    args = parser.parse_args(argv)
    try:
        if args.command == "install":
            install(args.user)
        elif args.command == "list":
            for key, description in MILESTONES:
                print(f"{key:12} {description}")
        elif args.command == "export":
            require_root()
            lab = load_lab()
            print(json.dumps({
                "lab_id": lab["lab_id"],
                "flags": [{"milestone": key, "flag": lab["flags"][key]} for key, _ in MILESTONES],
            }, indent=2))
        else:
            require_root()
            lab = load_lab()
            passed, message = check_milestone(args.milestone, lab)
            if not passed:
                print(f"Not complete: {message}", file=sys.stderr)
                return 1
            if args.milestone not in lab["completed"]:
                lab["completed"].append(args.milestone)
                save_lab(lab)
            print(f"{args.milestone}: {lab['flags'][args.milestone]}")
        return 0
    except (LabError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
