#!/usr/bin/env python3
"""Run bounded archive checks with inert files. Do not execute archive content."""

import ast
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "build-macos/django-source"
DATA = ROOT / "build-macos/django-security"
COMMIT = "f16e25dcb9fe55734ba4ea2b00ac34405b7df74a"
MARKER = b"Inert security-review marker. Never execute this file.\n"


def write_archive(path, kind, member_name, mode):
    if kind == "zip":
        member = zipfile.ZipInfo(member_name)
        member.create_system = 3
        member.external_attr = (stat.S_IFREG | mode) << 16
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(member, MARKER)
    else:
        member = tarfile.TarInfo(member_name)
        member.size, member.mode = len(MARKER), mode
        with tarfile.open(path, "w") as archive:
            archive.addfile(member, io.BytesIO(MARKER))


def main():
    assert subprocess.check_output(["git", "-C", str(SOURCE), "rev-parse", "HEAD"], text=True).strip() == COMMIT
    assert not subprocess.check_output(["git", "-C", str(SOURCE), "status", "--porcelain", "--untracked-files=all"], text=True)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(SOURCE))
    from django.core.exceptions import SuspiciousOperation
    from django.utils.archive import BaseArchive, extract

    tree = ast.parse((SOURCE / "django/core/management/templates.py").read_text())
    command = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "TemplateCommand")
    method = next(node for node in command.body if isinstance(node, ast.FunctionDef) and node.name == "apply_umask")
    namespace = {"os": os, "stat": stat}
    exec(compile(ast.Module(body=[method], type_ignores=[]), "<pinned TemplateCommand.apply_umask>", "exec"), namespace)
    report = dict(commit_sha=COMMIT, uid=os.getuid(), application_started=False,
                  archive_content_executed=False, symlink_checks=[], permission_checks=[])
    with tempfile.TemporaryDirectory(prefix="archive-hunt-", dir=DATA) as folder:
        work = Path(folder)
        for kind in ("tar", "zip"):
            destination, sibling = work / f"{kind}-destination", work / f"{kind}-sibling"
            destination.mkdir()
            sibling.mkdir()
            (destination / "bridge").symlink_to(sibling, target_is_directory=True)
            payload = work / f"symlink.{kind}"
            write_archive(payload, kind, "bundle/bridge/marker.txt", 0o644)
            extract(str(payload), str(destination))
            outside = sibling / "marker.txt"
            report["symlink_checks"].append(dict(format=kind,
                escaped_requested_directory=outside.is_file() and outside.read_bytes() == MARKER,
                remained_inside_owned_temporary_directory=True))

            mode_destination = work / f"{kind}-permissions"
            mode_destination.mkdir()
            payload = work / f"permissions.{kind}"
            write_archive(payload, kind, "bundle/marker.txt", 0o6755)
            extract(str(payload), str(mode_destination))
            old_path, new_path = mode_destination / "marker.txt", work / f"{kind}-copied-marker.txt"
            new_path.write_bytes(MARKER)
            namespace["apply_umask"](None, old_path, new_path)
            extracted_mode = stat.S_IMODE(old_path.stat().st_mode)
            copied_mode = stat.S_IMODE(new_path.stat().st_mode)
            report["permission_checks"].append(dict(format=kind, requested_mode="0o6755",
                extracted_mode=oct(extracted_mode), scaffold_copy_mode=oct(copied_mode),
                setuid_retained=bool(extracted_mode & stat.S_ISUID),
                setgid_retained=bool(extracted_mode & stat.S_ISGID)))

        try:
            BaseArchive().target_filename(str(work / "root"), "../outside.txt")
        except SuspiciousOperation:
            report["plain_parent_traversal_rejected"] = True
        else:
            report["plain_parent_traversal_rejected"] = False
    assert not subprocess.check_output(["git", "-C", str(SOURCE), "status", "--porcelain", "--untracked-files=all"], text=True)
    (DATA / "archive-hunt-probes.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
