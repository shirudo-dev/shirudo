#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

"""Run the commands and create the example files shown in the quick guides."""

import argparse
import re
import shlex
import subprocess
import sys
import uuid
from pathlib import Path
from textwrap import dedent

ROOT = Path(__file__).resolve().parents[2]
START = Path("Documentation/start")
TUTORIALS = ("attest-target", "first-upatch", "publish-package")
BLOCK = re.compile(r"^( *)\.\. code-block:: (\w+)$")
DIRECTIVE = re.compile(r"^ *\.\. guide-check: (\w+)(?: (.+))?$")
PROMPT = re.compile(r"^(operator\$|target#|\$) (.+)$")
MODES = {
    "boot", "capture", "connect", "fail", "guides", "match", "registry",
    "remove", "skip", "stop", "write",
}
PLACEHOLDER = re.compile(r"<([a-z][a-z0-9-]*)>")


def examples(page):
    lines = (ROOT / page).read_text().splitlines()
    action = ("run", "")
    for i, line in enumerate(lines):
        directive = DIRECTIVE.fullmatch(line)
        if directive:
            mode, argument = directive.groups()
            if mode not in MODES or bool(argument) != (mode in ("capture", "fail", "match", "write")):
                raise ValueError(f"{page}:{i + 1}: invalid guide-check comment")
            action = (mode, argument or "")
            continue
        block = BLOCK.fullmatch(line)
        if not block:
            continue
        indent, language = block.groups()
        end = i + 1
        while end < len(lines):
            body_line = lines[end]
            if body_line.strip() and not body_line.startswith(indent + " "):
                break
            end += 1
        first = i + 1
        while first < end and not lines[first].strip():
            first += 1
        body = dedent("\n".join(lines[first:end])).splitlines()
        mode, argument = action
        action = ("run", "")
        if mode == "write":
            yield f"{page}:{i + 1}", "operator$", "\n".join(body), mode, argument
            continue
        if language != "console":
            if mode != "run":
                raise ValueError(f"{page}:{i + 1}: {mode} requires a console block")
            continue
        commands = []
        n = 0
        while n < len(body):
            prompt = PROMPT.fullmatch(body[n])
            if not prompt:
                n += 1
                continue
            at = f"{page}:{first + n + 1}"
            side, command = prompt.groups()
            while command.endswith("\\"):
                n += 1
                if n == len(body):
                    raise ValueError(f"{at}: unfinished shell continuation")
                command += "\n" + body[n]
            commands.append((at, side, command))
            n += 1
        for step in commands[:-1]:
            yield *step, "run", ""
        if commands:
            yield *commands[-1], mode, argument
        elif mode != "run":
            raise ValueError(f"{page}:{i + 1}: {mode} has no command")
    if action[0] != "run":
        raise ValueError(f"{page}: guide-check comment has no block")


def plan():
    for step in examples(START / "quickstart.rst"):
        if step[3] == "guides":
            for tutorial in TUTORIALS:
                yield from examples(START / "guides" / f"{tutorial}.rst")
        yield step


class Shell:
    def __init__(self, argv):
        self.process = subprocess.Popen(
            argv, cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, errors="replace",
        )
        self.marker = f"guide-{uuid.uuid4().hex}"
        status, _ = self.run("set -o pipefail; shopt -s expand_aliases")
        if status:
            raise RuntimeError("could not initialize the guide shell")

    def run(self, command):
        self.process.stdin.write(
            f"{command}\nprintf '\\n{self.marker} %d\\n' \"$?\"\n"
        )
        self.process.stdin.flush()
        output = []
        for line in self.process.stdout:
            if line.startswith(self.marker + " "):
                return int(line.split()[1]), "".join(output).removesuffix("\n")
            print(line, end="", flush=True)
            output.append(line)
        raise RuntimeError("shell closed before reporting the command's status")

    def close(self, command=None):
        try:
            if command:
                self.process.stdin.write(command + "\n")
            self.process.stdin.close()
        except BrokenPipeError:
            # A shell that closed its input can still have output to drain.
            pass
        for line in self.process.stdout:
            print(line, end="", flush=True)
        self.process.stdout.close()
        return self.process.wait()


def run(steps):
    bash = ["bash", "--noprofile", "--norc", "-s"]
    host = Shell(bash)
    guest = None
    values = {}
    vm_started = False
    registry_started = False
    at = "guide prerequisites"
    try:
        status, _ = host.run(
            'test ! -e "$HOME/hello" && test ! -e "$HOME/hello-1.0.0.bee" '
            '&& test ! -e build/test-vm/vms/quickstart '
            '&& test ! -e basic.upatch && test ! -e basic.unload.upatch '
            '&& test ! -e build/tutorial'
        )
        if status:
            raise RuntimeError("use a fresh checkout and unused guide instance names")

        for at, side, command, mode, argument in steps:
            if mode == "skip":
                continue
            description = f"write {argument}" if mode == "write" else f"{side} {command}"
            print(f"\n{at} {description}", flush=True)
            if mode == "connect":
                shell_command = shlex.split(command)
                shell_command.append("VM_SSH_COMMAND=" + shlex.join(bash))
                shell_command.insert(1, "-s")
                guest = Shell(shell_command)
                # make vm-ssh sets this alias in a terminal's shell only.
                if guest.run("alias shirudo=shirudo-runtime")[0]:
                    raise RuntimeError("could not name the runtime binary")
                continue
            if mode == "guides":
                if guest.close(command):
                    raise RuntimeError("target shell failed to exit")
                guest = None
                if host.run(f"cd {shlex.quote(str(ROOT))}")[0]:
                    raise RuntimeError("could not return to the checkout")
                continue
            shell = guest if side == "target#" else host
            if shell is None:
                raise RuntimeError("guide command needs an open guest shell")
            if mode == "write":
                if argument.startswith("~/"):
                    path = '"$HOME"/' + shlex.quote(argument[2:])
                else:
                    path = shlex.quote(argument)
                command = f"printf '%s\\n' {shlex.quote(command)} > {path}"
            else:
                command = PLACEHOLDER.sub(lambda m: values[m[1]], command)
            if mode == "registry":
                command += " </dev/null"
            if mode == "boot":
                vm_started = True
                command += " </dev/null"
            status, output = shell.run(command)
            if mode == "fail":
                if not status or not re.search(argument, output, re.MULTILINE):
                    raise RuntimeError(f"expected failure matching {argument!r}, got {status}")
                continue
            if status:
                raise RuntimeError(f"command exited with status {status}")
            if mode == "match" and not re.search(argument, output, re.MULTILINE):
                raise RuntimeError(f"output did not match {argument!r}")
            if mode == "capture":
                match = re.search(r"^(?:\w+: )?([0-9a-f]{64})$", output.rstrip().split("\n")[-1])
                if not match:
                    raise RuntimeError(f"expected a hex value for <{argument}>")
                values[argument] = match[1]
            if mode == "registry":
                registry_started = True
            if mode == "remove":
                registry_started = False
            if mode == "stop":
                vm_started = False
    except (KeyError, OSError, RuntimeError) as error:
        print(f"{at}: {error}", file=sys.stderr)
        return 1
    finally:
        if guest:
            guest.close()
        if registry_started:
            host.run("docker rm -f shirudo-registry")
        if vm_started:
            host.run(f"make -C {shlex.quote(str(ROOT / 'testing'))} vm-stop VM_NAME=quickstart")
        host.close()
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="show the steps without running them")
    args = parser.parse_args()
    try:
        steps = list(plan())
    except ValueError as error:
        return parser.error(str(error))
    if args.list:
        for at, side, command, mode, argument in steps:
            print(f"{at} {side} [{mode} {argument}] {command.splitlines()[0]}")
        return 0
    return run(steps)


if __name__ == "__main__":
    sys.exit(main())
