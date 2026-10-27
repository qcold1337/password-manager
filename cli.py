#!/usr/bin/env python3
"""
Password Manager CLI

Usage:
    python cli.py generate [-l N] [--no-upper] [--no-lower] [--no-digits] [--no-special] [--exclude-ambiguous]
    python cli.py passphrase [-w N] [-s SEP]
    python cli.py vault create <path> [-f]
    python cli.py vault open <path>
    python cli.py vault add <path> <name> <username> [-u URL] [-n NOTES] [-f]
    python cli.py vault get <path> <name> [--show] [--copy]
    python cli.py vault list <path>
    python cli.py vault delete <path> <name> [-f]
    python cli.py vault passwd <path>

The master password is always asked via a hidden prompt. For scripts use
--password-stdin (reads one line from stdin). A password is never accepted
as a command-line argument: it would end up in shell history and `ps`.
"""

import sys
import argparse
from datetime import datetime
from pathlib import Path

# password_manager.py lives next to this file
sys.path.insert(0, str(Path(__file__).resolve().parent))

from password_manager import (  # noqa: E402
    PasswordGenerator, Vault, VaultError, PasswordEntry,
    get_master_password, copy_to_clipboard, strength_label,
)
import getpass  # noqa: E402


def die(message: str, code: int = 1):
    print(message, file=sys.stderr)
    sys.exit(code)


def read_master(args, prompt="Enter master password: ", confirm=False) -> str:
    if getattr(args, "password_stdin", False):
        password = sys.stdin.readline().rstrip("\n")
        if not password:
            die("Error: empty master password on stdin.")
        return password
    return get_master_password(prompt, confirm=confirm)


def open_vault(args) -> Vault:
    """Return an unlocked vault or exit with a clear message."""
    vault = Vault(Path(args.path).expanduser().resolve())
    if not vault.exists():
        die(f"Error: Vault not found at {vault.vault_path}")
    try:
        if not vault.unlock(read_master(args)):
            die("❌ Incorrect master password!")
    except VaultError as e:
        die(f"❌ {e}. Try {vault.vault_path.name}.bak if you have one.")
    return vault


def cmd_generate(args):
    gen = PasswordGenerator()
    opts = dict(
        use_uppercase=not args.no_upper,
        use_lowercase=not args.no_lower,
        use_digits=not args.no_digits,
        use_special=not args.no_special,
        exclude_ambiguous=args.exclude_ambiguous,
    )
    try:
        pwd = gen.generate(length=args.length, **opts)
        bits = gen.entropy_bits(args.length, **opts)
    except ValueError as e:
        die(f"Error: {e}")
    print(pwd)
    note = f"~{bits:.0f} bits ({strength_label(bits)})"
    if args.length < 12:
        note += " - short, 12+ recommended"
    print(note, file=sys.stderr)


def cmd_passphrase(args):
    gen = PasswordGenerator()
    words = args.words or (8 if gen.using_fallback else 6)
    try:
        phrase = gen.generate_passphrase(words, args.separator)
    except ValueError as e:
        die(f"Error: {e}")
    print(phrase)
    bits = gen.passphrase_entropy_bits(words)
    print(f"~{bits:.0f} bits ({strength_label(bits)})", file=sys.stderr)
    if gen.using_fallback:
        print("Warning: small built-in wordlist. Put eff_large_wordlist.txt "
              "next to the script.", file=sys.stderr)


def cmd_vault_create(args):
    path = Path(args.path).expanduser().resolve()
    vault = Vault(path)
    if vault.exists() and not args.force:
        die(f"Error: Vault already exists at {path}. Use --force to overwrite.")
    master = read_master(args, "Create master password: ", confirm=True)
    if vault.exists():
        print(f"Old vault backed up to {vault.backup()}")
    vault.create(master, overwrite=True)
    print(f"✅ Vault created at {path}")


def cmd_vault_open(args):
    open_vault(args)
    print("✅ Vault unlocked successfully!")


def cmd_vault_add(args):
    vault = open_vault(args)
    gen = PasswordGenerator()

    created_at = None
    if vault.has_entry(args.name):
        if not args.force:
            die(f"Entry '{args.name}' already exists. Use --force to overwrite.")
        created_at = vault.get_entry(args.name).created_at

    password = getpass.getpass("Entry password (hidden, empty = generate): ").strip()
    if not password:
        password = gen.generate(length=20)
        print(f"Generated password: {password}")

    now = datetime.now().isoformat(timespec="seconds")
    vault.add_entry(PasswordEntry(
        name=args.name, username=args.username, password=password,
        url=args.url or "", notes=args.notes or "",
        created_at=created_at or now, updated_at=now))
    vault.save()
    print(f"✅ Entry '{args.name}' saved!")


def cmd_vault_get(args):
    vault = open_vault(args)
    entry = vault.get_entry(args.name)
    if not entry:
        die(f"Entry '{args.name}' not found.")
    print(f"Name: {entry.name}")
    print(f"Username: {entry.username}")
    if entry.url:
        print(f"URL: {entry.url}")
    if entry.notes:
        print(f"Notes: {entry.notes}")
    print(f"Created: {entry.created_at}")
    print(f"Updated: {entry.updated_at}")
    if args.copy:
        copy_to_clipboard(entry.password)
    if args.show:
        print(f"Password: {entry.password}")
    if not (args.copy or args.show):
        print("(password hidden: use --show or --copy)")


def cmd_vault_list(args):
    vault = open_vault(args)
    keys = vault.list_entries()
    if not keys:
        print("No entries found.")
        return
    for key in keys:
        entry = vault.get_entry(key)
        if entry:
            print(f"  {entry.name} ({entry.username})")


def cmd_vault_delete(args):
    vault = open_vault(args)
    if not vault.has_entry(args.name):
        die(f"Entry '{args.name}' not found.")
    if not args.force:
        if input(f"Delete '{args.name}'? This cannot be undone! (y/N): ").lower() != "y":
            print("Cancelled.")
            return
    vault.delete_entry(args.name)
    vault.save()
    print(f"✅ Entry '{args.name}' deleted.")


def cmd_vault_passwd(args):
    vault = open_vault(args)
    new = get_master_password("New master password: ", confirm=True)
    vault.change_master_password(new)
    print("✅ Master password changed (old vault saved as .bak, still "
          "encrypted with the OLD password).")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Password Manager CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py generate -l 20
  python cli.py passphrase -w 6
  python cli.py vault create ~/.my_vault.json
  python cli.py vault add ~/.my_vault.json GitHub myuser
  python cli.py vault get ~/.my_vault.json GitHub --copy
  python cli.py vault list ~/.my_vault.json
""",
    )
    sub = parser.add_subparsers(dest="command")

    g = sub.add_parser("generate", help="Generate a password")
    g.add_argument("-l", "--length", type=int, default=16)
    g.add_argument("--no-upper", action="store_true")
    g.add_argument("--no-lower", action="store_true")
    g.add_argument("--no-digits", action="store_true")
    g.add_argument("--no-special", action="store_true")
    g.add_argument("--exclude-ambiguous", action="store_true")
    g.set_defaults(func=cmd_generate)

    p = sub.add_parser("passphrase", help="Generate a passphrase")
    p.add_argument("-w", "--words", type=int, default=None,
                   help="Number of words (default: 6, or 8 with the small wordlist)")
    p.add_argument("-s", "--separator", default="-")
    p.set_defaults(func=cmd_passphrase)

    v = sub.add_parser("vault", help="Vault operations")
    vs = v.add_subparsers(dest="vault_command")

    def vault_parser(name, help_text, func, with_name=False):
        sp = vs.add_parser(name, help=help_text)
        sp.add_argument("path", help="Vault file path")
        if with_name:
            sp.add_argument("name", help="Entry name")
        sp.add_argument("--password-stdin", action="store_true",
                        help="Read master password from stdin (for scripts)")
        sp.set_defaults(func=func)
        return sp

    c = vault_parser("create", "Create a new vault", cmd_vault_create)
    c.add_argument("-f", "--force", action="store_true", help="Overwrite (old one is backed up)")

    vault_parser("open", "Open/verify vault", cmd_vault_open)

    a = vault_parser("add", "Add entry", cmd_vault_add, with_name=True)
    a.add_argument("username", help="Username/email")
    a.add_argument("-u", "--url")
    a.add_argument("-n", "--notes")
    a.add_argument("-f", "--force", action="store_true", help="Overwrite existing entry")

    ge = vault_parser("get", "Get entry", cmd_vault_get, with_name=True)
    ge.add_argument("--show", action="store_true", help="Print the password")
    ge.add_argument("--copy", action="store_true", help="Copy password to clipboard (Termux:API)")

    vault_parser("list", "List entries", cmd_vault_list)

    d = vault_parser("delete", "Delete entry", cmd_vault_delete, with_name=True)
    d.add_argument("-f", "--force", action="store_true", help="Skip confirmation")

    vault_parser("passwd", "Change master password", cmd_vault_passwd)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    if not getattr(args, "func", None):
        parser.print_help()
        sys.exit(1)
    try:
        args.func(args)
    except KeyboardInterrupt:
        die("\nCancelled.", 130)


if __name__ == "__main__":
    main()
