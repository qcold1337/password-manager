#!/usr/bin/env python3
"""
Reliable Password Generator and Manager
=======================================
Secure password generator with an encrypted vault.

- Passwords/passphrases: `secrets` (CSPRNG), entropy estimate shown
- Vault: AES-256-GCM, PBKDF2-HMAC-SHA256 (600k iterations, stored in file)
- Header (version/kdf/iterations/salt) is authenticated via GCM associated data
- Atomic writes, file permissions 600, backup before overwriting a vault
- Old v1 vaults are opened and upgraded automatically
- Termux: copy to clipboard with auto-clear (needs `pkg install termux-api`)

Passphrases: put the EFF large wordlist next to this script as
`eff_large_wordlist.txt` (7776 words, ~12.9 bits/word):
  curl -o eff_large_wordlist.txt https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
"""

import os
import json
import math
import time
import shutil
import base64
import getpass
import secrets
import string
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict, fields

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

AUTOLOCK_SECONDS = 300
CLIPBOARD_CLEAR_SECONDS = 30
MIN_MASTER_LENGTH = 10


@dataclass
class PasswordEntry:
    """Represents a stored password entry."""
    name: str
    username: str
    password: str
    url: str = ""
    notes: str = ""
    created_at: str = ""
    updated_at: str = ""


# --------------------------------------------------------------------------
# Generator
# --------------------------------------------------------------------------

FALLBACK_WORDS = [
    "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf",
    "hotel", "india", "juliet", "kilo", "lima", "mike", "november",
    "oscar", "papa", "quebec", "romeo", "sierra", "tango", "uniform",
    "victor", "whiskey", "xray", "yankee", "zulu", "apple", "banana",
    "cherry", "dragon", "eagle", "forest", "galaxy", "harbor", "island",
    "jungle", "knight", "lighthouse", "mountain", "nebula", "ocean",
    "pirate", "quest", "river", "shield", "thunder", "valley", "wizard",
    "xenon", "yacht", "zeppelin",
]


def load_wordlist() -> Optional[List[str]]:
    """Load an EFF/diceware wordlist from next to the script, if present."""
    base = Path(__file__).resolve().parent
    for name in ("eff_large_wordlist.txt", "wordlist.txt"):
        path = base / name
        if not path.exists():
            continue
        words = []
        for line in path.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if parts:
                words.append(parts[-1])  # handles "11111<tab>word" and "word"
        if len(words) >= 1000:
            return words
    return None


class PasswordGenerator:
    """Cryptographically secure password generator."""

    AMBIGUOUS = "Il1O0o|"
    SPECIAL = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    MIN_LENGTH = 8
    MAX_LENGTH = 256

    def __init__(self):
        words = load_wordlist()
        self.using_fallback = words is None
        self.wordlist = words or FALLBACK_WORDS

    def _classes(self, use_uppercase, use_lowercase, use_digits,
                 use_special, exclude_ambiguous) -> List[str]:
        classes = []
        if use_lowercase:
            classes.append(string.ascii_lowercase)
        if use_uppercase:
            classes.append(string.ascii_uppercase)
        if use_digits:
            classes.append(string.digits)
        if use_special:
            classes.append(self.SPECIAL)
        if exclude_ambiguous:
            classes = ["".join(c for c in cls if c not in self.AMBIGUOUS)
                       for cls in classes]
        classes = [c for c in classes if c]
        if not classes:
            raise ValueError("At least one character type must be selected")
        return classes

    def generate(
        self,
        length: int = 16,
        use_uppercase: bool = True,
        use_lowercase: bool = True,
        use_digits: bool = True,
        use_special: bool = True,
        exclude_ambiguous: bool = False,
    ) -> str:
        """Generate a password with at least one char of each chosen class."""
        if not self.MIN_LENGTH <= length <= self.MAX_LENGTH:
            raise ValueError(
                f"Length must be between {self.MIN_LENGTH} and {self.MAX_LENGTH}")
        classes = self._classes(use_uppercase, use_lowercase, use_digits,
                                use_special, exclude_ambiguous)
        charset = "".join(classes)
        chars = [secrets.choice(c) for c in classes]
        chars += [secrets.choice(charset) for _ in range(length - len(chars))]
        secrets.SystemRandom().shuffle(chars)
        return "".join(chars)

    def entropy_bits(self, length: int, **opts) -> float:
        """Approximate entropy of a generated password."""
        classes = self._classes(
            opts.get("use_uppercase", True), opts.get("use_lowercase", True),
            opts.get("use_digits", True), opts.get("use_special", True),
            opts.get("exclude_ambiguous", False))
        return length * math.log2(len("".join(classes)))

    def generate_passphrase(self, word_count: int = 6, separator: str = "-") -> str:
        """Generate a diceware-style passphrase."""
        if not 1 <= word_count <= 20:
            raise ValueError("Word count must be between 1 and 20")
        return separator.join(secrets.choice(self.wordlist)
                              for _ in range(word_count))

    def passphrase_entropy_bits(self, word_count: int) -> float:
        return word_count * math.log2(len(self.wordlist))


# --------------------------------------------------------------------------
# Vault
# --------------------------------------------------------------------------

class VaultError(Exception):
    """Vault file is corrupted or unsupported."""


def normalize_name(name: str) -> str:
    return name.strip().lower().replace(" ", "_")


class Vault:
    """Encrypted password vault (file format v2, reads v1)."""

    VAULT_VERSION = 2
    KDF_NAME = "pbkdf2-sha256"
    SALT_LENGTH = 16
    NONCE_LENGTH = 12
    KEY_LENGTH = 32
    PBKDF2_ITERATIONS = 600_000
    LEGACY_ITERATIONS = 100_000
    MAX_ITERATIONS = 10_000_000

    def __init__(self, vault_path: Path):
        self.vault_path = Path(vault_path)
        self._entries: Dict[str, Dict[str, Any]] = {}
        self._key: Optional[bytes] = None
        self._salt: bytes = b""
        self._iterations: int = self.PBKDF2_ITERATIONS

    # -- crypto helpers ----------------------------------------------------

    @staticmethod
    def _derive_key(master_password: str, salt: bytes, iterations: int) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=Vault.KEY_LENGTH,
                         salt=salt, iterations=iterations)
        return kdf.derive(master_password.encode("utf-8"))

    def _aad(self, version: int, iterations: int, salt: bytes) -> bytes:
        return f"{version}|{self.KDF_NAME}|{iterations}|".encode() + salt

    def _write_file(self, obj: dict) -> None:
        """Atomic write with 0600 permissions."""
        tmp = self.vault_path.with_name(self.vault_path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.vault_path)

    def _persist(self) -> None:
        if self._key is None:
            raise RuntimeError("Vault is locked")
        plaintext = json.dumps({"entries": self._entries},
                               ensure_ascii=False).encode("utf-8")
        nonce = secrets.token_bytes(self.NONCE_LENGTH)
        aad = self._aad(self.VAULT_VERSION, self._iterations, self._salt)
        ciphertext = AESGCM(self._key).encrypt(nonce, plaintext, aad)
        self._write_file({
            "version": self.VAULT_VERSION,
            "kdf": self.KDF_NAME,
            "iterations": self._iterations,
            "salt": base64.b64encode(self._salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        })

    def _rekey(self, master_password: str) -> None:
        """New salt + current iteration count, then save."""
        self._salt = secrets.token_bytes(self.SALT_LENGTH)
        self._iterations = self.PBKDF2_ITERATIONS
        self._key = self._derive_key(master_password, self._salt, self._iterations)
        self._persist()

    # -- lifecycle ---------------------------------------------------------

    def exists(self) -> bool:
        return self.vault_path.exists()

    def backup(self) -> Optional[Path]:
        """Copy the current vault to .bak (0600). Returns backup path."""
        if not self.vault_path.exists():
            return None
        bak = self.vault_path.with_name(self.vault_path.name + ".bak")
        shutil.copy2(self.vault_path, bak)
        try:
            os.chmod(bak, 0o600)
        except OSError:
            pass
        return bak

    def create(self, master_password: str, overwrite: bool = False) -> None:
        if self.vault_path.exists() and not overwrite:
            raise FileExistsError(f"Vault already exists at {self.vault_path}")
        self._entries = {}
        self._rekey(master_password)

    def unlock(self, master_password: str) -> bool:
        """Returns False on wrong password; raises VaultError if corrupted."""
        if not self.vault_path.exists():
            raise FileNotFoundError(f"Vault not found at {self.vault_path}")
        try:
            raw = json.loads(self.vault_path.read_text())
            version = raw["version"]
            salt = base64.b64decode(raw["salt"], validate=True)
            nonce = base64.b64decode(raw["nonce"], validate=True)
            ciphertext = base64.b64decode(raw["ciphertext"], validate=True)
            if version == 1:
                iterations, aad = self.LEGACY_ITERATIONS, None
            elif version == 2:
                if raw.get("kdf") != self.KDF_NAME:
                    raise VaultError("Unsupported key derivation function")
                iterations = int(raw["iterations"])
                if not 1 <= iterations <= self.MAX_ITERATIONS:
                    raise VaultError("Invalid iteration count")
                aad = self._aad(version, iterations, salt)
            else:
                raise VaultError(f"Unsupported vault version: {version}")
        except (KeyError, ValueError, TypeError) as e:
            raise VaultError("Vault file is corrupted") from e

        key = self._derive_key(master_password, salt, iterations)
        try:
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            return False

        try:
            entries = json.loads(plaintext.decode("utf-8"))["entries"]
            if not isinstance(entries, dict):
                raise TypeError
        except (KeyError, ValueError, TypeError) as e:
            raise VaultError("Vault contents are corrupted") from e

        self._entries, self._key = entries, key
        self._salt, self._iterations = salt, iterations
        if version == 1 or iterations < self.PBKDF2_ITERATIONS:
            self.backup()
            self._rekey(master_password)  # upgrade format / strength
        return True

    def lock(self) -> None:
        """Drop key and data references (Python can't guarantee memory wipe)."""
        self._key = None
        self._entries = {}

    def is_locked(self) -> bool:
        return self._key is None

    def _require_unlocked(self) -> None:
        if self._key is None:
            raise RuntimeError("Vault is locked")

    def verify_password(self, master_password: str) -> bool:
        self._require_unlocked()
        key = self._derive_key(master_password, self._salt, self._iterations)
        return secrets.compare_digest(key, self._key)

    def change_master_password(self, new_password: str) -> None:
        self._require_unlocked()
        self.backup()
        self._rekey(new_password)

    # -- entries -----------------------------------------------------------

    def save(self) -> None:
        self._persist()

    def has_entry(self, name: str) -> bool:
        self._require_unlocked()
        return normalize_name(name) in self._entries

    def add_entry(self, entry: PasswordEntry) -> None:
        """Add or replace an entry (caller confirms overwrite)."""
        self._require_unlocked()
        self._entries[normalize_name(entry.name)] = asdict(entry)

    def get_entry(self, name: str) -> Optional[PasswordEntry]:
        self._require_unlocked()
        data = self._entries.get(normalize_name(name))
        if not data:
            return None
        known = {f.name for f in fields(PasswordEntry)}
        return PasswordEntry(**{k: v for k, v in data.items() if k in known})

    def list_entries(self) -> List[str]:
        self._require_unlocked()
        return sorted(self._entries.keys())

    def delete_entry(self, name: str) -> bool:
        self._require_unlocked()
        return self._entries.pop(normalize_name(name), None) is not None


# --------------------------------------------------------------------------
# CLI helpers
# --------------------------------------------------------------------------

def get_master_password(prompt: str = "Enter master password: ",
                        confirm: bool = False) -> str:
    while True:
        password = getpass.getpass(prompt)
        if not password:
            print("Password cannot be empty.")
            continue
        if confirm:
            if len(password) < MIN_MASTER_LENGTH:
                print(f"Master password must be at least {MIN_MASTER_LENGTH} characters.")
                continue
            if password != getpass.getpass("Confirm master password: "):
                print("Passwords do not match. Try again.")
                continue
        return password


def copy_to_clipboard(text: str) -> bool:
    """Copy via Termux:API and clear after a delay."""
    if not shutil.which("termux-clipboard-set"):
        print("Clipboard unavailable (install: pkg install termux-api, plus the Termux:API app).")
        return False
    try:
        subprocess.run(["termux-clipboard-set"], input=text.encode(),
                       check=True, timeout=10)
        subprocess.Popen(
            ["sh", "-c", f"sleep {CLIPBOARD_CLEAR_SECONDS}; termux-clipboard-set ''"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True)
        print(f"📋 Copied. Clipboard will be cleared in {CLIPBOARD_CLEAR_SECONDS}s.")
        return True
    except (subprocess.SubprocessError, OSError) as e:
        print(f"Clipboard error: {e}")
        return False


def strength_label(bits: float) -> str:
    if bits < 50:
        return "weak"
    if bits < 72:
        return "fair"
    if bits < 100:
        return "strong"
    return "very strong"


def ask_yn(prompt: str, default: bool) -> bool:
    answer = input(prompt).strip().lower()
    if not answer:
        return default
    return answer == "y"


def print_banner():
    print("=" * 60)
    print("   🔐 Reliable Password Generator & Manager")
    print("=" * 60)


def print_menu(vault: Vault):
    status = "🔒 locked" if vault.is_locked() else "🔓 unlocked"
    print(f"\nMain Menu:  [Vault: {status}]")
    print("  1. Generate Password")
    print("  2. Generate Passphrase")
    print("  3. Create New Vault")
    print("  4. Open Existing Vault")
    print("  5. Add Entry to Vault")
    print("  6. View Entry")
    print("  7. List All Entries")
    print("  8. Delete Entry")
    print("  9. Lock Vault")
    print(" 10. Change Master Password")
    print("  0. Exit")
    print()


def generate_password_menu(generator: PasswordGenerator):
    print("\n--- Generate Password ---")
    try:
        length = int(input("Length (default 16): ") or "16")
        opts = dict(
            use_uppercase=ask_yn("Include uppercase? (Y/n): ", True),
            use_lowercase=ask_yn("Include lowercase? (Y/n): ", True),
            use_digits=ask_yn("Include digits? (Y/n): ", True),
            use_special=ask_yn("Include special chars? (Y/n): ", True),
            exclude_ambiguous=ask_yn("Exclude ambiguous chars? (y/N): ", False),
        )
        password = generator.generate(length=length, **opts)
        bits = generator.entropy_bits(length, **opts)
        print(f"\n🔑 Generated Password: {password}")
        print(f"   Length: {len(password)}  |  ~{bits:.0f} bits ({strength_label(bits)})")
        if length < 12:
            print("   ⚠ Short password: 12+ characters recommended.")
        if ask_yn("Copy to clipboard? (y/N): ", False):
            copy_to_clipboard(password)
    except ValueError as e:
        print(f"Error: {e}")
    except KeyboardInterrupt:
        print("\nCancelled.")


def generate_passphrase_menu(generator: PasswordGenerator):
    print("\n--- Generate Passphrase ---")
    if generator.using_fallback:
        print("⚠ Using the small built-in wordlist (weak). Add eff_large_wordlist.txt")
        print("  next to the script (see the header of password_manager.py).")
    try:
        default = 8 if generator.using_fallback else 6
        word_count = int(input(f"Number of words (default {default}): ") or str(default))
        separator = input("Separator (default -): ") or "-"
        passphrase = generator.generate_passphrase(word_count, separator)
        bits = generator.passphrase_entropy_bits(word_count)
        print(f"\n🔑 Generated Passphrase: {passphrase}")
        print(f"   Words: {word_count}  |  ~{bits:.0f} bits ({strength_label(bits)})")
        if ask_yn("Copy to clipboard? (y/N): ", False):
            copy_to_clipboard(passphrase)
    except ValueError as e:
        print(f"Error: {e}")
    except KeyboardInterrupt:
        print("\nCancelled.")


def create_vault_menu(vault: Vault):
    print("\n--- Create New Vault ---")
    overwrite = False
    if vault.exists():
        if input(f"Vault exists at {vault.vault_path}. Overwrite? (y/N): ").lower() != "y":
            print("Cancelled.")
            return
        overwrite = True
    try:
        master_password = get_master_password("Create master password: ", confirm=True)
        if overwrite:
            bak = vault.backup()
            print(f"Old vault backed up to {bak}")
        vault.create(master_password, overwrite=overwrite)
        print(f"\n✅ Vault created at {vault.vault_path}")
        print("   Keep your master password safe! It cannot be recovered.")
    except KeyboardInterrupt:
        print("\nCancelled. Existing vault is untouched.")
    except Exception as e:
        print(f"Error creating vault: {e}")


def open_vault_menu(vault: Vault):
    print("\n--- Open Existing Vault ---")
    if not vault.exists():
        print(f"Vault not found at {vault.vault_path}")
        return
    try:
        master_password = get_master_password("Enter master password: ")
        if vault.unlock(master_password):
            print("\n✅ Vault unlocked successfully!")
        else:
            print("\n❌ Incorrect master password!")
    except VaultError as e:
        print(f"\n❌ {e}. Restore from {vault.vault_path.name}.bak if you have one.")
    except KeyboardInterrupt:
        print("\nCancelled.")


def add_entry_menu(vault: Vault, generator: PasswordGenerator):
    print("\n--- Add Entry ---")
    if vault.is_locked():
        print("Vault is locked. Please open it first.")
        return
    try:
        name = input("Entry name (e.g., 'GitHub', 'Email'): ").strip()
        if not name:
            print("Name cannot be empty.")
            return

        created_at = None
        if vault.has_entry(name):
            if not ask_yn(f"'{name}' already exists. Overwrite? (y/N): ", False):
                print("Cancelled.")
                return
            created_at = vault.get_entry(name).created_at

        username = input("Username/Email: ").strip()
        password = getpass.getpass("Password (hidden, leave empty to generate): ").strip()
        if not password:
            password = generator.generate(length=20)
            print(f"Generated password: {password}")
        url = input("URL (optional): ").strip()
        notes = input("Notes (optional): ").strip()

        now = datetime.now().isoformat(timespec="seconds")
        vault.add_entry(PasswordEntry(
            name=name, username=username, password=password, url=url,
            notes=notes, created_at=created_at or now, updated_at=now))
        vault.save()
        print(f"\n✅ Entry '{name}' saved!")
    except KeyboardInterrupt:
        print("\nCancelled.")
    except Exception as e:
        print(f"Error: {e}")


def view_entry_menu(vault: Vault):
    print("\n--- View Entry ---")
    if vault.is_locked():
        print("Vault is locked. Please open it first.")
        return
    name = input("Entry name: ").strip()
    entry = vault.get_entry(name)
    if not entry:
        print(f"Entry '{name}' not found.")
        return
    print(f"\n📋 Entry: {entry.name}")
    print(f"   Username: {entry.username}")
    if entry.url:
        print(f"   URL: {entry.url}")
    if entry.notes:
        print(f"   Notes: {entry.notes}")
    print(f"   Created: {entry.created_at}")
    print(f"   Updated: {entry.updated_at}")
    if ask_yn("Copy password to clipboard? (y/N): ", False):
        copy_to_clipboard(entry.password)
    if ask_yn("Show password on screen? (y/N): ", False):
        print(f"   Password: {entry.password}")


def list_entries_menu(vault: Vault):
    print("\n--- All Entries ---")
    if vault.is_locked():
        print("Vault is locked. Please open it first.")
        return
    names = vault.list_entries()
    if not names:
        print("No entries found.")
        return
    for i, key in enumerate(names, 1):
        entry = vault.get_entry(key)
        if entry:
            print(f"  {i}. {entry.name} ({entry.username})")


def delete_entry_menu(vault: Vault):
    print("\n--- Delete Entry ---")
    if vault.is_locked():
        print("Vault is locked. Please open it first.")
        return
    name = input("Entry name to delete: ").strip()
    if not vault.has_entry(name):
        print(f"Entry '{name}' not found.")
        return
    if input(f"Delete '{name}'? This cannot be undone! (y/N): ").lower() == "y":
        vault.delete_entry(name)
        vault.save()
        print(f"✅ Entry '{name}' deleted.")
    else:
        print("Cancelled.")


def change_master_menu(vault: Vault):
    print("\n--- Change Master Password ---")
    if vault.is_locked():
        print("Vault is locked. Please open it first.")
        return
    try:
        old = get_master_password("Current master password: ")
        if not vault.verify_password(old):
            print("❌ Incorrect master password!")
            return
        new = get_master_password("New master password: ", confirm=True)
        vault.change_master_password(new)
        print("✅ Master password changed (previous vault saved as .bak).")
        print("   Note: the .bak file is still encrypted with the OLD password.")
    except KeyboardInterrupt:
        print("\nCancelled.")


def main():
    vault = Vault(Path.home() / ".password_vault.json")
    generator = PasswordGenerator()
    last_activity = time.monotonic()

    print_banner()

    while True:
        print_menu(vault)
        try:
            choice = input("Select option: ").strip()

            if (not vault.is_locked()
                    and time.monotonic() - last_activity > AUTOLOCK_SECONDS):
                vault.lock()
                print("🔒 Vault auto-locked after inactivity. Open it again.")
                if choice in {"5", "6", "7", "8", "10"}:
                    continue
            last_activity = time.monotonic()

            if choice == "1":
                generate_password_menu(generator)
            elif choice == "2":
                generate_passphrase_menu(generator)
            elif choice == "3":
                create_vault_menu(vault)
            elif choice == "4":
                open_vault_menu(vault)
            elif choice == "5":
                add_entry_menu(vault, generator)
            elif choice == "6":
                view_entry_menu(vault)
            elif choice == "7":
                list_entries_menu(vault)
            elif choice == "8":
                delete_entry_menu(vault)
            elif choice == "9":
                vault.lock()
                print("🔒 Vault locked.")
            elif choice == "10":
                change_master_menu(vault)
            elif choice == "0":
                vault.lock()
                print("Goodbye! 👋")
                break
            else:
                print("Invalid option. Please try again.")
            last_activity = time.monotonic()

        except KeyboardInterrupt:
            print("\n\nGoodbye! 👋")
            break
        except EOFError:
            break


if __name__ == "__main__":
    main()
