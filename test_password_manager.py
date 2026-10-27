#!/usr/bin/env python3
"""
Tests for password_manager.py

Run:  python test_password_manager.py        (or: python -m unittest -v)
"""

import base64
import json
import os
import secrets
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import password_manager as pm  # noqa: E402
from password_manager import (  # noqa: E402
    PasswordGenerator, Vault, VaultError, PasswordEntry,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

REAL_ITERATIONS = Vault.PBKDF2_ITERATIONS
FAST_ITERATIONS = 1000  # keeps the suite quick, especially on a phone


class GeneratorTests(unittest.TestCase):
    def setUp(self):
        self.gen = PasswordGenerator()

    def test_lengths(self):
        for n in (8, 16, 32, 256):
            self.assertEqual(len(self.gen.generate(length=n)), n)

    def test_length_bounds(self):
        for n in (0, 4, 7, 257):
            with self.assertRaises(ValueError):
                self.gen.generate(length=n)

    def test_no_charset_selected(self):
        with self.assertRaises(ValueError):
            self.gen.generate(use_uppercase=False, use_lowercase=False,
                              use_digits=False, use_special=False)

    def test_excluding_special(self):
        for _ in range(50):
            pwd = self.gen.generate(use_special=False)
            self.assertFalse(any(c in self.gen.SPECIAL for c in pwd))

    def test_lowercase_only(self):
        pwd = self.gen.generate(12, use_uppercase=False, use_digits=False,
                                use_special=False)
        self.assertTrue(pwd.islower() and pwd.isalpha())

    def test_each_selected_class_present(self):
        for _ in range(200):
            pwd = self.gen.generate(8)
            self.assertTrue(any(c.islower() for c in pwd))
            self.assertTrue(any(c.isupper() for c in pwd))
            self.assertTrue(any(c.isdigit() for c in pwd))
            self.assertTrue(any(c in self.gen.SPECIAL for c in pwd))

    def test_exclude_ambiguous(self):
        for _ in range(200):
            pwd = self.gen.generate(32, exclude_ambiguous=True)
            self.assertFalse(any(c in self.gen.AMBIGUOUS for c in pwd))

    def test_passwords_differ(self):
        self.assertEqual(len({self.gen.generate(24) for _ in range(100)}), 100)

    def test_entropy_estimate(self):
        # 16 chars from 26+26+10+26 = 88 symbols -> ~103 bits
        self.assertAlmostEqual(self.gen.entropy_bits(16), 103.4, delta=0.5)
        self.assertLess(self.gen.entropy_bits(8, use_uppercase=False,
                                              use_digits=False,
                                              use_special=False), 40)

    def test_passphrase(self):
        self.assertEqual(len(self.gen.generate_passphrase(4).split("-")), 4)
        self.assertEqual(len(self.gen.generate_passphrase(6, "_").split("_")), 6)

    def test_passphrase_bounds(self):
        for n in (0, -1, 21):
            with self.assertRaises(ValueError):
                self.gen.generate_passphrase(n)

    def test_passphrase_entropy(self):
        bits = self.gen.passphrase_entropy_bits(6)
        self.assertGreater(bits, 30)
        if not self.gen.using_fallback:  # EFF list present
            self.assertGreater(bits, 75)


class VaultTests(unittest.TestCase):
    def setUp(self):
        Vault.PBKDF2_ITERATIONS = FAST_ITERATIONS
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.path = self.dir / "vault.json"

    def tearDown(self):
        Vault.PBKDF2_ITERATIONS = REAL_ITERATIONS
        self._tmp.cleanup()

    def new_vault(self, password="master-pass-123"):
        v = Vault(self.path)
        v.create(password)
        return v

    @staticmethod
    def entry(name="GitHub", password="s3cret", **kw):
        return PasswordEntry(name=name, username="me", password=password,
                             created_at="2026-01-01T00:00:00",
                             updated_at="2026-01-01T00:00:00", **kw)

    # -- defaults / file format -------------------------------------------

    def test_default_iterations_are_strong(self):
        self.assertGreaterEqual(REAL_ITERATIONS, 600_000)

    def test_file_structure_and_permissions(self):
        self.new_vault()
        data = json.loads(self.path.read_text())
        for key in ("version", "kdf", "iterations", "salt", "nonce", "ciphertext"):
            self.assertIn(key, data)
        self.assertEqual(data["version"], 2)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_no_plaintext_in_file(self):
        v = self.new_vault()
        v.add_entry(self.entry(password="UNIQUE-PLAINTEXT-MARKER"))
        v.save()
        self.assertNotIn("UNIQUE-PLAINTEXT-MARKER", self.path.read_text())
        self.assertNotIn("GitHub", self.path.read_text())

    def test_nonce_changes_on_every_save(self):
        v = self.new_vault()
        nonces = set()
        for _ in range(5):
            v.save()
            nonces.add(json.loads(self.path.read_text())["nonce"])
        self.assertEqual(len(nonces), 5)

    def test_no_temp_file_left_behind(self):
        v = self.new_vault()
        v.save()
        self.assertEqual([p.name for p in self.dir.iterdir()], ["vault.json"])

    # -- locking / passwords ----------------------------------------------

    def test_create_refuses_to_overwrite(self):
        self.new_vault()
        with self.assertRaises(FileExistsError):
            Vault(self.path).create("another-pass-123")

    def test_wrong_password_and_lock(self):
        v = self.new_vault()
        v.lock()
        self.assertTrue(v.is_locked())
        self.assertFalse(v.unlock("wrong-password"))
        self.assertTrue(v.is_locked())
        self.assertTrue(v.unlock("master-pass-123"))
        self.assertFalse(v.is_locked())

    def test_operations_require_unlock(self):
        v = self.new_vault()
        v.lock()
        for call in (lambda: v.list_entries(), lambda: v.get_entry("x"),
                     lambda: v.add_entry(self.entry()), lambda: v.save(),
                     lambda: v.delete_entry("x"), lambda: v.has_entry("x")):
            with self.assertRaises(RuntimeError):
                call()

    def test_unlock_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            Vault(self.path).unlock("x")

    def test_verify_password(self):
        v = self.new_vault()
        self.assertTrue(v.verify_password("master-pass-123"))
        self.assertFalse(v.verify_password("nope"))

    def test_change_master_password(self):
        v = self.new_vault()
        v.add_entry(self.entry())
        v.save()
        old_salt = json.loads(self.path.read_text())["salt"]
        v.change_master_password("brand-new-pass-456")
        self.assertNotEqual(json.loads(self.path.read_text())["salt"], old_salt)
        self.assertTrue((self.dir / "vault.json.bak").exists())
        v.lock()
        self.assertFalse(v.unlock("master-pass-123"))
        self.assertTrue(v.unlock("brand-new-pass-456"))
        self.assertEqual(v.get_entry("github").password, "s3cret")

    # -- entries ----------------------------------------------------------

    def test_entry_roundtrip(self):
        v = self.new_vault()
        v.add_entry(self.entry(url="https://github.com", notes="n"))
        v.save()
        v2 = Vault(self.path)
        self.assertTrue(v2.unlock("master-pass-123"))
        e = v2.get_entry("GitHub")
        self.assertEqual((e.username, e.password, e.url, e.notes),
                         ("me", "s3cret", "https://github.com", "n"))

    def test_name_normalization(self):
        v = self.new_vault()
        v.add_entry(self.entry(name="My Bank"))
        for variant in ("my bank", "MY BANK", "  My Bank  ", "my_bank"):
            self.assertTrue(v.has_entry(variant), variant)
            self.assertIsNotNone(v.get_entry(variant))

    def test_same_name_replaces(self):
        v = self.new_vault()
        v.add_entry(self.entry(password="one"))
        v.add_entry(self.entry(name="github", password="two"))
        self.assertEqual(v.list_entries(), ["github"])
        self.assertEqual(v.get_entry("GITHUB").password, "two")

    def test_list_sorted_and_delete(self):
        v = self.new_vault()
        for n in ("Zeta", "Alpha", "Mid"):
            v.add_entry(self.entry(name=n))
        self.assertEqual(v.list_entries(), ["alpha", "mid", "zeta"])
        self.assertTrue(v.delete_entry("MID"))
        self.assertFalse(v.delete_entry("MID"))
        self.assertEqual(v.list_entries(), ["alpha", "zeta"])

    def test_get_missing_entry(self):
        self.assertIsNone(self.new_vault().get_entry("nothing"))

    def test_unicode(self):
        v = self.new_vault("пароль-мастер-123")
        v.add_entry(self.entry(name="Почта", password="пароль🔑"))
        v.save()
        v2 = Vault(self.path)
        self.assertTrue(v2.unlock("пароль-мастер-123"))
        self.assertEqual(v2.get_entry("почта").password, "пароль🔑")

    # -- tampering / corruption ------------------------------------------

    def _tamper(self, **changes):
        raw = json.loads(self.path.read_text())
        raw.update(changes)
        self.path.write_text(json.dumps(raw))

    def test_header_tampering_detected(self):
        v = self.new_vault()
        raw = json.loads(self.path.read_text())
        v.lock()
        self._tamper(iterations=raw["iterations"] + 1)
        self.assertFalse(v.unlock("master-pass-123"))

    def test_ciphertext_tampering_detected(self):
        v = self.new_vault()
        raw = json.loads(self.path.read_text())
        ct = bytearray(base64.b64decode(raw["ciphertext"]))
        ct[0] ^= 1
        v.lock()
        self._tamper(ciphertext=base64.b64encode(bytes(ct)).decode())
        self.assertFalse(v.unlock("master-pass-123"))

    def test_corrupted_files(self):
        self.new_vault()
        cases = {
            "garbage": "not json at all",
            "empty": "",
            "list": "[]",
            "missing keys": json.dumps({"version": 2}),
            "bad base64": json.dumps({"version": 2, "kdf": Vault.KDF_NAME,
                                      "iterations": 1000, "salt": "!!",
                                      "nonce": "!!", "ciphertext": "!!"}),
        }
        for label, content in cases.items():
            self.path.write_text(content)
            with self.assertRaises(VaultError, msg=label):
                Vault(self.path).unlock("master-pass-123")

    def test_unsupported_version_and_bad_iterations(self):
        v = self.new_vault()
        v.lock()
        self._tamper(version=99)
        with self.assertRaises(VaultError):
            v.unlock("master-pass-123")
        self._tamper(version=2, iterations=10**12)
        with self.assertRaises(VaultError):
            v.unlock("master-pass-123")

    # -- backups / legacy -------------------------------------------------

    def test_backup(self):
        self.assertIsNone(Vault(self.path).backup())
        v = self.new_vault()
        bak = v.backup()
        self.assertEqual(bak.read_text(), self.path.read_text())

    def test_overwrite_create_replaces_data(self):
        v = self.new_vault()
        v.add_entry(self.entry())
        v.save()
        v.backup()
        v.create("second-master-123", overwrite=True)
        v.lock()
        self.assertTrue(v.unlock("second-master-123"))
        self.assertEqual(v.list_entries(), [])

    def test_v1_vault_is_read_and_upgraded(self):
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        key = Vault._derive_key("old-pass-12345", salt, Vault.LEGACY_ITERATIONS)
        plaintext = json.dumps({
            "version": 1, "salt": "",
            "entries": {"a": {"name": "A", "username": "u", "password": "p"}},
        }).encode()
        self.path.write_text(json.dumps({
            "version": 1,
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(
                AESGCM(key).encrypt(nonce, plaintext, None)).decode(),
        }))

        v = Vault(self.path)
        self.assertTrue(v.unlock("old-pass-12345"))
        self.assertEqual(v.get_entry("a").password, "p")

        upgraded = json.loads(self.path.read_text())
        self.assertEqual(upgraded["version"], 2)
        self.assertEqual(upgraded["iterations"], FAST_ITERATIONS)
        self.assertTrue((self.dir / "vault.json.bak").exists())

        v2 = Vault(self.path)
        self.assertTrue(v2.unlock("old-pass-12345"))
        self.assertEqual(v2.get_entry("a").username, "u")


class HelperTests(unittest.TestCase):
    def test_strength_label(self):
        self.assertEqual(pm.strength_label(30), "weak")
        self.assertEqual(pm.strength_label(60), "fair")
        self.assertEqual(pm.strength_label(80), "strong")
        self.assertEqual(pm.strength_label(120), "very strong")

    def test_normalize_name(self):
        self.assertEqual(pm.normalize_name("  My Site "), "my_site")


if __name__ == "__main__":
    unittest.main(verbosity=2)
