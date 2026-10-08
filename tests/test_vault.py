"""Vault header / slot tests: auth factors (T-03, T-04), downgrade (T-09), header tampering."""

import pytest

from mlref import vault as V
from mlref.constants import PRODUCTION_POLICY, SLOT_RECOVERY, SLOT_USB, SLOT_USB_PASSWORD, VAULT_FIXED_LEN
from mlref.errors import AuthError, FormatError, IntegrityError, KdfPolicyError
from mlref.keyfile import recovery_generate
from mlref.manifest import FileEntry


def make(fast, keyfile, password="pw", recovery=None):
    slots = [(SLOT_USB_PASSWORD, {"keyfile": keyfile, "password": password})]
    if recovery:
        slots.append((SLOT_RECOVERY, {"recovery_key": recovery}))
    ov = V.create(slots, policy=fast)
    ov.manifest.files["a.txt"] = FileEntry("a.txt", b"\x01" * 32, 1, 1, 0, b"\x02" * 32)
    return ov, V.serialize(ov)


def test_open_with_usb_and_password(fast, keyfile):
    ov, data = make(fast, keyfile)
    ov2 = V.open_vault(data, V.Credentials((keyfile,), "pw"), fast)
    assert ov2.vmk == ov.vmk and ov2.manifest == ov.manifest


def test_password_alone_or_usb_alone_insufficient(fast, keyfile, keyfile2):
    _, data = make(fast, keyfile)
    for creds in [V.Credentials((keyfile,), None), V.Credentials((keyfile,), "wrong"),
                  V.Credentials((keyfile2,), "pw"), V.Credentials((), "pw")]:
        with pytest.raises(AuthError):
            V.open_vault(data, creds, fast)


def test_password_unicode_normalization(fast, keyfile):
    _, data = make(fast, keyfile, password="şifre\u0301")
    import unicodedata

    V.open_vault(data, V.Credentials((keyfile,), unicodedata.normalize("NFC", "şifre\u0301")), fast)


def test_recovery_slot(fast, keyfile):
    rec = recovery_generate()
    ov, data = make(fast, keyfile, recovery=rec)
    assert V.open_vault(data, V.Credentials(recovery_key=rec), fast).vmk == ov.vmk
    with pytest.raises(AuthError):
        V.open_vault(data, V.Credentials(recovery_key=recovery_generate()), fast)


def test_usb_only_slot(fast, keyfile):
    ov = V.create([(SLOT_USB, {"keyfile": keyfile})], policy=fast)
    data = V.serialize(ov)
    assert V.open_vault(data, V.Credentials((keyfile,)), fast).vmk == ov.vmk


def test_production_policy_rejects_weak_params(fast, keyfile):
    """T-09: a vault (or attacker-modified slot) with weak Argon2 params is refused
    before Argon2 runs."""
    _, data = make(fast, keyfile)
    with pytest.raises(KdfPolicyError):
        V.open_vault(data, V.Credentials((keyfile,), "pw"), PRODUCTION_POLICY)


def test_argon_param_tamper_breaks_unwrap(fast, keyfile):
    _, data = make(fast, keyfile)
    slot0 = VAULT_FIXED_LEN + 1
    t = bytearray(data)
    t[slot0 + 72] += 1  # argon_t 1 -> 2: still within FAST policy, but bound in AAD
    with pytest.raises(AuthError):
        V.open_vault(bytes(t), V.Credentials((keyfile,), "pw"), fast)


def test_every_header_byte_is_authenticated(fast, keyfile):
    """Flip one bit in every byte of the vault file: open must fail (never succeed silently)."""
    _, data = make(fast, keyfile)
    for i in range(len(data)):
        t = bytearray(data)
        t[i] ^= 0x01
        with pytest.raises((AuthError, IntegrityError, FormatError)):
            V.open_vault(bytes(t), V.Credentials((keyfile,), "pw"), fast)


def test_truncated_or_extended(fast, keyfile):
    _, data = make(fast, keyfile)
    for bad in (data[:-1], data + b"\x00", data[:40]):
        with pytest.raises(FormatError):
            V.open_vault(bad, V.Credentials((keyfile,), "pw"), fast)


def test_slot_swap_between_vaults(fast, keyfile):
    """A slot copied from another vault (same key file) must not open this vault."""
    _, a = make(fast, keyfile)
    _, b = make(fast, keyfile)
    s = slice(VAULT_FIXED_LEN + 1, VAULT_FIXED_LEN + 1 + 136)
    t = bytearray(a)
    t[s] = b[s]
    with pytest.raises((AuthError, IntegrityError)):
        V.open_vault(bytes(t), V.Credentials((keyfile,), "pw"), fast)


def test_repr_hides_secrets(fast, keyfile):
    ov, _ = make(fast, keyfile)
    assert ov.vmk.hex() not in repr(ov)
    assert "pw" not in repr(V.Credentials((keyfile,), "pw"))
