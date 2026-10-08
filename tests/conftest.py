import pytest

from mlref.constants import KdfPolicy
from mlref.keyfile import KeyFile
from mlref.rng import DeterministicRng

# TEST ONLY: tiny Argon2id cost so the suite runs fast. Production minimum is 64 MiB.
FAST = KdfPolicy(default_m_kib=8, default_t=1, min_m_kib=8, min_t=1)


@pytest.fixture
def fast():
    return FAST


@pytest.fixture
def drng():
    return DeterministicRng(b"mylocker-test-seed")


@pytest.fixture
def keyfile():
    return KeyFile.generate("test")


@pytest.fixture
def keyfile2():
    return KeyFile.generate("other")
