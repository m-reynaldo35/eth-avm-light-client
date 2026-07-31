import pytest
from algopy_testing import algopy_testing_context


@pytest.fixture
def ctx():
    """Standard algopy_testing context for offline (pure-emulation) tests --
    no algod/docker dependency. `sha256` and friends are emulated in Python
    by algorand-python-testing, which is why the *majority* of M3 is
    genuinely offline-testable (design doc §8)."""
    with algopy_testing_context() as context:
        yield context
