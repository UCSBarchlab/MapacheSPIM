"""
Shared pytest configuration.

Assembling ARM64, x86-64, and MIPS code needs the optional Keystone Engine,
which has no prebuilt wheels for some platforms (e.g. Apple Silicon). Tests
that fail only because Keystone is missing are reported as skipped there,
while RISC-V tests (which use the built-in encoder) still run everywhere.
"""

import pytest

from mapachespim.toolchain.assembler import KEYSTONE_AVAILABLE

KEYSTONE_MISSING_MARKER = "requires the Keystone Engine"


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if KEYSTONE_AVAILABLE or not report.failed:
        return
    if KEYSTONE_MISSING_MARKER in str(report.longrepr):
        report.outcome = "skipped"
        report.longrepr = (str(item.path), item.location[1] or 0, "Skipped: Keystone not installed")
