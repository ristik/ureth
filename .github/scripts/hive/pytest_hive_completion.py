"""Let Hive classify test failures only when pytest reached every selected case."""

import pytest


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    if hasattr(session.config, 'workerinput') or exitstatus not in (pytest.ExitCode.OK, pytest.ExitCode.TESTS_FAILED):
        return
    reporter = session.config.pluginmanager.get_plugin('terminalreporter')
    completed = {
        report.nodeid
        for outcome in ('passed', 'failed', 'error', 'skipped', 'xfailed', 'xpassed')
        for report in (reporter.stats.get(outcome, ()) if reporter else ())
        if isinstance(report, pytest.TestReport)
    }
    if 0 < session.testscollected == len(completed):
        # The Hive test reports still carry the original failures. Aborts,
        # collection errors, signals, and missing outcomes keep a failing exit.
        session.exitstatus = pytest.ExitCode.OK
    else:
        session.exitstatus = pytest.ExitCode.INTERNAL_ERROR
