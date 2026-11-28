import json
from pathlib import Path
import re
import tempfile
import unittest

from validate_attempt import case_names, pattern_for, validate


class AttemptTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sim = 'ethereum/engine'
        self.suite = 'engine-api'
        self.case = {'name': 'exact case', 'end': '2026-11-28T00:00:00Z', 'summaryResult': {'pass': True}}

    def reports(self, *cases):
        report = {'id': 0, 'name': self.suite, 'testCases': dict(enumerate(cases))}
        (self.root / '1-a.json').write_text(json.dumps(report))

    def completion(self, suites, tests, failed):
        result = {'simulator': self.sim, 'suites': suites, 'tests': tests, 'failed': failed}
        (self.root / 'completed.json').write_text(json.dumps(result))

    def test_early_exit_after_passing_suite_cannot_reuse_an_older_attempt(self):
        old = self.root / 'attempt-old'
        old.mkdir()
        (old / 'completed.json').write_text('{}')
        self.reports(self.case)
        with self.assertRaises(FileNotFoundError):
            validate(self.root, self.sim, 0)

    def test_structured_counts_and_nonzero_real_cases_required(self):
        self.reports(self.case)
        self.completion(1, 2, 0)
        with self.assertRaisesRegex(ValueError, 'counts disagree'):
            validate(self.root, self.sim, 0)
        self.reports(dict(self.case, name='engine test loader'))
        self.completion(1, 1, 0)
        with self.assertRaisesRegex(ValueError, 'no completed test cases'):
            validate(self.root, self.sim, 0)
        self.reports()
        self.completion(1, 0, 0)
        with self.assertRaisesRegex(ValueError, 'no completed test cases'):
            validate(self.root, self.sim, 0)

    def test_completed_test_failure_can_be_parsed(self):
        self.reports(dict(self.case, summaryResult={'pass': False}))
        self.completion(1, 1, 1)
        validate(self.root, self.sim, 1, [self.case['name']], self.suite)
        with self.assertRaisesRegex(ValueError, 'inconsistent Hive exit'):
            validate(self.root, self.sim, 2)
        with self.assertRaisesRegex(ValueError, 'case selection mismatch'):
            validate(self.root, self.sim, 1, ['exact case suffix'])

    def test_incomplete_case_cannot_count_as_a_completed_failure(self):
        self.reports(dict(self.case, end='0001-01-01T00:00:00Z', summaryResult={'pass': False}))
        self.completion(1, 1, 1)
        with self.assertRaisesRegex(ValueError, 'unfinished test case'):
            validate(self.root, self.sim, 1)

    def test_eels_filter_matches_only_pinned_ids(self):
        for path in Path(__file__).parent.glob('cancun-*.txt'):
            if path.name == 'cancun-reorg.txt':
                continue
            names = case_names(path)
            pattern = re.compile(pattern_for(names))
            for name in names:
                self.assertIn('[fork_Cancun-', name)
                self.assertRegex(f'eels.py::test_hive[{name}]', pattern)
                self.assertNotRegex(name.replace('fork_Cancun-', 'fork_Amsterdam-'), pattern)
                self.assertNotRegex(name + '-extra', pattern)


if __name__ == '__main__':
    unittest.main()
