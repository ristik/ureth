"""Validate one isolated Hive attempt and its exact case selection, if configured."""

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys


def case_names(path):
    if path is None:
        return []
    names = [line for line in path.read_text().splitlines() if line and not line.startswith('#')]
    if not names or len(names) != len(set(names)):
        raise ValueError(f'{path}: expected a nonempty list of unique case names')
    return names


def pattern_for(names, suite=None):
    if suite:
        return f'^{re.escape(suite)}$/^(' + '|'.join(map(re.escape, names)) + ')$'
    # EELS applies Python regexes to pytest names that may wrap the fixture ID
    # in brackets and append the client. The Hive report uses the ID plus -reth.
    ids = (re.escape(name.removesuffix('-reth')) for name in names)
    return r'^(?:.*\[)?(?:' + '|'.join(ids) + r')(?:-reth)?\]?$'


def suite_reports(root):
    return sorted(path for path in root.iterdir() if re.fullmatch(r'\d+-[0-9a-f]+\.json', path.name))


def validate(root, simulator, hive_exit, names=(), suite=None):
    completion = json.loads((root / 'completed.json').read_text())
    if completion['simulator'] != simulator:
        raise ValueError('completion record names a different simulator')
    reports = suite_reports(root)
    counts = Counter()
    observed = Counter()
    suite_ids = set()
    for path in reports:
        report = json.loads(path.read_text())
        if report['id'] in suite_ids or not isinstance(report['testCases'], dict):
            raise ValueError(f'{path}: duplicate suite or invalid test cases')
        suite_ids.add(report['id'])
        if suite and report['name'] != suite:
            raise ValueError(f'{path}: unexpected suite {report["name"]}')
        for case in report['testCases'].values():
            name, result = case['name'], case['summaryResult']
            if not name or type(result['pass']) is not bool or not case['end'] or case['end'].startswith('0001-'):
                raise ValueError(f'{path}: malformed or unfinished test case {name!r}')
            counts['tests'] += 1
            counts['failed'] += not result['pass']
            if not (simulator == 'ethereum/engine' and name.endswith(' test loader')):
                observed[name] += 1
    counts['suites'] = len(reports)
    if any(type(completion[key]) is not int or completion[key] != counts[key] for key in ('suites', 'tests', 'failed')):
        raise ValueError(f'Hive completion counts disagree with the reports: {completion}, {dict(counts)}')
    if not observed or hive_exit != int(counts['failed'] > 0):
        raise ValueError(f'no completed test cases or inconsistent Hive exit status {hive_exit}')
    if names and observed != Counter(names):
        want = Counter(names)
        raise ValueError(f'case selection mismatch: missing {list((want - observed).elements())}, '
                         f'extra {list((observed - want).elements())}')
    print(f'{simulator}: {counts["suites"]} suites, {counts["tests"]} completed tests, {counts["failed"]} failed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pattern', action='store_true')
    parser.add_argument('--cases', type=Path)
    parser.add_argument('--suite')
    parser.add_argument('--results', type=Path)
    parser.add_argument('--simulator')
    parser.add_argument('--hive-exit', type=int)
    args = parser.parse_args()
    try:
        names = case_names(args.cases)
        if args.pattern:
            if not names:
                parser.error('--pattern requires --cases')
            print(pattern_for(names, args.suite))
        else:
            validate(args.results, args.simulator, args.hive_exit, names, args.suite)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        sys.exit(f'Hive attempt invalid: {error}')


if __name__ == '__main__':
    main()
