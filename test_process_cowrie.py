"""Offline regression tests for Cowrie processing and SQLite integrity."""

import ast
from contextlib import closing
import json
import logging
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest


SCRIPT = Path(__file__).with_name('process_cowrie.py')


def database_functions(path):
    """Load database helpers without running the command-line script."""
    tree = ast.parse(SCRIPT.read_text(encoding='utf-8'))
    constants = {'SESSIONS_COLS', 'COMMANDS_COLS', 'FILES_COLS', 'FILES_PROCESSED_COLS'}
    functions = {'initialize_database', 'flush_to_sqlite', 'df_session_exists', 'df_insert_session'}
    nodes = [node for node in tree.body if
             isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id in constants
                                                   for target in node.targets)
             or isinstance(node, ast.FunctionDef) and node.name in functions]
    env = {'con': sqlite3.connect(path), 'DB_PATH': str(path), 'sqlite3': sqlite3,
           'logging': logging, 'time': time}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(SCRIPT), 'exec'), env)
    return env


class ProcessCowrieTests(unittest.TestCase):
    def test_login_without_commands_produces_report_and_session(self):
        for accumulate in (False, True):
            with self.subTest(accumulate=accumulate), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                logs = root / 'logs'
                logs.mkdir()
                events = [
                    {'eventid': 'cowrie.session.connect', 'session': 's1', 'protocol': 'ssh',
                     'timestamp': '2026-10-30T12:00:00.000000Z', 'src_ip': '192.0.2.1'},
                    {'eventid': 'cowrie.login.success', 'session': 's1', 'username': 'root',
                     'password': 'test', 'timestamp': '2026-10-30T12:00:01.000000Z', 'src_ip': '192.0.2.1'},
                    {'eventid': 'cowrie.session.closed', 'session': 's1', 'duration': 1.0,
                     'timestamp': '2026-10-30T12:00:02.000000Z', 'src_ip': '192.0.2.1'},
                ]
                (logs / 'cowrie.json').write_text(''.join(json.dumps(event) + '\n' for event in events),
                                                  encoding='utf-8')
                db_path = root / 'cowrie.sqlite'
                args = [sys.executable, str(SCRIPT), '--logpath', str(logs),
                        '--sourcefile', str(db_path)]
                if accumulate:
                    args.append('--accumulate')
                result = subprocess.run(args,
                                        cwd=root, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                reports = list(root.glob('*/*_report.txt'))
                self.assertEqual(len(reports), 2, result.stdout)
                for report in reports:
                    report_text = report.read_text(encoding='utf-8')
                    self.assertTrue(report_text.lstrip().startswith('Total Number of Attacks:'), report)
                    self.assertIn('Most Common Number of Commands:', report_text)
                    self.assertEqual(report_text.count('Total Number of Attacks:'), 1)
                    if 'abnormal' not in report.name:
                        self.assertIn('s1', report_text)
                with closing(sqlite3.connect(db_path)) as db:
                    self.assertEqual(db.execute('SELECT session, total_commands FROM sessions').fetchone(),
                                     ('s1', 0))

    def test_new_database_has_primary_key_and_unique_event_indexes(self):
        with tempfile.TemporaryDirectory() as temp:
            env = database_functions(Path(temp) / 'source.sqlite')
            try:
                env['initialize_database']()
                db = env['con']
                self.assertTrue(any(row[1] == 'session' and row[5]
                                    for row in db.execute('PRAGMA table_info(sessions)')))
                for table in ('commands', 'files', 'files_processed'):
                    self.assertTrue(any(row[2] for row in db.execute(f'PRAGMA index_list({table})')))
                env['df_insert_session']({'session': 's1', 'timestamp': 1.0, 'source_ip': '192.0.2.1'})
                env['flush_to_sqlite']()
                with self.assertRaises(sqlite3.IntegrityError):
                    db.execute("INSERT INTO sessions (session) VALUES ('s1')")
                with self.assertRaisesRegex(RuntimeError, 'Conflicting data for session ID'):
                    env['df_session_exists']('s1', 2.0, '192.0.2.1')
            finally:
                env['con'].close()

    def test_legacy_duplicate_sessions_fail_during_upgrade(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'legacy.sqlite'
            with closing(sqlite3.connect(path)) as db, db:
                db.execute('CREATE TABLE sessions (session TEXT)')
                db.executemany('INSERT INTO sessions VALUES (?)', [('s1',), ('s1',)])
            env = database_functions(path)
            try:
                with self.assertRaisesRegex(RuntimeError, 'duplicate session keys'):
                    env['initialize_database']()
            finally:
                env['con'].close()


if __name__ == '__main__':
    unittest.main()
