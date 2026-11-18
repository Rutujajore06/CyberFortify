import os
import unittest
from unittest.mock import patch, MagicMock
from app.database import (
    translate_sql_to_postgres,
    PostgresCursorWrapper,
    get_database_url,
    is_postgres
)


class TestDatabasePostgresAdapter(unittest.TestCase):
    def test_01_translate_ddl_autoincrement_to_serial(self):
        sql = """
        CREATE TABLE IF NOT EXISTS live_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL
        )
        """
        pg = translate_sql_to_postgres(sql, has_params=False)
        self.assertIn('SERIAL PRIMARY KEY', pg)
        self.assertNotIn('AUTOINCREMENT', pg.upper())

    def test_02_translate_insert_or_ignore_to_on_conflict(self):
        sql = "INSERT OR IGNORE INTO target_users (username, role) VALUES (?, ?)"
        pg = translate_sql_to_postgres(sql, has_params=True)
        self.assertTrue(pg.startswith('INSERT INTO target_users'))
        self.assertIn('VALUES (%s, %s)', pg)
        self.assertTrue(pg.endswith('ON CONFLICT DO NOTHING'))

    def test_03_translate_preserves_question_marks_in_string_literals_and_escapes_percent(self):
        sql = "SELECT * FROM events WHERE payload_data LIKE '%test%' AND note != 'why?' AND id = ?"
        pg = translate_sql_to_postgres(sql, has_params=True)
        self.assertIn("'why?'", pg)
        self.assertIn("'%%test%%'", pg)
        self.assertTrue(pg.endswith('AND id = %s'))

    def test_04_postgres_cursor_wrapper_captures_lastrowid(self):
        mock_pg_cur = MagicMock()
        mock_pg_cur.fetchone.return_value = {'id': 42}
        wrapper = PostgresCursorWrapper(mock_pg_cur)

        wrapper.execute("INSERT INTO events (endpoint, http_method) VALUES (?, ?)", ('/login', 'POST'))
        called_sql, called_params = mock_pg_cur.execute.call_args[0]
        self.assertIn('VALUES (%s, %s) RETURNING id', called_sql)
        self.assertEqual(called_params, ('/login', 'POST'))
        self.assertEqual(wrapper.lastrowid, 42)

    def test_05_database_url_normalization(self):
        with patch.dict(os.environ, {'DATABASE_URL': 'postgres://user:pass@ep-demo.neon.tech/neondb'}, clear=False):
            url = get_database_url()
            self.assertEqual(url, 'postgresql://user:pass@ep-demo.neon.tech/neondb')
            self.assertTrue(is_postgres())


if __name__ == '__main__':
    unittest.main()
