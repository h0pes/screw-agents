# Fixture: Test code with hardcoded SQL — should not be flagged or flagged at reduced severity
# Expected: TRUE NEGATIVE or reduced severity
# Pattern: Test/fixture code with no runtime user input

import sqlite3
import pytest


@pytest.fixture
def db():
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # Hardcoded DDL — no user input at runtime
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    cursor.execute("INSERT INTO users VALUES (1, 'Alice', 'alice@example.com')")
    cursor.execute("INSERT INTO users VALUES (2, 'Bob', 'bob@example.com')")
    conn.commit()
    yield conn
    conn.close()


def test_search_users(db):
    cursor = db.cursor()
    # Hardcoded test query — no user input, safe
    cursor.execute("SELECT * FROM users WHERE name = 'Alice'")
    result = cursor.fetchone()
    assert result[1] == "Alice"


def test_search_by_id(db):
    cursor = db.cursor()
    test_id = 1  # Hardcoded, not from user input
    # Even with f-string, this is test code with hardcoded values
    cursor.execute(f"SELECT * FROM users WHERE id = {test_id}")
    result = cursor.fetchone()
    assert result[0] == 1


class TestUserRepository:
    """Test class — all queries use hardcoded test data."""

    def test_count(self, db):
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        assert cursor.fetchone()[0] == 2

    def test_concat_constants(self, db):
        cursor = db.cursor()
        # String concatenation of constants only — no user input
        table = "users"
        query = "SELECT * FROM " + table + " WHERE id = 1"
        cursor.execute(query)
        assert cursor.fetchone() is not None
