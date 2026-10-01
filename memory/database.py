import sqlite3
import os
import secrets

# =========================================================
# DATABASE LOCATION
# =========================================================

DATABASE_PATH = os.path.join(
    os.path.dirname(__file__),
    "cybertrap.db"
)


# =========================================================
# CONNECT TO DATABASE
# =========================================================

def connect_db():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


# =========================================================
# DATABASE MIGRATION HELPERS
# =========================================================

def _column_names(cursor, table_name):
    cursor.execute(f"PRAGMA table_info({table_name})")
    return [row[1] for row in cursor.fetchall()]


def _ensure_column(cursor, table_name, column_name, definition):
    columns = _column_names(cursor, table_name)
    if column_name not in columns:
        cursor.execute(
            f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}"
        )


# =========================================================
# CREATE / UPGRADE TABLES
# =========================================================

def create_tables():
    connection = connect_db()
    cursor = connection.cursor()

    # -----------------------------------------------------
    # USERS
    # -----------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # -----------------------------------------------------
    # CASES
    # -----------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            case_id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_description TEXT NOT NULL,
            crime_type TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id TEXT
        )
    """)

    # Upgrade an older Cyber Trap database that already has cases.
    _ensure_column(cursor, "cases", "user_id", "TEXT")

    # -----------------------------------------------------
    # EVIDENCE
    # -----------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER,
            evidence_type TEXT,
            evidence_text TEXT,
            FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
        )
    """)

    # -----------------------------------------------------
    # INVESTIGATIONS
    # -----------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS investigations (
            investigation_id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER,
            action TEXT,
            result TEXT,
            FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
        )
    """)

    # -----------------------------------------------------
    # REPORTS
    # -----------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            report_id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER,
            report_text TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
        )
    """)

    connection.commit()
    connection.close()


# =========================================================
# USER MANAGEMENT
# =========================================================

def generate_user_id():
    connection = connect_db()
    cursor = connection.cursor()

    try:
        while True:
            user_id = "CT-" + secrets.token_hex(4).upper()
            cursor.execute(
                "SELECT 1 FROM users WHERE user_id = ?",
                (user_id,)
            )
            if cursor.fetchone() is None:
                return user_id
    finally:
        connection.close()


def create_user(user_id, name, email, phone, password_hash, role="user"):
    connection = connect_db()
    cursor = connection.cursor()

    try:
        cursor.execute("""
            INSERT INTO users
            (user_id, name, email, phone, password_hash, role)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            name.strip(),
            email.strip().lower(),
            phone.strip(),
            password_hash,
            role.lower()
        ))
        connection.commit()
        return True
    except sqlite3.IntegrityError:
        connection.rollback()
        return False
    finally:
        connection.close()


def get_user_by_email(email):
    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT user_id, name, email, phone, password_hash, role, created_at
        FROM users
        WHERE LOWER(email) = LOWER(?)
        LIMIT 1
    """, (email.strip(),))

    user = cursor.fetchone()
    connection.close()
    return user


def get_user_by_id(user_id):
    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT user_id, name, email, phone, password_hash, role, created_at
        FROM users
        WHERE user_id = ?
        LIMIT 1
    """, (user_id,))

    user = cursor.fetchone()
    connection.close()
    return user


def email_exists(email):
    return get_user_by_email(email) is not None


def get_all_users():
    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT user_id, name, email, phone, role, created_at
        FROM users
        ORDER BY created_at DESC
    """)

    users = cursor.fetchall()
    connection.close()
    return users


# =========================================================
# CASE MANAGEMENT
# =========================================================

def save_case(
    case_description,
    crime_type,
    risk_score,
    risk_level,
    user_id=None
):
    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO cases
        (
            case_description,
            crime_type,
            risk_score,
            risk_level,
            user_id
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        case_description,
        crime_type,
        risk_score,
        risk_level,
        user_id
    ))

    case_id = cursor.lastrowid
    connection.commit()
    connection.close()
    return case_id


def assign_case_to_user(case_id, user_id):
    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE cases
        SET user_id = ?
        WHERE case_id = ?
    """, (user_id, case_id))

    connection.commit()
    updated = cursor.rowcount
    connection.close()
    return updated > 0


def get_all_cases():
    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            case_id,
            user_id,
            case_description,
            crime_type,
            risk_score,
            risk_level,
            created_at
        FROM cases
        ORDER BY case_id DESC
    """)

    cases = cursor.fetchall()
    connection.close()
    return cases


def get_recent_cases(limit=5):
    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            case_id,
            user_id,
            case_description,
            crime_type,
            risk_score,
            risk_level,
            created_at
        FROM cases
        ORDER BY case_id DESC
        LIMIT ?
    """, (int(limit),))

    cases = cursor.fetchall()
    connection.close()
    return cases


def get_user_cases(user_id):
    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            case_id,
            user_id,
            case_description,
            crime_type,
            risk_score,
            risk_level,
            created_at
        FROM cases
        WHERE user_id = ?
        ORDER BY case_id DESC
    """, (user_id,))

    cases = cursor.fetchall()
    connection.close()
    return cases


def get_case_by_id(case_id):
    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            case_id,
            user_id,
            case_description,
            crime_type,
            risk_score,
            risk_level,
            created_at
        FROM cases
        WHERE case_id = ?
        LIMIT 1
    """, (case_id,))

    case = cursor.fetchone()
    connection.close()
    return case


# =========================================================
# EVIDENCE
# =========================================================

def save_evidence(case_id, evidence_type, evidence_text):
    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO evidence
        (case_id, evidence_type, evidence_text)
        VALUES (?, ?, ?)
    """, (case_id, evidence_type, evidence_text))

    connection.commit()
    connection.close()


def get_case_evidence(case_id):
    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT evidence_type, evidence_text
        FROM evidence
        WHERE case_id = ?
        ORDER BY evidence_id ASC
    """, (case_id,))

    evidence = cursor.fetchall()
    connection.close()
    return evidence


# =========================================================
# INVESTIGATION HISTORY
# =========================================================

def save_investigation(case_id, action, result):
    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO investigations
        (case_id, action, result)
        VALUES (?, ?, ?)
    """, (case_id, action, result))

    connection.commit()
    connection.close()


def get_case_investigations(case_id):
    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT action, result
        FROM investigations
        WHERE case_id = ?
        ORDER BY investigation_id ASC
    """, (case_id,))

    investigations = cursor.fetchall()
    connection.close()
    return investigations


# =========================================================
# REPORTS
# =========================================================

def save_report(case_id, report_text):
    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO reports
        (case_id, report_text)
        VALUES (?, ?)
    """, (case_id, report_text))

    connection.commit()
    connection.close()


def get_case_report(case_id):
    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT report_id, report_text, created_at
        FROM reports
        WHERE case_id = ?
        ORDER BY report_id DESC
        LIMIT 1
    """, (case_id,))

    report = cursor.fetchone()
    connection.close()
    return report


# =========================================================
# DASHBOARD STATISTICS
# =========================================================

def get_dashboard_stats():
    connection = connect_db()
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) FROM cases")
    total_cases = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM cases
        WHERE UPPER(COALESCE(risk_level, '')) = 'CRITICAL'
    """)
    critical_cases = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM cases
        WHERE UPPER(COALESCE(risk_level, '')) = 'HIGH'
    """)
    high_cases = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM cases
        WHERE UPPER(COALESCE(risk_level, '')) = 'MEDIUM'
    """)
    medium_cases = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM cases
        WHERE UPPER(COALESCE(risk_level, '')) = 'LOW'
    """)
    low_cases = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM investigations")
    total_investigations = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]

    connection.close()

    return {
        "total_cases": total_cases,
        "critical_cases": critical_cases,
        "high_cases": high_cases,
        "medium_cases": medium_cases,
        "low_cases": low_cases,
        "total_investigations": total_investigations,
        "total_users": total_users
    }


# =========================================================
# INITIALIZE DATABASE
# =========================================================

create_tables()


if __name__ == "__main__":
    print("✓ Cyber Trap database is ready.")
