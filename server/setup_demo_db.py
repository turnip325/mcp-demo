#!/usr/bin/env python3
"""
FortiWeb WAF Demo — Demo Database Setup
========================================
Creates and seeds /opt/demo/demo.db with two tables:
  - users    : simulates an identity/auth store (SQL injection target)
  - products : simulates a product catalogue

Safe to re-run — tables are dropped and recreated each time.
This script is also used to reset the database between demo runs.

Usage:
  python setup_demo_db.py
  # or from the server:
  sudo /opt/demo/venv/bin/python /opt/demo/setup_demo_db.py
"""

import os
import sqlite3

DB_DIR = "/opt/demo"
DB_PATH = f"{DB_DIR}/demo.db"

os.makedirs(DB_DIR, exist_ok=True)

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

# ── Users table ───────────────────────────────────────────────────────────────
# Simulates an authentication/identity store. The query_database tool
# allows callers to filter by WHERE clause — the SQL injection demo
# targets this table with a payload like: ' OR '1'='1

c.executescript("""
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT    NOT NULL,
    email    TEXT    NOT NULL,
    role     TEXT    NOT NULL
);
INSERT INTO users (username, email, role) VALUES
    ('alice',   'alice@demo.local',   'admin'),
    ('bob',     'bob@demo.local',     'analyst'),
    ('carol',   'carol@demo.local',   'viewer'),
    ('dave',    'dave@demo.local',    'analyst'),
    ('mallory', 'mallory@demo.local', 'suspended');
""")

# ── Products table ────────────────────────────────────────────────────────────
# Simulates a product catalogue. Provides plausible demo data and a second
# table for legitimate query demonstrations during the baseline test phase.

c.executescript("""
DROP TABLE IF EXISTS products;
CREATE TABLE products (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    price       REAL    NOT NULL,
    description TEXT
);
INSERT INTO products (name, price, description) VALUES
    ('FortiWeb 400F',  12999.99, 'Hardware WAF appliance — 1 Gbps throughput'),
    ('FortiGate 60F',    895.00, 'Next-generation firewall for SMB / branch'),
    ('FortiAnalyzer',   4200.00, 'Centralized log management and analytics'),
    ('FortiManager',    5500.00, 'Centralized device and policy management'),
    ('FortiSandbox',    8800.00, 'Advanced threat detection via sandboxing');
""")

conn.commit()
conn.close()

print(f"Database created: {DB_PATH}")
print("Tables: users (5 rows), products (5 rows)")
