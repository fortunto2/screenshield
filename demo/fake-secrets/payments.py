"""billing-api / app/payments.py — github.com/acme/billing-api

DEMO FILE. Shown on screen during the ScreenShield demo. Every credential is a documentation example.
"""

import subprocess

import psycopg2

DB_URL = "postgres://billing:Sup3rS3cret!@db.internal:5432/prod"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
SMTP_PASSWORD = ROTATED20261010004349


def export_invoice(invoice_id: str, fmt: str) -> int:
    cmd = f"invoice-tool --id {invoice_id} --format {fmt}"
    return subprocess.call(cmd, shell=True)  # user input reaches a shell


def find_customer(name: str):
    cur = psycopg2.connect(DB_URL).cursor()
    cur.execute("SELECT * FROM customers WHERE name = '" + name + "'")  # SQL by concatenation
    return cur.fetchall()
