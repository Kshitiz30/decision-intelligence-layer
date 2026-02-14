import sqlite3
import hashlib
import json
import asyncio
from datetime import datetime

DB_PATH = "dil_ledger.db"

async def log_decision(decision_data: dict) -> bool:
    """
    Logs a decision to a local SQLite database with a SHA-256 fingerprint.
    Returns True if successful, False otherwise.
    """
    try:
        # Generate Digital Fingerprint
        # Combine Prompt, Response, and RiskScore for the hash
        content_to_hash = (
            str(decision_data.get('prompt', '')) + 
            str(decision_data.get('proposed_action', '')) + 
            str(decision_data.get('risk_assessment', {}).get('RiskScore', 0))
        ).encode('utf-8')
        
        fingerprint = hashlib.sha256(content_to_hash).hexdigest()
        
        # Prepare data for storage
        timestamp = datetime.now().isoformat()
        full_record = json.dumps(decision_data)
        
        # Async-friendly DB operation (using run_in_executor for sqlite3)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _write_to_db, timestamp, fingerprint, full_record)
        
        return True
    except Exception as e:
        print(f"Ledger Error: {e}")
        return False

def _write_to_db(timestamp, fingerprint, record):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create table if not exists
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ledger (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            fingerprint TEXT UNIQUE,
            data TEXT
        )
    ''')
    
    cursor.execute(
        "INSERT INTO ledger (timestamp, fingerprint, data) VALUES (?, ?, ?)",
        (timestamp, fingerprint, record)
    )
    
    conn.commit()
    conn.close()
