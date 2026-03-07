import sqlite3
import os

DB_PATH = "data/ids_logs.db"

def migrate():
    if not os.path.exists(DB_PATH):
        print("Database not found. Nothing to migrate.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("PRAGMA table_info(alerts)")
    existing_cols = [c[1] for c in cursor.fetchall()]
    
    # Define columns that MUST be in the table for the dashboard to work
    additions = [
        ("port", "INTEGER"),
        ("packet_size", "INTEGER"),
        ("flags", "TEXT"),
        ("payload", "TEXT"),
        ("detection_source", "TEXT"),
        ("risk_score", "INTEGER"),
        ("is_replay", "BOOLEAN")
    ]
    
    for col_name, col_type in additions:
        if col_name not in existing_cols:
            print(f"Adding missing column: {col_name}")
            default_val = "0" if col_type in ["INTEGER", "BOOLEAN", "REAL"] else "''"
            try:
                cursor.execute(f"ALTER TABLE alerts ADD COLUMN {col_name} {col_type} DEFAULT {default_val}")
                conn.commit()
            except Exception as e:
                print(f"Error adding {col_name}: {e}")
    
    conn.close()
    print("Migration Check Complete.")

if __name__ == "__main__":
    migrate()
