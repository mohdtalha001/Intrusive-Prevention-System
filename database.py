import sqlite3

# Database initialize karne ke liye function
def init_db():
    conn = sqlite3.connect('ips_logs.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            src_ip TEXT,
            attack_type TEXT,
            action TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Naye attack event ko database mein insert karne ke liye
def log_event(src_ip, attack_type, action="BLOCKED"):
    conn = sqlite3.connect('ips_logs.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO logs (src_ip, attack_type, action)
        VALUES (?, ?, ?)
    ''', (src_ip, attack_type, action))
    conn.commit()
    conn.close()

# Database se logs fetch karne ke liye
def get_all_logs(limit=20):
    conn = sqlite3.connect('ips_logs.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, timestamp, src_ip, attack_type, action FROM logs ORDER BY id DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows

if __name__ == '__main__':
    init_db()
    print("✅ Database created and ready!")