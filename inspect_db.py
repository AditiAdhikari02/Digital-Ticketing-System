import sqlite3

conn = sqlite3.connect("site.db")
cursor = conn.cursor()

# Create ticket table (only if it doesn't exist)
cursor.execute('''
    CREATE TABLE IF NOT EXISTS ticket (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_name TEXT NOT NULL,
        holder_name TEXT NOT NULL,
        seat_number TEXT,
        purchase_date TEXT
    )
''')

conn.commit()

# Now inspect columns
cursor.execute("PRAGMA table_info(ticket);")
columns = cursor.fetchall()

print("Columns in 'ticket' table:")
for col in columns:
    print(col)

conn.close()
