
import sqlite3
import pandas as pd
import json

def safe_json_parse(x):
    try:
        if isinstance(x, str):
            return json.loads(x)
        return x
    except:
        return {}

try:
    conn = sqlite3.connect('shadow_hunter.db')
    cursor = conn.cursor()
    
    # Get table names
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    
    print(f"\n{'='*60}")
    print(f"📂 SHADOW HUNTER DATABASE INSPECTOR")
    print(f"{'='*60}\n")
    
    for table in tables:
        table_name = table[0]
        count = cursor.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]
        
        print(f"🔹 TABLE: {table_name.upper()} ({count} records)")
        
        if count > 0:
            df = pd.read_sql_query(f"SELECT * FROM {table_name} LIMIT 5", conn)
            
            # Make it more readable: Parse JSON properties
            if 'properties' in df.columns:
                # Expand JSON into columns
                props = df['properties'].apply(safe_json_parse).apply(pd.Series)
                # Drop original messy column and join new ones
                df = df.drop('properties', axis=1).join(props)
                
            # Clean up redundant columns if they exist
            if 'labels' in df.columns:
                df['labels'] = df['labels'].apply(lambda x: x.replace('["', '').replace('"]', ''))

            # Fill NaN with -
            df = df.fillna('-')
            
            # Print nicely formatted
            print(df.to_string(index=False))
            print("\n" + "-" * 60 + "\n")
            
    conn.close()

except Exception as e:
    print(f"Error accessing database: {e}")
