
import os
from supabase import create_client
from dotenv import load_dotenv

load_dotenv(encoding='utf-8')

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    print("Error: SUPABASE_URL or SUPABASE_KEY not found in environment")
    exit(1)

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

def add_column_if_not_exists(table, column, data_type):
    print(f"Checking {table} for {column}...")
    try:
        # Try to select the column to see if it exists
        supabase.table(table).select(column).limit(1).execute()
        print(f"Column {column} already exists in {table}.")
    except Exception as e:
        print(f"Column {column} likely missing in {table}. Attempting to add it via SQL (RPC) or direct query if possible.")
        # Supabase-py client doesn't support DDL directly easily unless we use rpc or raw sql if enabled.
        # However, we can try to use the postgres connection if we had it, but we only have REST.
        # A trick is to use the SQL editor in the dashboard, but I can't do that.
        # Another trick: If the user provided a service key, we might have more permissions.
        # Let's try to use a raw SQL query if there's an endpoint or function for it.
        # Often there isn't one exposed by default.
        
        # ALTERNATIVE: We can't easily alter table schema via the JS/Python client unless there's a stored procedure for it.
        # I will try to assume the user can run this, OR I will try to use a workaround.
        # Workaround: I can't really add columns without SQL.
        # I will ask the user to add the columns OR I will try to define a stored procedure 'exec_sql' if it exists? No.
        
        print("WARNING: Cannot automatically add columns via Supabase Client without SQL access.")
        print(f"Please execute the following SQL in your Supabase SQL Editor:")
        print(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {data_type};")

# Since I cannot run DDL, I will notify the user to run the SQL.
# But wait, I am an agent. I should try to do it if I can.
# If I can't, I'll have to ask the user.
# Let's try to see if I can use the 'rpc' to run SQL if a function exists.
# Usually not.

# I will create a migration file and ask the user to run it? 
# Or I can try to proceed and see if the insert fails?
# If I modify the code to insert 'dedication', and the column is missing, it will fail.

# Let's try to just print the instructions for the user.
pass

print("--- MIGRATION INSTRUCTIONS ---")
print("Please run the following SQL commands in your Supabase SQL Editor to enable the Dedications feature:")
print("")
print("ALTER TABLE song_ranking ADD COLUMN IF NOT EXISTS dedication text;")
print("ALTER TABLE song_history ADD COLUMN IF NOT EXISTS dedication text;")
print("")
print("------------------------------")
