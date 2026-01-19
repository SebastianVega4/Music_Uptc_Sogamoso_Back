import os
import re
import time
from supabase import create_client, Client
from dotenv import load_dotenv

# Load environment variables
try:
    load_dotenv(encoding='utf-8')
except Exception:
    load_dotenv(encoding='utf-16')

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    print("Error: SUPABASE_URL or SUPABASE_KEY not found in environment variables.")
    exit(1)

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

def fix_remaining_emails():
    print("Searching for remaining records to fix...")
    
    total_updated = 0
    
    while True:
        # Fetch records where description contains "Email:" 
        # We'll fetch 1000 at a time
        try:
            # Note: ilike is used to be case-insensitive
            response = supabase.table('buitres_people')\
                .select('id', 'name', 'description', 'email')\
                .ilike('description', '%Email:%')\
                .limit(1000)\
                .execute()
            
            people = response.data
            
            if not people:
                print("No more records with 'Email:' in description found.")
                break
                
            print(f"Processing batch of {len(people)} records...")
            
            for person in people:
                pid = person['id']
                description = person.get('description', '')
                
                # Double check the description has Email:
                if description and 'Email:' in description:
                    # Extract email
                    email_match = re.search(r'Email:\s*([\w\.-]+@[\w\.-]+)', description, re.IGNORECASE)
                    
                    if email_match:
                        extracted_email = email_match.group(1).strip()
                        new_description = re.sub(r'Email:\s*[\w\.-]+@[\w\.-]+', '', description, flags=re.IGNORECASE).strip()
                        
                        update_data = {
                            'email': extracted_email,
                            'description': new_description
                        }
                        
                        try:
                            supabase.table('buitres_people').update(update_data).eq('id', pid).execute()
                            total_updated += 1
                        except Exception as e:
                            print(f"Failed to update {person['name']} ({pid}): {e}")
                            # To avoid infinite loop if a specific record keeps failing, 
                            # we might want to track failed IDs, but for now we'll just log.
                    else:
                        # If "Email:" exists but no email pattern matches, 
                        # we should probably remove the "Email:" text anyway to stop it from appearing in the query
                        new_description = description.replace('Email:', '').strip()
                        try:
                            supabase.table('buitres_people').update({'description': new_description}).eq('id', pid).execute()
                            print(f"Cleaned up empty 'Email:' tag for {person['name']}")
                        except: pass
            
            print(f"Progress: {total_updated} records fixed so far...")
            # Small sleep to be nice to the API
            time.sleep(0.5)

        except Exception as e:
            print(f"Error during migration batch: {e}")
            break
            
    print(f"Migration finished. Total updated/fixed: {total_updated}")

if __name__ == "__main__":
    fix_remaining_emails()
