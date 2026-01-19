import os
import re
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

def fix_emails():
    print("Resuming email migration from record 56000...")
    
    start = 56000
    batch_size = 1000
    total_processed = 0
    total_updated = 0
    total_skipped = 0
    
    while True:
        print(f"Fetching records {start} to {start + batch_size}...")
        try:
            # Fetch batch
            response = supabase.table('buitres_people').select('*').range(start, start + batch_size - 1).execute()
            people = response.data
            
            if not people:
                print("No more records found.")
                break
                
            batch_count = len(people)
            print(f"Processing batch of {batch_count} records...")
            
            for person in people:
                pid = person['id']
                description = person.get('description', '')
                current_email = person.get('email', '')
                
                # Check if description contains "Email: "
                if description and isinstance(description, str) and (description.strip().startswith('Email:') or 'Email:' in description):
                    # Extract email
                    email_match = re.search(r'Email:\s*([\w\.-]+@[\w\.-]+)', description, re.IGNORECASE)
                    
                    if email_match:
                        extracted_email = email_match.group(1).strip()
                        new_description = re.sub(r'Email:\s*[\w\.-]+@[\w\.-]+', '', description, flags=re.IGNORECASE).strip()
                        
                        update_data = {
                            'email': extracted_email,
                            'description': new_description
                        }
                        
                        # print(f"Updating {person['name']}")
                        try:
                            supabase.table('buitres_people').update(update_data).eq('id', pid).execute()
                            total_updated += 1
                        except Exception as e:
                            print(f"Failed to update {person['name']}: {e}")
                            
                    elif 'Email:' in description:
                        # Fallback simple split
                        parts = description.split('Email:')
                        if len(parts) > 1:
                            candidate = parts[1].strip()
                            if '@' in candidate:
                                update_data = {
                                    'email': candidate,
                                    'description': parts[0].strip()
                                }
                                # print(f"Updating {person['name']} (Fallback)")
                                supabase.table('buitres_people').update(update_data).eq('id', pid).execute()
                                total_updated += 1
                                continue
                
                elif description and '@uptc.edu.co' in description and not current_email:
                     if '@' in description and len(description.split()) == 1:
                          update_data = {
                            'email': description.strip(),
                            'description': ''
                          }
                          # print(f"Updating {person['name']} (Direct)")
                          supabase.table('buitres_people').update(update_data).eq('id', pid).execute()
                          total_updated += 1
                     else:
                          total_skipped += 1
                else:
                    total_skipped += 1
            
            total_processed += batch_count
            start += batch_size
            
            # Print progress every 5000 records
            if total_processed % 5000 == 0:
                 print(f"--- Progress: {total_processed} records processed (Updated: {total_updated}) ---")

        except Exception as e:
            print(f"Error fetching batch at start {start}: {e}")
            # If we hit a critical error, maybe break or retry? 
            # For now, let's break to avoid infinite loops on error
            break
            
    print(f"Migration complete. Total Processed: {total_processed}, Updated: {total_updated}, Skipped: {total_skipped}")

if __name__ == "__main__":
    fix_emails()
