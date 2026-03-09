# remove_all_duplicates.py
import sqlite3
from datetime import datetime

print("=" * 60)
print("🧹 COMPLETE DUPLICATE REMOVER")
print("=" * 60)

conn = sqlite3.connect('validation_results.db')
cursor = conn.cursor()

# Find all duplicate record_id + field_name combinations
cursor.execute('''
    SELECT record_id, field_name, COUNT(*) as count, 
           GROUP_CONCAT(id) as ids, 
           GROUP_CONCAT(timestamp) as timestamps
    FROM validation_errors
    GROUP BY record_id, field_name
    HAVING COUNT(*) > 1
    ORDER BY record_id, field_name
''')

duplicates = cursor.fetchall()

if not duplicates:
    print("✅ No duplicates found! Your database is clean.")
else:
    print(f"❌ Found {len(duplicates)} record/field combinations with duplicates:")
    print()
    
    total_to_delete = 0
    all_delete_ids = []
    
    for dup in duplicates:
        record_id = dup[0]
        field_name = dup[1]
        count = dup[2]
        ids = dup[3].split(',')
        timestamps = dup[4].split(',')
        
        print(f"\n📌 Record: '{record_id}', Field: '{field_name}' - {count} occurrences")
        
        # Pair IDs with timestamps and sort by timestamp (newest first)
        id_time_pairs = list(zip(ids, timestamps))
        id_time_pairs.sort(key=lambda x: x[1], reverse=True)
        
        # Keep the newest, delete the rest
        keep_id = id_time_pairs[0][0]
        keep_time = id_time_pairs[0][1]
        delete_ids = [int(pair[0]) for pair in id_time_pairs[1:]]
        
        print(f"   ✅ KEEPING: ID {keep_id} (from {keep_time})")
        for del_id, del_time in id_time_pairs[1:]:
            print(f"   🗑️ DELETING: ID {del_id} (from {del_time})")
            total_to_delete += 1
            all_delete_ids.extend(delete_ids)
    
    print(f"\n📊 Total duplicates to delete: {total_to_delete}")
    
    # Ask for confirmation
    response = input("\n⚠️  Proceed with deletion? (yes/no): ")
    
    if response.lower() == 'yes':
        # Delete all duplicates in one query
        if all_delete_ids:
            # Remove duplicates from list (in case of duplicates in the list)
            unique_delete_ids = list(set(all_delete_ids))
            placeholders = ','.join('?' * len(unique_delete_ids))
            cursor.execute(f"DELETE FROM validation_errors WHERE id IN ({placeholders})", unique_delete_ids)
            conn.commit()
            print(f"\n✅ Deleted {len(unique_delete_ids)} duplicate errors!")
    else:
        print("\n❌ Operation cancelled.")

# Show final statistics
print("\n" + "=" * 60)
print("📊 FINAL DATABASE STATISTICS")
print("=" * 60)

# Show errors per record
cursor.execute('''
    SELECT record_id, COUNT(*) as count
    FROM validation_errors
    GROUP BY record_id
    ORDER BY count DESC
''')
print("\nErrors per record:")
for row in cursor.fetchall():
    print(f"   {row[0]}: {row[1]} errors")

# Show unique combinations
cursor.execute('''
    SELECT record_id, field_name, timestamp
    FROM validation_errors
    ORDER BY record_id, field_name, datetime(timestamp) DESC
''')
rows = cursor.fetchall()

print("\nUnique errors (one per field per record):")
current_record = None
current_field = None
for row in rows:
    record = row[0]
    field = row[1]
    time = row[2]
    
    if record != current_record or field != current_field:
        print(f"   {record} - {field}: {time}")
        current_record = record
        current_field = field

conn.close()

print("\n" + "=" * 60)
print("🎉 Cleanup complete! Your dashboard will now show unique errors only.")
print("=" * 60)