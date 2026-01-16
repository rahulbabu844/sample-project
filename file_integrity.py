"""
File Integrity Checker
Monitors files for changes using hash-based integrity checking
"""

import os
import json
import hashlib
from datetime import datetime
from hash_tool import calculate_hash


class FileIntegrityChecker:
    """Manages file integrity monitoring using hash values."""
    
    def __init__(self, database_file='integrity_db.json'):
        """
        Initialize the file integrity checker.
        
        Args:
            database_file (str): Path to JSON file storing file hashes
        """
        self.database_file = database_file
        self.database = self._load_database()
    
    def _load_database(self):
        """Load the integrity database from file."""
        if os.path.exists(self.database_file):
            try:
                with open(self.database_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading database: {e}")
                return {}
        return {}
    
    def _save_database(self):
        """Save the integrity database to file."""
        try:
            with open(self.database_file, 'w') as f:
                json.dump(self.database, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving database: {e}")
            return False
    
    def add_file(self, file_path, algorithm='sha256'):
        """
        Add a file to the integrity monitoring database.
        
        Args:
            file_path (str): Path to the file to monitor
            algorithm (str): Hash algorithm to use
        """
        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' not found.")
            return False
        
        file_path = os.path.abspath(file_path)
        hash_value = calculate_hash(file_path, algorithm)
        
        if hash_value:
            file_info = {
                'hash': hash_value,
                'algorithm': algorithm,
                'size': os.path.getsize(file_path),
                'modified': os.path.getmtime(file_path),
                'added_date': datetime.now().isoformat()
            }
            
            self.database[file_path] = file_info
            self._save_database()
            
            print(f"\n✓ File added to integrity database:")
            print(f"  File: {file_path}")
            print(f"  Hash: {hash_value}")
            print(f"  Algorithm: {algorithm.upper()}\n")
            return True
        return False
    
    def check_file(self, file_path):
        """
        Check if a monitored file has been modified.
        
        Args:
            file_path (str): Path to the file to check
            
        Returns:
            dict: Check results with status and details
        """
        file_path = os.path.abspath(file_path)
        
        if file_path not in self.database:
            return {
                'status': 'not_monitored',
                'message': f"File '{file_path}' is not in the integrity database."
            }
        
        if not os.path.exists(file_path):
            return {
                'status': 'deleted',
                'message': f"File '{file_path}' has been deleted or moved."
            }
        
        stored_info = self.database[file_path]
        current_hash = calculate_hash(file_path, stored_info['algorithm'])
        current_size = os.path.getsize(file_path)
        current_modified = os.path.getmtime(file_path)
        
        if current_hash == stored_info['hash']:
            return {
                'status': 'ok',
                'message': f"File '{file_path}' integrity verified - no changes detected.",
                'file': file_path,
                'hash': current_hash
            }
        else:
            return {
                'status': 'modified',
                'message': f"⚠ WARNING: File '{file_path}' has been modified!",
                'file': file_path,
                'original_hash': stored_info['hash'],
                'current_hash': current_hash,
                'original_size': stored_info['size'],
                'current_size': current_size,
                'original_modified': stored_info['modified'],
                'current_modified': current_modified
            }
    
    def check_all(self):
        """Check all monitored files for integrity."""
        if not self.database:
            print("No files in the integrity database.")
            return
        
        print("\n" + "="*60)
        print("FILE INTEGRITY CHECK")
        print("="*60)
        
        results = {
            'ok': [],
            'modified': [],
            'deleted': [],
            'not_monitored': []
        }
        
        for file_path in self.database.keys():
            result = self.check_file(file_path)
            status = result['status']
            results[status].append(result)
            
            if status == 'ok':
                print(f"✓ {file_path}")
            elif status == 'modified':
                print(f"⚠ {file_path} - MODIFIED!")
            elif status == 'deleted':
                print(f"✗ {file_path} - DELETED!")
        
        print("="*60)
        print(f"\nSummary:")
        print(f"  OK: {len(results['ok'])}")
        print(f"  Modified: {len(results['modified'])}")
        print(f"  Deleted: {len(results['deleted'])}")
        print()
        
        return results
    
    def list_files(self):
        """List all files in the integrity database."""
        if not self.database:
            print("No files in the integrity database.")
            return
        
        print("\n" + "="*60)
        print("MONITORED FILES")
        print("="*60)
        for file_path, info in self.database.items():
            print(f"\nFile: {file_path}")
            print(f"  Hash: {info['hash']}")
            print(f"  Algorithm: {info['algorithm'].upper()}")
            print(f"  Size: {info['size']:,} bytes")
            print(f"  Added: {info['added_date']}")
        print("="*60 + "\n")
    
    def remove_file(self, file_path):
        """Remove a file from the integrity database."""
        file_path = os.path.abspath(file_path)
        if file_path in self.database:
            del self.database[file_path]
            self._save_database()
            print(f"✓ File '{file_path}' removed from database.")
            return True
        else:
            print(f"File '{file_path}' not found in database.")
            return False


if __name__ == "__main__":
    checker = FileIntegrityChecker()
    
    print("File Integrity Checker")
    print("-" * 50)
    
    while True:
        print("\nOptions:")
        print("1. Add file to monitor")
        print("2. Check file integrity")
        print("3. Check all files")
        print("4. List monitored files")
        print("5. Remove file from monitoring")
        print("6. Exit")
        
        choice = input("\nEnter choice: ").strip()
        
        if choice == '1':
            file_path = input("Enter file path: ").strip()
            checker.add_file(file_path)
        elif choice == '2':
            file_path = input("Enter file path: ").strip()
            result = checker.check_file(file_path)
            print(f"\n{result['message']}")
        elif choice == '3':
            checker.check_all()
        elif choice == '4':
            checker.list_files()
        elif choice == '5':
            file_path = input("Enter file path: ").strip()
            checker.remove_file(file_path)
        elif choice == '6':
            break
        else:
            print("Invalid choice.")
