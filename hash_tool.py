"""
Hash Generator and Verifier
Generates and verifies file hashes using various algorithms
"""

import hashlib
import os


def calculate_hash(file_path, algorithm='sha256'):
    """
    Calculate hash of a file.
    
    Args:
        file_path (str): Path to the file
        algorithm (str): Hash algorithm (md5, sha1, sha256, sha512)
        
    Returns:
        str: Hexadecimal hash of the file
    """
    hash_obj = hashlib.new(algorithm)
    
    try:
        with open(file_path, 'rb') as f:
            # Read file in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"Error calculating hash: {e}")
        return None


def calculate_string_hash(text, algorithm='sha256'):
    """
    Calculate hash of a string.
    
    Args:
        text (str): Text to hash
        algorithm (str): Hash algorithm (md5, sha1, sha256, sha512)
        
    Returns:
        str: Hexadecimal hash of the string
    """
    hash_obj = hashlib.new(algorithm)
    hash_obj.update(text.encode('utf-8'))
    return hash_obj.hexdigest()


def verify_file_integrity(file_path, expected_hash, algorithm='sha256'):
    """
    Verify file integrity by comparing with expected hash.
    
    Args:
        file_path (str): Path to the file
        expected_hash (str): Expected hash value
        algorithm (str): Hash algorithm used
        
    Returns:
        bool: True if hash matches, False otherwise
    """
    actual_hash = calculate_hash(file_path, algorithm)
    if actual_hash is None:
        return False
    
    return actual_hash.lower() == expected_hash.lower()


def display_hash_info(file_path, algorithm='sha256'):
    """Display hash information for a file."""
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        return None
    
    hash_value = calculate_hash(file_path, algorithm)
    if hash_value:
        file_size = os.path.getsize(file_path)
        print("\n" + "="*50)
        print("FILE HASH INFORMATION")
        print("="*50)
        print(f"File: {file_path}")
        print(f"Size: {file_size:,} bytes")
        print(f"Algorithm: {algorithm.upper()}")
        print(f"Hash: {hash_value}")
        print("="*50 + "\n")
        return hash_value
    return None


if __name__ == "__main__":
    print("Hash Generator and Verifier")
    print("-" * 50)
    
    choice = input("Enter '1' for file hash, '2' for string hash: ")
    
    if choice == '1':
        file_path = input("Enter file path: ")
        algo = input("Enter algorithm (md5/sha1/sha256/sha512) [default: sha256]: ").lower() or 'sha256'
        display_hash_info(file_path, algo)
    elif choice == '2':
        text = input("Enter text to hash: ")
        algo = input("Enter algorithm (md5/sha1/sha256/sha512) [default: sha256]: ").lower() or 'sha256'
        hash_value = calculate_string_hash(text, algo)
        print(f"\n{algo.upper()} Hash: {hash_value}\n")
    else:
        print("Invalid choice.")
