"""
Password Strength Checker
Checks password strength based on various criteria
"""

import re
import string


def check_password_strength(password):
    """
    Analyzes password strength and returns a detailed report.
    
    Args:
        password (str): The password to check
        
    Returns:
        dict: Dictionary containing strength score, level, and feedback
    """
    if not password:
        return {
            'score': 0,
            'level': 'Very Weak',
            'feedback': 'Password cannot be empty'
        }
    
    score = 0
    feedback = []
    
    # Length checks
    length = len(password)
    if length >= 8:
        score += 1
        feedback.append('✓ Has minimum 8 characters')
    else:
        feedback.append('✗ Should be at least 8 characters')
    
    if length >= 12:
        score += 1
        feedback.append('✓ Has 12+ characters (good)')
    
    if length >= 16:
        score += 1
        feedback.append('✓ Has 16+ characters (excellent)')
    
    # Character variety checks
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    
    if has_lower:
        score += 1
        feedback.append('✓ Contains lowercase letters')
    else:
        feedback.append('✗ Missing lowercase letters')
    
    if has_upper:
        score += 1
        feedback.append('✓ Contains uppercase letters')
    else:
        feedback.append('✗ Missing uppercase letters')
    
    if has_digit:
        score += 1
        feedback.append('✓ Contains numbers')
    else:
        feedback.append('✗ Missing numbers')
    
    if has_special:
        score += 1
        feedback.append('✓ Contains special characters')
    else:
        feedback.append('✗ Missing special characters')
    
    # Common patterns check
    common_patterns = [
        r'(.)\1{2,}',  # Repeated characters
        r'(012|123|234|345|456|567|678|789|890)',  # Sequential numbers
        r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',  # Sequential letters
    ]
    
    has_weak_pattern = False
    for pattern in common_patterns:
        if re.search(pattern, password.lower()):
            has_weak_pattern = True
            feedback.append('⚠ Contains weak patterns (sequential or repeated characters)')
            break
    
    if not has_weak_pattern:
        feedback.append('✓ No obvious weak patterns detected')
    
    # Common passwords check
    common_passwords = ['password', '12345678', 'qwerty', 'abc123', 'password123']
    if password.lower() in common_passwords:
        score = max(0, score - 3)
        feedback.append('⚠ This is a very common password - avoid using it!')
    
    # Determine strength level
    if score <= 2:
        level = 'Very Weak'
    elif score <= 4:
        level = 'Weak'
    elif score <= 6:
        level = 'Moderate'
    elif score <= 8:
        level = 'Strong'
    else:
        level = 'Very Strong'
    
    return {
        'score': score,
        'level': level,
        'feedback': feedback,
        'length': length
    }


def display_password_report(password):
    """Display a formatted password strength report."""
    result = check_password_strength(password)
    
    print("\n" + "="*50)
    print("PASSWORD STRENGTH REPORT")
    print("="*50)
    print(f"Password: {'*' * len(password)}")
    print(f"Length: {result['length']} characters")
    print(f"Strength Score: {result['score']}/10")
    print(f"Strength Level: {result['level']}")
    print("\nDetails:")
    for item in result['feedback']:
        print(f"  {item}")
    print("="*50 + "\n")
    
    return result


if __name__ == "__main__":
    print("Password Strength Checker")
    print("-" * 50)
    password = input("Enter password to check: ")
    display_password_report(password)
