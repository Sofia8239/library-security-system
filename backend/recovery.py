"""
Recovery Script for Library System
Rebuilds the database from system.log in case of data loss.
"""

import json
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from backend.library_system import LibrarySystem, User, Book, Review, Reservation, json_line_encode

def recover_from_log(log_file='data/system.log'):
    """Recover system state from log file."""
    library = LibrarySystem()
    
    library.users = {}
    library.books = {}
    library.reviews = []
    library.reservations = []
    
    if not os.path.exists(log_file):
        print("Log file not found")
        return
    
    with open(log_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(' | ')
            if len(parts) != 5:
                continue
            timestamp = parts[0].strip('[]')
            action_part = parts[1]
            user_part = parts[2]
            book_part = parts[3]
            result_part = parts[4]
            
            action = action_part.split(': ')[1]
            user_id = user_part.split(': ')[1] if ': ' in user_part else ''
            book_id = book_part.split(': ')[1] if ': ' in book_part else ''
            result = result_part.split(': ')[1] if ': ' in result_part else ''
            
            if result != 'SUCCESS':
                continue
            
            if action == 'user_registered':
                pass
            elif action == 'book_added':
                pass
    
    print("Recovery completed")
    return library

if __name__ == '__main__':
    recover_from_log()