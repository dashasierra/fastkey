"""
Database Module

Fastkey supports SQLAlchemy, and fails back to
dictionaries should SQLAlchemy not be available.

Dictionaries should not be used in production
"""

try:
    from . import db_alchemy as database
except ImportError:
    from . import db_dictionary as database

users_db = database.users_db
challenges_db = {}
