"""
Dictionary Implementation
"""

import logging


class UsersDatabase(dict):
    """
    Extending Dictionary Class for Auth Compatability
    """

    def user_exists(self, username: str) -> bool:
        """
        Returns boolean indicating if specified user is in database
        """
        return username in self.keys()


users_db = UsersDatabase()

logging.warning(
    "Running with db_dictionary. Do not run this configuration in production"
)
