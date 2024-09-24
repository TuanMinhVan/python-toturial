import logging

logging.basicConfig(level=logging.INFO)

from .user import User

__all__ = ["User"]

logging.info("Model package initialized")