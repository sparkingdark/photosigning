"""Pixel-embedded, public-key photograph signatures."""

from .core import PhotoSignError, sign_photo, verify_photo

__all__ = ["PhotoSignError", "sign_photo", "verify_photo"]
