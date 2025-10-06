"""
Handlers package for request routing and validation.
"""
from .role_handler import (
    handle_options_request,
    handle_post_request,
    handle_get_request,
    handle_put_request,
    handle_delete_request,
    extract_caller_identity
)

__all__ = [
    'handle_options_request',
    'handle_post_request',
    'handle_get_request',
    'handle_put_request',
    'handle_delete_request',
    'extract_caller_identity'
]
