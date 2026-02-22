"""
LogCentry API Routes Package

Contains all API route modules.
"""

from logcentry.api.routes.auth import router as auth_router
from logcentry.api.routes.projects import router as projects_router

__all__ = ["auth_router", "projects_router"]
