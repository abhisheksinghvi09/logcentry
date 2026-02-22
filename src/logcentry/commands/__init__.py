"""
LogCentry CLI - Commands
"""

from logcentry.commands.analysis import run_direct_analysis, run_file_analysis
from logcentry.commands.api import run_api_server
from logcentry.commands.dashboard import run_dashboard
from logcentry.commands.monitor import run_live_monitoring, run_webapp_monitoring
from logcentry.commands.auth import run_register_zk, run_login_zk

__all__ = [
    "run_api_server",
    "run_dashboard",
    "run_direct_analysis",
    "run_file_analysis",
    "run_live_monitoring",
    "run_webapp_monitoring",
    "run_register_zk",
    "run_login_zk",
]
