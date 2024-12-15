# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
# This file is included in the final Docker image and SHOULD be overridden when
# deploying the image to prod. Settings configured here are intended for use in local
# development environments. Also note that superset_config_docker.py is imported
# as a final step as a means to override "defaults" configured here
#
import logging
import os
from superset.security import SupersetSecurityManager
from flask_appbuilder.security.views import AuthDBView
from flask import flash, redirect, request, g, url_for, session
from redis import Redis
from flask_appbuilder.security.views import AuthDBView
from flask_appbuilder import expose
from flask import flash, redirect, request, url_for
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta

from celery.schedules import crontab
from flask_caching.backends.filesystemcache import FileSystemCache

from functools import wraps

logger = logging.getLogger()

APP_ICON = "/static/assets/images/DN_Logo.svg"

# Enable server-side sessions
SESSION_TYPE = "redis"
SESSION_REDIS = Redis(host='redis', port=6379, db=0, decode_responses=True)  # Use the Docker Compose service name as hostname
SESSION_USE_SIGNER = True
SESSION_PERMANENT = True  # This enables session lifetime configuration
PERMANENT_SESSION_LIFETIME = timedelta(minutes=20)  # Session expires after 20 minutes of inactivity

def check_session_validity():
    """Check if the current session is valid"""
    if hasattr(g, 'user') and g.user.is_authenticated:
        active_session = SessionManager.get_active_session(g.user.id)
        if not active_session:
            # Session has expired, clear Flask session and force logout
            session.clear()
            return False
    return True

# Create a before_request handler to check session validity
def before_request():
    # Skip session check for login/logout endpoints
    if request.endpoint in ['AuthDBView.login', 'CustomAuthDBView.login', 'AuthDBView.logout', 'CustomAuthDBView.logout']:
        return None
        
    if not check_session_validity():
        flash('Your session has expired. Please log in again.', 'warning')
        return redirect(url_for('CustomAuthDBView.login'))

class SessionManager:
    @staticmethod
    def register_session(user_id):
        # Clear any existing sessions first
        SessionManager.clear_session(user_id)
        session_key = f"user_session:{user_id}"
        session_data = {
            "user_id": user_id,
            "login_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "last_activity": datetime.now().timestamp(),
            "ip_address": request.remote_addr,
            "user_agent": request.user_agent.string
        }
        SESSION_REDIS.hmset(session_key, session_data)
        SESSION_REDIS.expire(session_key, int(PERMANENT_SESSION_LIFETIME.total_seconds()))

    @staticmethod
    def get_active_session(user_id):
        session_key = f"user_session:{user_id}"
        session_data = SESSION_REDIS.hgetall(session_key)
        if session_data:
            last_activity = float(session_data.get('last_activity', 0))
            if datetime.now().timestamp() - last_activity > PERMANENT_SESSION_LIFETIME.total_seconds():
                # Session has expired
                SessionManager.clear_session(user_id)
                return None
            # Update last activity time
            SESSION_REDIS.hset(session_key, "last_activity", datetime.now().timestamp())
            SESSION_REDIS.expire(session_key, int(PERMANENT_SESSION_LIFETIME.total_seconds()))
            return session_data
        return None

    @staticmethod
    def get_session_info(user_id):
        session_data = SessionManager.get_active_session(user_id)
        if session_data:
            return {
                "ip_address": session_data.get("ip_address", "unknown"),
                "login_time": session_data.get("login_time", "unknown"),
                "user_agent": session_data.get("user_agent", "unknown")
            }
        return None

    @staticmethod
    def clear_session(user_id):
        session_key = f"user_session:{user_id}"
        SESSION_REDIS.delete(session_key)

class CustomAuthDBView(AuthDBView):
    login_template = "appbuilder/general/security/login_db.html"

    def __init__(self):
        super(CustomAuthDBView, self).__init__()
        if not hasattr(self, 'form'):
            from flask_appbuilder.security.forms import LoginForm_db
            self.form = LoginForm_db
    
    @expose('/login/', methods=['GET', 'POST'])
    def login(self):
        if request.method == 'POST':
            username = request.form.get('username')
            
            # First verify if user exists and check for existing session
            user = self.appbuilder.sm.find_user(username=username)
            if user:
                active_session = SessionManager.get_active_session(user.id)
                if active_session:
                    session_info = SessionManager.get_session_info(user.id)
                    flash(
                        f'Account already logged in from {session_info["ip_address"]} '
                        f'since {session_info["login_time"]}. Please log out from there first.',
                        'warning'
                    )
                    form = self.form()
                    form.username.data = username
                    return self.render_template(
                        self.login_template,
                        title=self.title,
                        form=form,
                        appbuilder=self.appbuilder,
                    )
            
            # If no existing session, proceed with normal login
            response = super().login()
            
            # Only register session if login was successful and user is authenticated
            if response.status_code == 302 and hasattr(g, 'user') and g.user.is_authenticated:
                SessionManager.register_session(g.user.id)
            
            return response
                
        return super().login()

    @expose('/logout/', methods=['GET'])
    def logout(self):
        if hasattr(g, 'user') and g.user.is_authenticated:
            SessionManager.clear_session(g.user.id)
        return super().logout()

class CustomSecurityManager(SupersetSecurityManager):
    authdbview = CustomAuthDBView
    
    def __init__(self, appbuilder):
        super(CustomSecurityManager, self).__init__(appbuilder)
        self.appbuilder.app.before_request(before_request)

CUSTOM_SECURITY_MANAGER = CustomSecurityManager

DATABASE_DIALECT = os.getenv("DATABASE_DIALECT")
DATABASE_USER = os.getenv("DATABASE_USER")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
DATABASE_HOST = os.getenv("DATABASE_HOST")
DATABASE_PORT = os.getenv("DATABASE_PORT")
DATABASE_DB = os.getenv("DATABASE_DB")

EXAMPLES_USER = os.getenv("EXAMPLES_USER")
EXAMPLES_PASSWORD = os.getenv("EXAMPLES_PASSWORD")
EXAMPLES_HOST = os.getenv("EXAMPLES_HOST")
EXAMPLES_PORT = os.getenv("EXAMPLES_PORT")
EXAMPLES_DB = os.getenv("EXAMPLES_DB")

# The SQLAlchemy connection string.
SQLALCHEMY_DATABASE_URI = (
    f"{DATABASE_DIALECT}://"
    f"{DATABASE_USER}:{DATABASE_PASSWORD}@"
    f"{DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_DB}"
)

SQLALCHEMY_EXAMPLES_URI = (
    f"{DATABASE_DIALECT}://"
    f"{EXAMPLES_USER}:{EXAMPLES_PASSWORD}@"
    f"{EXAMPLES_HOST}:{EXAMPLES_PORT}/{EXAMPLES_DB}"
)

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")
REDIS_CELERY_DB = os.getenv("REDIS_CELERY_DB", "0")
REDIS_RESULTS_DB = os.getenv("REDIS_RESULTS_DB", "1")

RESULTS_BACKEND = FileSystemCache("/app/superset_home/sqllab")

CACHE_CONFIG = {
    "CACHE_TYPE": "RedisCache",
    "CACHE_DEFAULT_TIMEOUT": 300,
    "CACHE_KEY_PREFIX": "superset_",
    "CACHE_REDIS_HOST": REDIS_HOST,
    "CACHE_REDIS_PORT": REDIS_PORT,
    "CACHE_REDIS_DB": REDIS_RESULTS_DB,
}
DATA_CACHE_CONFIG = CACHE_CONFIG


class CeleryConfig:
    broker_url = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_CELERY_DB}"
    imports = (
        "superset.sql_lab",
        "superset.tasks.scheduler",
        "superset.tasks.thumbnails",
        "superset.tasks.cache",
    )
    result_backend = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_RESULTS_DB}"
    worker_prefetch_multiplier = 1
    task_acks_late = False
    beat_schedule = {
        "reports.scheduler": {
            "task": "reports.scheduler",
            "schedule": crontab(minute="*", hour="*"),
        },
        "reports.prune_log": {
            "task": "reports.prune_log",
            "schedule": crontab(minute=10, hour=0),
        },
    }


CELERY_CONFIG = CeleryConfig

FEATURE_FLAGS = {"ALERT_REPORTS": True}
ALERT_REPORTS_NOTIFICATION_DRY_RUN = True
WEBDRIVER_BASEURL = "http://superset:8088/"  # When using docker compose baseurl should be http://superset_app:8088/
# The base URL for the email report hyperlinks.
WEBDRIVER_BASEURL_USER_FRIENDLY = WEBDRIVER_BASEURL
SQLLAB_CTAS_NO_LIMIT = True

#
# Optionally import superset_config_docker.py (which will have been included on
# the PYTHONPATH) in order to allow for local settings to be overridden
#
try:
    import superset_config_docker

    from superset_config_docker import *  # noqa
    logger.info(
        f"Loaded your Docker configuration at " f"[{superset_config_docker.__file__}]"
    )
except ImportError:
    logger.info("Using default Docker config...")
