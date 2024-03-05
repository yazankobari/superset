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
from flask import flash, redirect, request
from redis import Redis
from flask_appbuilder.security.views import AuthDBView
from flask_appbuilder import expose
from flask import flash, redirect, request, url_for
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


from celery.schedules import crontab
from flask_caching.backends.filesystemcache import FileSystemCache



logger = logging.getLogger()

APP_ICON = "/static/assets/images/DN_Logo.svg"

# Enable server-side sessions
SESSION_TYPE = "redis"
SESSION_REDIS = Redis(host='redis', port=6379, db=0, decode_responses=True)  # Use the Docker Compose service name as hostname
SESSION_USE_SIGNER = True
SESSION_PERMANENT = False
SESSION_KEY_PREFIX = "superset_session:"
# Ensure the SECRET_KEY is set
SECRET_KEY = 'yLrUFVOicvzFondOKVyRpX+Z+xr3QtttWdzCtF05ONcpvor92zm5i6gW'  # Replace with your own secret key

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
    imports = ("superset.sql_lab",)
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
WEBDRIVER_BASEURL = "http://superset:8088/"
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


    
redis_conn = Redis(host='redis', port=6379, db=0, decode_responses=True)
from flask import session

class CustomAuthDBView(AuthDBView):
    @expose('/login/', methods=['GET', 'POST'])
    def login(self):
        # This block is only executed for POST requests
        if request.method == 'POST':
            username = request.form.get('username')
            user_key = f"logged_in_user:{username}"
            if redis_conn.exists(user_key):
                flash('You are already logged in from another browser.', 'warning')
                # Redirect to the index page or another appropriate page
                return redirect(url_for('SupersetIndexView.index'))
            else:
                # Set a flag in Redis that the user is logged in
                redis_conn.set(user_key, "true", ex=3600)  # Expiration time of 1 hour
                # Proceed with the normal login process
                session['username'] = username
                return super().login()
        else:
            # If not authenticated, proceed with the normal login process
            return super().login()
    
    @expose('/logout/', methods=['GET', 'POST'])
    def logout(self):
        username = session.get('username')
        if username:
            user_key = f"logged_in_user:{username}"
            # Delete the user's session key from Redis
            redis_conn.delete(user_key)
            flash('You have been successfully logged out.', 'info')
            # Clear the username from the session
            session.pop('username', None)
        else:
            flash('No active session found.', 'info')
        # Proceed with the standard logout process
        return super().logout()
   
class CustomSecurityManager(SupersetSecurityManager):
    authdbview = CustomAuthDBView

CUSTOM_SECURITY_MANAGER = CustomSecurityManager