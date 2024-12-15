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

import logging
import os
from typing import Optional

from flask import Flask

from superset.initialization import SupersetAppInitializer
from flask import session, redirect
from redis import Redis
import uuid

logger = logging.getLogger(__name__)


def create_app(superset_config_module: Optional[str] = None) -> Flask:
    app = SupersetApp(__name__)

    try:
        # Allow user to override our config completely
        config_module = superset_config_module or os.environ.get(
            "SUPERSET_CONFIG", "superset.config"
        )
        app.config.from_object(config_module)

        app_initializer = app.config.get("APP_INITIALIZER", SupersetAppInitializer)(app)
        app_initializer.init_app()

        redis_url = 'redis://redis:6379/0'  # Adjust this as necessary
        session_manager = SingleSessionManager(app, redis_url)

        return app

    # Make sure that bootstrap errors ALWAYS get logged
    except Exception:
        logger.exception("Failed to create app")
        raise


class SupersetApp(Flask):
    pass

class SingleSessionManager:
    def __init__(self, app=None, redis_url='redis://redis:6379/0'):
        self.redis_client = Redis.from_url(redis_url, decode_responses=True)
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        self.app = app
        app.before_request(self.check_session)

    def check_session(self):
        user_id = session.get('user_id')
        logger.debug(f"Yazan {user_id}");
        if user_id:
            current_session_token = session.get('session_token')
            stored_session_token = self.redis_client.get(f"user_session:{user_id}")
            if stored_session_token and current_session_token != stored_session_token:
                session.clear()