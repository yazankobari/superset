"""Module for managing user sessions in Superset using Redis."""
from typing import Optional
from datetime import datetime, timedelta
from flask import request, current_app
import hashlib
import json
import redis

class SessionManager:
    """Manages user sessions to prevent concurrent logins using Redis."""
    
    @classmethod
    def _get_redis_client(cls) -> redis.Redis:
        """Get Redis client from app config."""
        return current_app.config['SESSION_REDIS']
    
    @classmethod
    def generate_session_id(cls) -> str:
        """Generate a unique session ID based on user agent and timestamp."""
        user_agent = request.headers.get('User-Agent', '')
        timestamp = datetime.utcnow().isoformat()
        session_data = f"{user_agent}{timestamp}"
        return hashlib.sha256(session_data.encode()).hexdigest()
    
    @classmethod
    def _get_user_session_key(cls, user_id: int) -> str:
        """Generate Redis key for user session."""
        return f"{current_app.config.get('SESSION_KEY_PREFIX', 'superset_session:')}user:{user_id}"
    
    @classmethod
    def register_session(cls, user_id: int) -> str:
        """Register a new session for a user in Redis."""
        session_id = cls.generate_session_id()
        redis_client = cls._get_redis_client()
        session_key = cls._get_user_session_key(user_id)
        
        # Store session data with user agent info for auditing
        session_data = {
            'session_id': session_id,
            'user_agent': request.headers.get('User-Agent', ''),
            'ip_address': request.remote_addr,
            'login_time': datetime.utcnow().isoformat()
        }
        
        # Store session with expiration
        expiration = int(current_app.config.get('PERMANENT_SESSION_LIFETIME', timedelta(hours=1)).total_seconds())
        redis_client.setex(
            session_key,
            expiration,
            json.dumps(session_data)
        )
        
        return session_id
    
    @classmethod
    def validate_session(cls, user_id: int, session_id: str) -> bool:
        """Validate if the current session is active and valid in Redis."""
        redis_client = cls._get_redis_client()
        session_key = cls._get_user_session_key(user_id)
        
        session_data = redis_client.get(session_key)
        if not session_data:
            return False
            
        try:
            stored_session = json.loads(session_data)
            return stored_session.get('session_id') == session_id
        except json.JSONDecodeError:
            return False
    
    @classmethod
    def clear_session(cls, user_id: int):
        """Clear user session from Redis."""
        redis_client = cls._get_redis_client()
        session_key = cls._get_user_session_key(user_id)
        redis_client.delete(session_key)
    
    @classmethod
    def get_active_session(cls, user_id: int) -> Optional[dict]:
        """Get the active session data for a user if it exists."""
        redis_client = cls._get_redis_client()
        session_key = cls._get_user_session_key(user_id)
        
        session_data = redis_client.get(session_key)
        if session_data:
            try:
                return json.loads(session_data)
            except json.JSONDecodeError:
                return None
        return None
    
    @classmethod
    def get_session_info(cls, user_id: int) -> Optional[dict]:
        """Get detailed session information for user."""
        session_data = cls.get_active_session(user_id)
        if session_data:
            return {
                'login_time': session_data.get('login_time'),
                'ip_address': session_data.get('ip_address'),
                'user_agent': session_data.get('user_agent')
            }
        return None
