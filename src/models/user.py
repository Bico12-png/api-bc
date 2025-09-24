from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import hashlib
import secrets

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    hwid = db.Column(db.String(255), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    first_login = db.Column(db.DateTime, nullable=True)
    is_logged_in = db.Column(db.Boolean, default=False)
    hwid_reset_count = db.Column(db.Integer, default=0)
    pause_count = db.Column(db.Integer, default=0)
    is_paused = db.Column(db.Boolean, default=False)
    paused_at = db.Column(db.DateTime, nullable=True)
    paused_time_total = db.Column(db.Integer, default=0)  # em segundos

    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, password):
        """Hash e define a senha do usuário"""
        self.password = hashlib.sha256(password.encode()).hexdigest()

    def check_password(self, password):
        """Verifica se a senha está correta"""
        return self.password == hashlib.sha256(password.encode()).hexdigest()

    def is_expired(self):
        """Verifica se o usuário está expirado"""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    def can_reset_hwid(self):
        """Verifica se o usuário pode resetar o HWID"""
        return self.hwid_reset_count < 2

    def can_pause(self):
        """Verifica se o usuário pode pausar a chave"""
        return self.pause_count < 3

    def reset_hwid(self):
        """Reseta o HWID do usuário"""
        if self.can_reset_hwid():
            self.hwid = None
            self.hwid_reset_count += 1
            return True
        return False

    def pause_key(self):
        """Pausa a chave do usuário"""
        if self.can_pause() and not self.is_paused:
            self.is_paused = True
            self.paused_at = datetime.utcnow()
            self.pause_count += 1
            return True
        return False

    def unpause_key(self):
        """Despausa a chave do usuário"""
        if self.is_paused and self.paused_at:
            pause_duration = (datetime.utcnow() - self.paused_at).total_seconds()
            self.paused_time_total += int(pause_duration)
            self.is_paused = False
            self.paused_at = None
            # Estende o tempo de expiração pelo tempo pausado
            if self.expires_at:
                self.expires_at += timedelta(seconds=pause_duration)
            return True
        return False

    def to_dict(self, include_sensitive=False):
        data = {
            'id': self.id,
            'username': self.username,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'first_login': self.first_login.isoformat() if self.first_login else None,
            'is_logged_in': self.is_logged_in,
            'hwid_reset_count': self.hwid_reset_count,
            'pause_count': self.pause_count,
            'is_paused': self.is_paused,
            'is_expired': self.is_expired()
        }
        
        if include_sensitive:
            data['password'] = self.password
            data['hwid'] = self.hwid
            
        return data

class AdminPermission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    discord_user_id = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(255), nullable=False)
    can_generate_users = db.Column(db.Boolean, default=False)
    granted_by = db.Column(db.String(255), nullable=True)
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'discord_user_id': self.discord_user_id,
            'username': self.username,
            'can_generate_users': self.can_generate_users,
            'granted_by': self.granted_by,
            'granted_at': self.granted_at.isoformat() if self.granted_at else None
        }
