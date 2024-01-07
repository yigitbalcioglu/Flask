from flask_login import UserMixin
from .extensions import db
from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime



class User(db.Model, UserMixin):
    __tablename__="users"
    id=db.Column(db.String(),primary_key=True)
    username = db.Column(db.String(length=30),nullable=False, unique=True)
    email_address = db.Column(db.String(length=50), nullable=False, unique=True)
    password_hash = db.Column(db.String(length=256), nullable=False)
    events = db.relationship('Event', backref='owned_user', lazy=True)
    friends = db.Column(db.String(), nullable=True)

class Event(db.Model):
    __tablename__="events"
    id = db.Column(db.String(), primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date = db.Column(db.Date, nullable=False)
    start_time=db.Column(db.DateTime, nullable=False)
    end_time=db.Column(db.DateTime, nullable=False)
    owner = db.Column(db.String(), db.ForeignKey('users.id'),nullable=True)
    category=db.Column(db.String(),nullable=False)
    access_level = db.Column(db.String(), nullable=True)
    #günlük aylık veya yıllık şekilde 3 çeşit tekrarlama tipi var
    #recurrence_type=db.Columm(db.Stri)
    #recurrence_start_date=
    #recurrence_end_date=
    def duration_calculation(self):
        sts=self.start_time
        ste=self.end_time
        t1=datetime.strptime(sts, "%H.%M.%S")
        t2=datetime.strptime(ste, "%H.%M.%S")
        delta= t2-t1
        self.duration=delta.total_seconds()
    
class Session(db.Model):
    __tablename__="sessions"
    session_id=db.Column(db.String(),primary_key=True)
    user_id = db.Column(db.String(), db.ForeignKey('users.id'),nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)

class FilePath(db.Model):
    __tablename__ = "file_paths"
    id = db.Column(db.String(), primary_key=True)
    path = db.Column(db.String(), nullable=False, unique=True)
    event_id = db.Column(db.String(), db.ForeignKey('events.id'), nullable=False)

@property
def is_active(self):
    return datetime.utcnow() < self.expires_at
