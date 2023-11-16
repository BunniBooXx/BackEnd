from flask_sqlalchemy import SQLAlchemy
from uuid import uuid4
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from random import shuffle

db= SQLAlchemy()



class User(db.Model):
    id = db.Column(db.String(64), primary_key=True)
    username= db.Column(db.String(16), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)

    def __init__(self,username,password):
        self.id= str(uuid4())
        self.username= username
        self.password = generate_password_hash(password)

    def compare_password(self,password):
        return check_password_hash(self.password, password)
    
    def create(self):
        db.session.add(self)
        db.session.commit()


    def delete(self): 
        db.session.delete(self)
        db.session.commit()

    def update(self, **kwargs): 
        for key, value in kwargs.items():
            if key == "password": 
                setattr(self, key, generate_password_hash(value))
            else: 
                setattr(self,key,value)
        db.session.commit()

    
    def to_response(self):
        return {
            "id": self.id,
            "username": self.username
        
        }


