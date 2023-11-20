from flask import Flask 
from config import Config
from flask_cors import CORS


app = Flask(__name__)
app.config.from_object(Config)
CORS(app, origins='http://localhost:3000', supports_credentials=True)
from .models import db, User
db.init_app(app)

from flask_migrate import Migrate

migrate = Migrate(app, db)

from flask_jwt_extended import JWTManager

jwt = JWTManager(app)

@jwt.user_identity_loader
def user_identity_lookup(user):
    return user

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()

from .auth import auth_blueprint

app.register_blueprint(auth_blueprint)


