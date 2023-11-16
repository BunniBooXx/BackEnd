from . import auth_blueprint as auth
from flask_jwt_extended import create_access_token
from flask import request, make_response, jsonify
from ..models import User
from datetime import timedelta 
from flask_login import login_required


@auth.route('/tts', methods=['POST'])
def tts():
    text = request.json.get('text')
    api_key = 'AIzaSyBVN5qq-8-eXcPjn7_nqWYdZPrpjDHCric'
    url = f'https://texttospeech.googleapis.com/v1/text:synthesize?key=AIzaSyBVN5qq-8-eXcPjn7_nqWYdZPrpjDHCric'

    payload = {
        'input': {'text': text},
        'voice': {'language_code': 'en-US', 'name': 'en-US-Wavenet-D'},
        'audioConfig': {'audioEncoding': 'LINEAR16'}
    }
    
    response = request.post(url, json=payload)

    if response.status_code == 200:
        audio_content = response.json().get('audioContent')
        return jsonify({'audioContent': audio_content})

    return jsonify({'error': 'Text-to-Speech conversion failed'}), 500


@login_required
@auth.route('/api/start_new_game', methods=['GET'])
def start_new_game():
    import requests

    response = requests.get('http://localhost:5000/api/start_new_game')
    print(response.json())

    return jsonify({
        'status': 'success', 
        'message': 'New game started!'
        
    }), 200

@auth.post('/register')
def handle_register(): 
    body = request.json

    if body is None: 
        response = {
            "message": "username and password are required to register"

        }
        return response, 400
    username = body.get("username")
    if username is None: 
        response = {
            "message": "username is required"
        }
        return response , 400
    

    existing_user = User.query.filter_by(username=username).one_or_none()
    if existing_user is not None: 
        response={
            "message": "username already in use"
        }
        return response, 400
    
    password = body.get("password")
    if password is None: 
        response = {
            "message": "password is required"
        }
        return response , 400
    
    user = User(username=username, password=password)
    user.create()

    response={
        "message": "user registered",
        "data": user.to_response()

    } 

    return response, 201

@auth.post("/login")
def handle_login(): 
    body = request.json

    if body is None: 
        response = {
            "message": "username and password are required to login"
        }
        return response,400
    
    username=body.get("username")
    if username is None:
        response = {
            "message": "username is required"
        }
        return response, 400
    
    password = body.get("password")
    if password is None: 
        response = {
            "message": "password is required"
        }

    user = User.query.filter_by(username=username).one_or_none()
    if user is None: 
        response = {
            "message": "please create an account before trying to login"
        }
        return response, 400
    
    ok = user.compare_password(password)
    if not ok:
        response={
            "message": "invalid login"

        }
        return response, 401
    


    auth_token = create_access_token(identity=user.id, expires_delta=timedelta(days=1))

    response = make_response({"message": "successfully logged in"})
    response.headers["Authorization"] = f"Bearer {auth_token}"
    return response , 200
    