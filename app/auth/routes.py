from . import auth_blueprint as auth
from flask_jwt_extended import create_access_token
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask import request, make_response, jsonify 
import base64
from flask_cors import cross_origin
import requests
from ..models import User, db
from datetime import timedelta 
from flask_login import login_required


@auth.route('/tts', methods=['GET'])
@cross_origin(supports_credentials=True)

def tts():
    api_key = 'AIzaSyBVN5qq-8-eXcPjn7_nqWYdZPrpjDHCric'
    url = f'https://texttospeech.googleapis.com/v1/text:synthesize?key=AIzaSyBVN5qq-8-eXcPjn7_nqWYdZPrpjDHCric'
    text = request.args.get('text')
    payload = {
        'input': {'text': text},
        'voice': {'language_code': 'en-US', 'name': 'en-US-Wavenet-D'},
        'audioConfig': {'audioEncoding': 'MP3'}
    }
    
    response = requests.post(url, json=payload)
    print(response.text)
    if response.status_code == 200:
        audio_content = response.json().get('audioContent')
        with open("app/static/yona.mp3", "wb") as f: 
            f.write(base64.b64decode(audio_content.encode()))
            response = make_response(base64.b64decode(audio_content.encode()))
            response.headers.set("Content-Type", "audio/mpeg")
            return response
        
        return jsonify({'audioContent': audio_content})

    return jsonify({'error': 'Text-to-Speech conversion failed'}), 500




@auth.route('/api/start_new_game', methods=['GET'])
@login_required
def start_new_game():
    import requests

    response = requests.get('http://127.0.0.1:8042/index.html')
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
        return response, 400

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
    


    auth_token = create_access_token(identity=user, expires_delta=timedelta(days=1))

    response = make_response({"message": "successfully logged in", "auth_token" : auth_token})
     
    response.headers["Authorization"] = f"Bearer {auth_token}"
    return response , 200
    



@auth.put('/update_user/<user_id>')
@jwt_required()  
def update_user(user_id):
    current_user_id = get_jwt_identity()

   
    if current_user_id != user_id:
        response = {"message": "Unauthorized: You can only update your own profile"}
        return response, 401

    body = request.json

    username = body.get("username")
    password = body.get("password")

  
    user = User.query.get(user_id)

    if not user:
        response = {"message": "User not found"}
        return response, 404

   
    if username:
        user.username = username
    if password:
        user.password = password

    db.session.commit()

    response = {"message": "User updated", "data": user.to_response()}
    return response, 200


@auth.delete('/delete_user')
@jwt_required()
def delete_user():
    

    current_user_id = get_jwt_identity()
    user = User.query.filter_by(id = current_user_id).one_or_404()

    if not user:
        response = {"message": "User not found"}
        return response, 404

  
    db.session.delete(user)
    db.session.commit()

    response = {"message": "User deleted"}
    return response, 200


@auth.route('/get_user_data', methods=['GET'])
@jwt_required()
#@cross_origin()
def get_user_data():
    try:
        
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        user_data = {
            "id": current_user_id,
            "username": user.username,
        
        }

        return jsonify(user_data), 200

    except Exception as e:
        print(f"Error getting user data: {str(e)}")
        response = {"message": "Error getting user data"}
        return jsonify(response), 500