#!/usr/bin/env python3

from flask import Flask, request, jsonify, make_response, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps


app = Flask(__name__)

#initiate the DB instance
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
    email = db.Column(db.String(255), unique=True)


#check the request has the valid Token
def token_required(f):
    """
       Get user details based on the given token and verifying the token
       :param current_user  : logged in user
       :return: returns user token key and sets current token
       :rtype: json
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            # log something like--trying to access with invalid Token
            return jsonify({'message': 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    """
       Get all the users of the Admin
       :param current_user  : logged in user
       :return: set of user details
       :rtype: json
    """

    if not current_user.admin:
        #log Cannot perform this operation on current_user
        return jsonify({'message', 'Cannot perform this operation'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users': output})


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    """
       Get all users
       :param current_user  : logged in user
       :return: user detail
       :rtype: json
    """

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user': user_data})


@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):

    """
       create new user (create)
       :param current_user  : logged in user
       :return: message
       :rtype: json
    """

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)

    db.session.add(new_user)
    db.session.commit()
    #log created new username called  new_user.name
    return jsonify({'message': 'New user created'})


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):

    """
       promotes user to admin (update)
       :param current_user  : logged in user
       :return: message
       :rtype: json
    """

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found'})

    user.admin = True
    db.session.commit()
    #log current_user.name Promoted to Admin
    return jsonify({'message': 'User is promoted to Admin'})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):

    """
       delete user (delete)
       :param current_user  : logged in user
       :param public_id : public_id of the user
       :return: message
       :rtype: json
    """

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found'})

    db.session.delete(user)
    db.session.commit()
    #log current_user -User deleted the user named user
    return jsonify({'message': 'User deleted from the database'})


@app.route('/')
def hello():
    return redirect(url_for('login'))

@app.route('/login')
def login():

    """
       login the user
       :return: config the app and set the messages and also returns public_key
       :rtype: json
    """

    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=1)},
            app.config['SECRET_KEY'])
        #log user logged in Successfully user.name
        return jsonify({'token': token.decode('UTF-8'),'public_id': user.public_id})
    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

if __name__ == '__main__':
    app.run(debug=True)
