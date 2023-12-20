from flask import Flask,jsonify,request
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import jwt
from functools import wraps
from werkzeug.security import generate_password_hash,check_password_hash
import datetime


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:root@localhost:5432/FlaskApi'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] ='ThisIsSecretKey'

db = SQLAlchemy(app)
ma = Marshmallow(app)

class User(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    user_id = db.Column(db.Integer,unique=True)
    username = db.Column(db.String(50),unique=True)
    password = db.Column(db.String(250))
    admin = db.Column(db.Boolean,default=False)

    def __init__(self,user_id,username,password,admin) -> None:
        self.user_id = user_id
        self.username = username
        self.password = password

class UserSchema(ma.Schema):
    class Meta:
        fields = ('user_id','username','password','admin')

user_schema = UserSchema()
users_schema = UserSchema(many=True)

@app.route('/database')
def create_db():
    with app.app_context():
        db.create_all()
    return jsonify({'msg':'database created'})

def token_required(f):
    @wraps(f)
    def decorater(*args,**kargs):
        token = request.headers['access-token']

        if not token:
            return jsonify({'msg':'token not found'}),401
        
        user_data = jwt.decode(token,app.config['SECRET_KEY'],algorithms=['HS256'])
        try :
            user = User.query.filter_by(user_id = user_data['user_id']).first()
        except:
            return jsonify({'msg':'token is invalid'}),401
        return f(user,*args,**kargs)
    return decorater

@app.route('/all')
@token_required
def all_user(current_user):
    if not current_user.admin:
        return jsonify({'msg':"you are not authorized"}),401
    users = User.query.all()
    data = users_schema.dump(users)
    return jsonify(data),201

@app.route('/user/<int:userid>')
@token_required
def get_user(current_user,userid):
    user = User.query.filter_by(user_id = userid).first()
    data = user_schema.dump(user)
    if current_user.admin  or user.user_id == current_user.user_id:
        return jsonify(data),201
    return jsonify({'msg':'Your not authorized'}),401

@app.route('/sign-up',methods=['POST'])
def sing_up():
    data = request.get_json()
    password = generate_password_hash(data['password'])
    user = User(data['user_id'],data['username'],password,False)
    db.session.add(user)
    db.session.commit()
    data = user_schema.dump(user)
    return jsonify(data),201

@app.route('/admin/<int:user_id>',methods = ['GET'])
@token_required
def make_admin(current_user,user_id):
    if current_user.admin:
        user = User.query.filter_by(user_id=user_id).first()
        if not user:
            return jsonify({'msg':'user is not found'})
        user.admin = True
        db.session.commit()
        return jsonify({'msg':'you are now admin'})
    return jsonify({'msg':"you don't have a access"})

@app.route('/delete-user/<int:user_id>',methods=['DELETE'])
@token_required
def delete_user(current_user,user_id):
    user = User.query.filter_by(user_id=user_id).first()
    if current_user.admin or current_user.user_id== user.user_id :
        db.session.delete(user)
        db.session.commit()
        return jsonify({'msg':'user is deleted'})
    return jsonify({'msg':"you don't Have permission"})

@app.route('/login',methods=['POST'])
def user_login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password :
        return jsonify({'msg':'please provide proper details'})
    user = User.query.filter_by(username= auth.username).first()

    if not user:
        return jsonify({'msg':'user not found'})
    if check_password_hash(user.password,auth.password):
        token = jwt.encode(
            {
                'user_id': user.user_id,
                'exp': datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(minutes=60),
            },
            app.config['SECRET_KEY'],
        )
        return jsonify({'token':token})
    return jsonify({'msg':'could not verify'})


if __name__ == '__main__':
    app.run(debug=True)