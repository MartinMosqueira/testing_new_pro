from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy 
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    apellido = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)
    tokenuser= None

#REVISAR ESTO
class CreditCard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    tipo = db.Column(db.String(50))
    number = db.Column(db.String(50))
    code = db.Column(db.String(50))
    vencimiento = db.Column(db.String(50))
    maxmonto = db.Column(db.String(50))
    user_id = db.Column(db.Integer)

class CreditCardToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    numbernew = db.Column(db.String(50))
    tokencard = None
    

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        
        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)
    
    return decorated



####REVISAR
"""
def token_required_2(f):
    @wraps(f)
    def decorated_2(*args, **kwargs):
        tokencard = None

        if 'x-card-token' in request.headers:
            tokencard = request.headers['x-card-token']
        
        if not tokencard:
            return jsonify({'message' : 'Token card is missing!'}), 401
        
        try:
            data = jwt.decode(tokencard, app.config['SECRET_KEY'])
            print("sssssssssssssss")
        except:
            return jsonify({'message' : 'Token card is invalid!'}), 401

        return f(current_user, *args, **kwargs)
    
    return decorated_2
"""


""""""""""""""""""""""""""""""""""""""""""""""""""
""""""""""""""""""""""""""""""""""""""""""""""""""
""""""""""""""""""""""""""""""""""""""""""""""""""
""""""""""""""""""""""""""""""""""""""""""""""""""
""""""""""""""""""""""""""""""""""""""""""""""""""
""""""""""""""""""""""""""""""""""""""""""""""""""

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    users = User.query.all()
    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['apellido'] = user.apellido
        user_data['password'] = user.password
        user_data['admin'] = user.admin

        output.append(user_data)

    return jsonify({'users' : output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id = public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})
    
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['apellido'] = user.apellido
    user_data['password'] = user.password
    user_data['admin'] = user.admin
    tokenuser = jwt.encode({'name' : user.name, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=70)}, app.config['SECRET_KEY'])
    tokenuser = tokenuser.decode('UTF-8')
    user.tokenuser = tokenuser
    user_data['tokenuser'] = user.tokenuser

    return jsonify({'user' : user_data})

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], apellido=data['apellido'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New user created!'})


@app.route('/user/<public_id>', methods=['PUT'])
@token_required 
def promote_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id = public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user.admin = True
    db.session.commit()
    return jsonify({'message' : 'The usser has been promoted!'})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id = public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})
    
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message' : 'The usser has been deleted!'})

"""LOGIN"""
""""""""""""""""""""""""""""""""""""""""""""""""""
""""""""""""""""""""""""""""""""""""""""""""""""""
""""""""""""""""""""""""""""""""""""""""""""""""""
""""""""""""""""""""""""""""""""""""""""""""""""""
""""""""""""""""""""""""""""""""""""""""""""""""""
""""""""""""""""""""""""""""""""""""""""""""""""""

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic Realm="Login Required"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic Realm="Login Required"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})
    
    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic Realm="Login Required"'})


"""RUTAS DE TARJETAS"""
""""""""""""""""""""""""""""""""""""""""""""""""""
""""""""""""""""""""""""""""""""""""""""""""""""""
""""""""""""""""""""""""""""""""""""""""""""""""""
""""""""""""""""""""""""""""""""""""""""""""""""""
""""""""""""""""""""""""""""""""""""""""""""""""""
""""""""""""""""""""""""""""""""""""""""""""""""""


@app.route('/ccard',  methods=['GET'])
@token_required

def get_all_ccard(current_user):
    ccards = CreditCard.query.filter_by(user_id=current_user.id).all()

    output = []

    for ccard in ccards:
        ccard_data = {}
        ccard_data['public_id'] = ccard.public_id
        ccard_data['tipo'] = ccard.tipo
        ccard_data['number'] = ccard.number
        ccard_data['code'] = ccard.code
        ccard_data['vencimiento'] = ccard.vencimiento
        ccard_data['maxmonto'] = ccard.maxmonto
        tokencard= jwt.encode({'number' : ccard.number, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=70)}, app.config['SECRET_KEY'])
        tokencard = tokencard.decode('UTF-8')
        ccard.tokencard = tokencard
        ccard_data['tokencard'] = ccard.tokencard
        output.append(ccard_data)
    
    return jsonify({'Tarjetas' : output})

@app.route('/ccard/<ccard_id>',  methods=['GET'])
@token_required


def get_one_ccard(current_user, ccard_id):
    ccard = CreditCard.query.filter_by(public_id=ccard_id, user_id=current_user.id).first()

    if not ccard:
        return jsonify({'message' : 'No credit card found'})
    
    ccard_data = {}
    ccard_data['public_id'] = ccard.public_id
    ccard_data['tipo'] = ccard.tipo
    ccard_data['number'] = ccard.number
    ccard_data['code'] = ccard.code
    ccard_data['vencimiento'] = ccard.vencimiento
    ccard_data['maxmonto'] = ccard.maxmonto
    tokencard= jwt.encode({'number' : ccard.number, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=70)}, app.config['SECRET_KEY'])
    tokencard = tokencard.decode('UTF-8')
    ccard.tokencard = tokencard
    ccard_data['tokencard'] = ccard.tokencard

    return jsonify(ccard_data)

@app.route('/ccard',  methods=['POST'])
@token_required
def create_ccard(current_user):
    data = request.get_json()

    new_ccard = CreditCard(public_id=str(uuid.uuid4()), tipo=data['tipo'], number=data['number'], code=data['code'], vencimiento=data['vencimiento'],maxmonto=data['maxmonto'],user_id=current_user.id)
    db.session.add(new_ccard)
    db.session.commit()

    return jsonify({'message' : 'CreditCard created!'})

@app.route('/ccard/<ccard_id>', methods=['DELETE'])
@token_required
def delete_ccard(current_user, ccard_id):
    ccard = CreditCard.query.filter_by(id=ccard_id, user_id=current_user.id).first()

    if not ccard:
        return jsonify({'message' : 'No credit card found'})
    
    db.session.delete(ccard)
    db.session.commit()
    return jsonify({'message' : 'The credit card has been deleted!'})

@app.route('/ccardtk',  methods=['POST'])
@token_required
def create_ccard_token(current_user):
    data = request.get_json()
    tokens = CreditCard.query.filter(CreditCard.number == data['numbernew']).all()
    
    if tokens:
        token = jwt.encode({'id' : tokens.id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'message' : 'DEVUELVE TOKEN'})
    return jsonify({'message' : 'NO DEVUELVE TOKEN'})


if __name__ == '__main__':
    app.run(debug=True)


