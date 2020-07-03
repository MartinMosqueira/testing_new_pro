from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy 
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from datetime import datetime

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

db = SQLAlchemy(app)
archivo = open("testing.txt", "a")

#SERVICIO WEB DE VENTAS

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    apellido = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)

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

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        archivo = open("log.txt", "a")

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        
        if not token:
            archivo.write("Token is missing! \n")
            return jsonify({'message' : 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            archivo.write("Token is missing! \n")
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)
    
    return decorated

@app.route('/cliente', methods=['GET'])
@token_required
def get_all_users(current_user):
    archivo = open("log.txt", "a")

    if not current_user.admin:
        archivo.write("Cannot perform that function! \n")
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

@app.route('/cliente/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    archivo = open("log.txt", "a")
    if not current_user.admin:
        archivo.write("Cannot perform that function! \n")
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id = public_id).first()

    if not user:
        archivo.write("No user found! \n")
        return jsonify({'message' : 'No user found!'})
    
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})

@app.route('/cliente', methods=['POST'])
@token_required
def create_user(current_user):

    archivo = open("testing.txt", "a")

    #if not current_user.admin:
        #return jsonify({'message' : 'Cannot perform that function!'})

    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], apellido=data['apellido'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    archivo.write("New user created! \n")
    archivo.close()

    return jsonify({'message' : 'New user created!'})


@app.route('/cliente/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    archivo = open("log.txt", "a")

    if not current_user.admin:
        archivo.write("Cannot perform that function! \n")
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id = public_id).first()

    if not user:
        archivo.write("No user found! \n")
        return jsonify({'message' : 'No user found!'})

    user.admin = True
    db.session.commit()
    archivo.write("The usser has been promoted! \n")
    return jsonify({'message' : 'The usser has been promoted!'})

@app.route('/cliente/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):

    archivo = open("testing.txt", "a")

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id = public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})
    
    db.session.delete(user)
    db.session.commit()
    archivo.write("The usser has been deleted! \n")
    return jsonify({'message' : 'The usser has been deleted!'})


@app.route('/token_cliente', methods=['POST'])
@token_required
def get_user(current_user):
    archivo = open("log.txt", "a")
    data = request.get_json()
    new_user = User(name=data['name'], apellido=data['apellido'])
    user = User.query.filter_by(name = new_user.name, apellido=new_user.apellido).first()

    if not user:
        archivo.write("No user found! \n")
        return '0'        
    
    return user.public_id
    
@app.route('/token_ccard', methods=['POST'])
@token_required
def get_card(current_user):
    archivo = open("log.txt", "a")
    data = request.get_json()
    new_card = CreditCard(number=data['number'])
    card = CreditCard.query.filter_by(number = new_card.number).first()

    if not card:
        archivo.write("No card found! \n")
        return '0'        
    
    return str(card.id)


@app.route('/venta', methods=['POST'])
@token_required
def get_new_venta(current_user):
    archivo = open("log.txt", "a")
    data = request.get_json()
    new_user = User(name=data['name'])
    new_card= CreditCard(code=data['code']) #acá deveria ir el token 
    new_monto= data['maxmonto']
    user = User.query.filter_by(name = new_user.name).first()
    venta = CreditCard.query.filter_by(code = new_card.code).first()

    if not user:
        archivo.write("usuario no encontrado \n")
        return jsonify({'userError' : new_user.name, 'error' : 'usuario no encontrado'})
    if not venta: 
        archivo.write("codigo de la tarjeta no encontrado \n")
        return jsonify({'codeError' : new_card.code, 'error' : 'codigo de la tarjeta no encontrado'})
    
    if int(venta.maxmonto) < int(new_monto):
        archivo.write("monto maximo superado \n")
        return jsonify({'montoError' : venta.maxmonto, 'error' : 'monto maximo superado'})

    archivo.write("venta exitosa \n")
    return 'venta exitosa'



@app.route('/ccard',  methods=['GET'])
@token_required
def get_all_ccard(current_user):
    archivo = open("log.txt", "a")
    ccards = CreditCard.query.filter_by(user_id=current_user.id).all()

    output = []

    for ccard in ccards:
        ccard_data = {}
        ccard_data['id'] = ccard.id
        ccard_data['tipo'] = ccard.tipo
        ccard_data['number'] = ccard.number
        ccard_data['code'] = ccard.code
        ccard_data['vencimiento'] = ccard.vencimiento
        ccard_data['maxmonto'] = ccard.maxmonto
        output.append(ccard_data)
    
    return jsonify({'Tarjetas' : output})

@app.route('/ccard/<ccard_id>',  methods=['GET'])
@token_required
def get_one_ccard(current_user, ccard_id):
    archivo = open("log.txt", "a")
    ccard = CreditCard.query.filter_by(id=ccard_id, user_id=current_user.id).first()

    if not ccard:
        archivo.write("No credit card found \n")
        return jsonify({'message' : 'No credit card found'})
    
    ccard_data = {}
    ccard_data['id'] = ccard.id
    ccard_data['tipo'] = ccard.tipo
    ccard_data['number'] = ccard.number
    ccard_data['code'] = ccard.code
    ccard_data['vencimiento'] = ccard.vencimiento
    ccard_data['maxmonto'] = ccard.maxmonto

    return jsonify(ccard_data)

@app.route('/ccard',  methods=['POST'])
@token_required
def create_ccard(current_user):
    archivo = open("log.txt", "a")
    data = request.get_json()

    new_ccard = CreditCard(public_id=str(uuid.uuid4()), tipo=data['tipo'], number=data['number'], code=data['code'], vencimiento=data['vencimiento'],maxmonto=data['maxmonto'],user_id=current_user.id)
    db.session.add(new_ccard)
    db.session.commit()

    archivo.write("CreditCard created! \n")
    return jsonify({'message' : 'CreditCard created!'})

@app.route('/ccard/<ccard_id>', methods=['DELETE'])
@token_required
def delete_ccard(current_user, ccard_id):
    archivo = open("log.txt", "a")
    ccard = CreditCard.query.filter_by(id=ccard_id, user_id=current_user.id).first()

    if not ccard:
        archivo.write("No credit card found \n")
        return jsonify({'message' : 'No credit card found'})
    
    db.session.delete(ccard)
    db.session.commit()
    archivo.write("The credit card has been deleted! \n")
    return jsonify({'message' : 'The credit card has been deleted!'})

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

#SERVICIO WEB DE TARJETAS

@app.route('/tarjeta',  methods=['POST'])
@token_required
def create_ccard_token(current_user):
    archivo = open("log.txt", "a")
    data = request.get_json()
    new_card = CreditCard(id=data['id'])  #acá deveria ir el token 
    card = CreditCard.query.filter_by(id=new_card.id, user_id=current_user.id).first()
    now = datetime.now()
    
    if not card:
        return jsonify({ "codError": str(new_card.id),"error": "No existe la tarjeta" }), 403       

    if int(card.vencimiento) < int(now.year) :
        return jsonify({ "codError": str(new_card.id),"error": "Tarjeta expirada" }), 403

    return jsonify({ "válido": "se puede continuar el proceso de venta" }), 201
    


    #if not token:
    #    return 'no exite este token'
    
    #return 'existe este token'


    # data = request.get_json()
    # tokens = CreditCard.query.filter(CreditCard.number == data['numbernew']).all()
    
    # if tokens:
    #     token = jwt.encode({'id' : tokens.id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
    #     return jsonify({'message' : 'DEVUELVE TOKEN'}) 
    # return jsonify({'message' : 'NO DEVUELVE TOKEN'})

@app.route('/monto',  methods=['POST'])
@token_required
def new_monto(current_user):
    archivo = open("log.txt", "a")
    data = request.get_json()
    new_card = CreditCard(id=data['id'])  #acá deveria ir el token 
    card = CreditCard.query.filter_by(id=new_card.id, user_id=current_user.id).first()
    new_monto= data['maxmonto']

    if not card:
        return jsonify({ "codError": str(new_card.id),"error": "No existe la tarjeta" }), 403       


    if int(card.maxmonto) < int(new_monto):
        return jsonify({ "codError": str(new_card.id),"error": "Monto máximo de venta superado" }), 403

    return jsonify({ "válido": "se puede continuar el proceso de venta" }), 201   


#Token Rodri que dentro de todo devuelve un token pero no se si esta bien.
"""
@app.route('/ccardtk/<number>',  methods=['POST'])
@token_required
def create_ccard_token(current_user, number):
    data = request.get_json()
    if (CreditCard.query.filter(CreditCard.number == data['numbernew']).all()):
        
        ccard = CreditCard.query.filter_by(number=number, user_id=current_user.id).first()
        tokencard = jwt.encode({'public_id' : ccard.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=70)}, app.config['SECRET_KEY'])
        tkn = jwt.decode(tokencard, app.config['SECRET_KEY'])
        return jsonify({'tokencard' : tokencard.decode('UTF-8'), 'tokendecode' : tkn})
    return jsonify({'message' : 'Tarjeta no almacenada'})
@app.route('/usertk/<name>',  methods=['POST'])
@token_required
def user_found(current_user, name):
    data = request.get_json()
    if (User.query.filter(User.name == data['namenew']).all()):
        id_user = User.query.filter(User.name == data['namenew']).first()
        user_data = {}
        user_data['public_id'] = id_user.public_id
        
        return jsonify({'message' : user_data})
"""


if __name__ == '__main__':
    app.run(debug=True)
