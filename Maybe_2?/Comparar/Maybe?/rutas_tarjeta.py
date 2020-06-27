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