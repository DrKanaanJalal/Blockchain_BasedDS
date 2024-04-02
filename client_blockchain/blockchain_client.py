from flask import Flask, jsonify, request, render_template
import Crypto
import Crypto.Random
from Crypto.PublicKey import RSA
import binascii
from collections import OrderedDict
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA


class Transaction:

    def __init__(self, sender_public_key, sender_private_key, recipient_public_key, data):
        self.sender_public_key = sender_public_key
        self.sender_private_key = sender_private_key
        self.recipient_public_key = recipient_public_key
        self.data = data

    # this function to convert transaction object to dictionary
    def to_dict(self):
        return OrderedDict({'sender_public_key': self.sender_public_key,
                            'recipient_public_key': self.recipient_public_key,
                            'data': self.data})

    # this function to sign the transactions
    def sign_transaction(self):
        """
        Sign transaction with private key
        """
        private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(self.to_dict()).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')


# instantiate the Node object
app = Flask(__name__)


# rendering template for render to the required web pages (End points)
# this end_point to home page render
@app.route('/')
def index():
    return render_template('./index.html')


# to make transactions
@app.route('/make/transaction')
def make_transaction():
    return render_template('./make_transaction.html')


# to show transactions
@app.route('/view/transactions')
def view_transaction():
    return render_template('./view_transactions.html')


# this end_point to generate public and private keys by using RSA algorithm
@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()
    response = {
        'private_key': binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
        'public_key': binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')
    }

    return jsonify(response), 200


# this end_point for generation the transactions
@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    sender_public_key = request.form['sender_public_key']
    sender_private_key = request.form['sender_private_key']
    recipient_public_key = request.form['recipient_public_key']
    data = request.form['data']

    transaction = Transaction(sender_public_key, sender_private_key, recipient_public_key, data)

    response = {'transaction': transaction.to_dict(),
                'signature': transaction.sign_transaction()
                }

    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port
    app.run(host='127.0.0.1', port=port)
