import base64
import hashlib
import hmac
import json

from flask import Flask, jsonify, request

app = Flask(__name__)


def parse_fb_signed_request(signed_request):
    encoded_sig, payload = signed_request.split('.', 2)
    secret = '50b6b5ba6279f1e5f5e1ca28297b34e8'

    encoded_sig = encoded_sig.encode('ascii')
    payload = payload.encode('ascii')
    encoded_sig += "=" * ((4 - len(encoded_sig) % 4) % 4)
    payload += "=" * ((4 - len(payload) % 4) % 4)

    sig = base64.urlsafe_b64decode(encoded_sig)
    data = json.loads(base64.urlsafe_b64decode(payload))

    # check the signature
    expected_sig = hmac.new(secret, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_sig,sig):
        return None
    else:
        return data


@app.route('/')
def hello_world():
    return 'Hello World!'


# https://developers.facebook.com/docs/apps/delete-data
@app.route('/fb/ddc', methods= ['POST'])
def data_deletion_callback():
    signed_request = request.form.get('signed_request')
    data = parse_fb_signed_request(signed_request)

    # do data deletion stuff here using the data above
    
    # return tracking url and code to FB
    return jsonify({
        'url': 'https://example.com/1234',
        'confirmation_code': '1234'
    })


if __name__ == '__main__':
    app.run()