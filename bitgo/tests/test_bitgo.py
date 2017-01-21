from bitgo import BitGo
import json

secrets = json.load(open('./bitgo/tests/secrets.json'))


b = BitGo(access_token=secrets['access_token'], production=False)
shared = {}


def test_ping():
    assert b.ping()['status'] == 'service is ok!'


def test_wallets():
    wallets = b.get_wallets()

    assert wallets['count'] > 0

    first_wallet_id = wallets['wallets'][0]['id']
    wallet = b.get_wallet(first_wallet_id)
    shared['wallet_id'] = first_wallet_id

    assert wallet['received'] > 0


def test_balance():
    assert b.get_balance(shared['wallet_id']) > 0


def test_send():
    b.unlock('000000')
    b.send(
        secrets['wallet_id'],
        secrets['pass_phrase'],
        secrets['address'],
        10001,
        'test transaction'
    )
