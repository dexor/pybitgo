"""

Simple API implementation for BitGo Wallets

A partially signed transaction looks like:
    OP_0 signature OP_0 redeem_script
where the second OP_0 is a placeholder. This appears to be the de facto
standard. However, pycoin does not use this at the moment. See
https://github.com/richardkiss/pycoin/issues/74
Starting with pycoin version 0.53, this can be easily remedied with the
following code:
    ScriptMultisig._dummy_signature = lambda x, y: "\x00"
However, there is a bug in version 0.52 which prevents this from working.
Below is a workaround.

"""
import requests
import json

from . import sjcl
from . errors import BitGoError, NotActiveWallet, NotSpendableWallet, NotEnoughFunds, UnauthorizedError

from Crypto.Random import random

from pycoin.key.BIP32Node import BIP32Node
from pycoin.tx.Spendable import Spendable
from pycoin.tx import tx_utils
from pycoin.tx.pay_to import build_hash160_lookup, build_p2sh_lookup
from pycoin.serialize import h2b, h2b_rev, b2h, h2b_rev
from pycoin.key.validate import is_address_valid
from pycoin import encoding
from pycoin.serialize import b2h, h2b, stream_to_bytes
from pycoin.key import Key
from pycoin.key.BIP32Node import BIP32Node
from pycoin.networks import NETWORK_NAMES
from pycoin.tx.pay_to import ScriptMultisig, build_p2sh_lookup
from pycoin.tx.pay_to import address_for_pay_to_script
from pycoin.tx import Tx
from pycoin.tx.tx_utils import LazySecretExponentDB
from pycoin.tx.tx_utils import create_tx
from pycoin.services import get_tx_db
from pycoin.tx import Spendable

from pycoin.tx.pay_to.ScriptMultisig import ScriptMultisig
from pycoin.tx.exceptions import SolvingError
from pycoin.tx.script import tools
from pycoin.tx.script.check_signature import parse_signature_blob
from pycoin import ecdsa
from pycoin import encoding

ScriptMultisig._dummy_signature = lambda x, y: "\x00"

PRODUCTION_URL = "https://www.bitgo.com/api/v1"
TEST_URL = "https://test.bitgo.com/api/v1"


def solve(self, **kwargs):
    """
    The kwargs required depend upon the script type.
    hash160_lookup:
        dict-like structure that returns a secret exponent for a hash160
    existing_script:
        existing solution to improve upon (optional)
    sign_value:
        the integer value to sign (derived from the transaction hash)
    signature_type:
        usually SIGHASH_ALL (1)
    """
    # we need a hash160 => secret_exponent lookup
    db = kwargs.get("hash160_lookup")
    if db is None:
        raise SolvingError("missing hash160_lookup parameter")

    sign_value = kwargs.get("sign_value")
    signature_type = kwargs.get("signature_type")

    secs_solved = set()
    existing_signatures = []
    existing_script = kwargs.get("existing_script")
    if existing_script:
        pc = 0
        opcode, data, pc = tools.get_opcode(existing_script, pc)
        # ignore the first opcode
        while pc < len(existing_script):
            opcode, data, pc = tools.get_opcode(existing_script, pc)
            sig_pair, actual_signature_type = parse_signature_blob(data)
            for sec_key in self.sec_keys:
                try:
                    public_pair = encoding.sec_to_public_pair(sec_key)
                    sig_pair, signature_type = parse_signature_blob(data)
                    v = ecdsa.verify(ecdsa.generator_secp256k1, public_pair, sign_value, sig_pair)
                    if v:
                        existing_signatures.append(data)
                        secs_solved.add(sec_key)
                        break
                except encoding.EncodingError:
                    # if public_pair is invalid, we just ignore it
                    pass

    for sec_key in self.sec_keys:
        if sec_key in secs_solved:
            continue
        if len(existing_signatures) >= self.n:
            break
        hash160 = encoding.hash160(sec_key)
        result = db.get(hash160)
        if result is None:
            continue
        secret_exponent, public_pair, compressed = result
        binary_signature = self._create_script_signature(secret_exponent, sign_value, signature_type)
        existing_signatures.append(b2h(binary_signature))
    DUMMY_SIGNATURE = "OP_0"
    while len(existing_signatures) < self.n:
        existing_signatures.append(DUMMY_SIGNATURE)

    script = "OP_0 %s" % " ".join(s for s in existing_signatures)
    solution = tools.compile(script)
    return solution

ScriptMultisig.solve = solve

"""
pycoin version 0.52 (and maybe 0.53) do not sign multisig transaction
correctly. See:
https://github.com/richardkiss/pycoin/issues/71
Below is a workaround.
"""


from pycoin.tx.Tx import Tx, SIGHASH_ALL
from pycoin.tx.pay_to import ScriptPayToScript, script_obj_from_script
from pycoin.tx.script import opcodes


byte_to_int = ord if bytes == str else lambda x: x


def sign_tx_in(self, hash160_lookup, tx_in_idx, tx_out_script, hash_type=SIGHASH_ALL, **kwargs):
    tx_in = self.txs_in[tx_in_idx]

    is_p2h = (
        len(tx_out_script) == 23 and
        byte_to_int(tx_out_script[0]) == opcodes.OP_HASH160 and
        byte_to_int(tx_out_script[-1]) == opcodes.OP_EQUAL
    )

    script_to_hash = tx_out_script
    if is_p2h:
        hash160 = ScriptPayToScript.from_script(tx_out_script).hash160
        p2sh_lookup = kwargs.get("p2sh_lookup")
        if p2sh_lookup is None:
            raise ValueError("p2sh_lookup not set")
        if hash160 not in p2sh_lookup:
            raise ValueError("hash160=%s not found in p2sh_lookup" %
                    b2h(hash160))
        script_to_hash = p2sh_lookup[hash160]

    signature_for_hash_type_f = lambda hash_type: self.signature_hash(tx_out_script, tx_in_idx, hash_type)
    if tx_in.verify(tx_out_script, signature_for_hash_type_f, lock_time=kwargs.get('lock_time')):
        return
    sign_value = self.signature_hash(script_to_hash, tx_in_idx, hash_type=hash_type)
    the_script = script_obj_from_script(tx_out_script)
    solution = the_script.solve(
        hash160_lookup=hash160_lookup,
        sign_value=sign_value,
        signature_type=hash_type,
        existing_script=self.txs_in[tx_in_idx].script,
        **kwargs
    )
    tx_in.script = solution

Tx.sign_tx_in = sign_tx_in


class BitGo(object):

    MINIMAL_FEE = 20000
    MINIMAL_SPLIT = 10000000

    def __init__(self, access_token=None, production=False):
        self.access_token = access_token
        self.production = production
        if production:
            self.url = PRODUCTION_URL
        else:
            self.url = TEST_URL

    def _request(self, url, req_type='GET', auth_required=True, data=None, error_handler=None):

        headers = auth_required and {'Authorization': 'Bearer {}'.format(self.access_token)} or {}
        url = self.url + url

        if req_type == 'GET':
            r = requests.get(url, headers=headers)
        elif req_type == 'POST':
            r = requests.post(url, data, headers=headers)
        else:
            raise NotImplemented('Method {} is not supported'.format(req_type))

        if r.status_code == 401:
            raise UnauthorizedError(r.content)

        if error_handler:
            if r.status_code != 200:
                raise error_handler['type'](error_handler['msg'].format(r.content))

        return r.json()

    def ping(self):
        """
        Check BitGo server status
        :return: response dictionary
        """
        return self._request('/ping', auth_required=False)

    def get_access_token(self, username, password, otp=None):
        """
        Get a token for first-party access to the BitGo API.

        First-party access is only intended for users accessing their own BitGo accounts.
        For 3rd party access to the BitGo API on behalf of another user, please see Partner Authentication.

        :param username:
        :param password:
        :param otp: One-Time Password - The 2-factor-authentication token
        :return: access token string
        """
        params = {
          'email': username,
          'password': password,
        }
        if otp:
            params['otp'] = otp

        r = self._request('/user/login', 'POST', auth_required=False, data=params, error_handler={
            'type': Exception,
            'msg': 'failed request to BitGo {}'
        })

        self.access_token = r['access_token']
        return self.access_token

    def send_otp(self):
        """
        Sends the one time password (2nd Factor Auth) token to the user, which can be used for login / unlock
        :return:
        """
        return self._request('/user/sendotp', 'POST')

    def get_wallets(self):
        """
        Get the list of wallets for the user
        :return:
        """
        return self._request('/wallet')

    def get_wallet(self, wallet_id):
        """
        Lookup wallet information, returning the wallet model including balances, permissions etc.
        :param wallet_id:
        :return:
        """
        return self._request('/wallet/{}'.format(wallet_id))

    def get_balance(self, wallet_id, confirmations=0):
        """
        Sum of unspent input transactions for a wallet
        :param wallet_id:
        :param confirmations:
        :return: sum of unspent inputs with specified minimum confirm count
        """

        r = self.get_unspents(wallet_id)
        return sum(map(lambda tx: tx['value'], filter(lambda tx: tx['confirmations'] >= confirmations, r['unspents'])))

    def get_transaction(self, wallet_id, tx_id):
        """
        Get information about a transaction on a wallet
        :param wallet_id: wallet ID
        :param tx_id: transaction ID
        :return: response
        """
        return self._request('/wallet/{}/tx/{}'.format(wallet_id, tx_id))

    def get_keychain(self, x_pub):
        """
        Lookup a keychain by x_pub - Extended Public Key
        :param x_pub: Extended Public Key
        :return: response dictionary
        """
        return self._request('/keychain/{}'.format(x_pub), 'POST')

    def get_unspents(self, wallet_id):
        """
        Gets a list of unspent input transactions for a wallet
        :param wallet_id:
        :return:
        """
        return self._request('/wallet/{}/unspents'.format(wallet_id))

    def unlock(self, otp, duration=60):
        """
        Unlock the current session, which is required for certain other sensitive API calls

        >>> long_lived_server_access_token = ''
        >>> b = BitGo(access_token=long_lived_server_access_token, production=False)
        >>> b.unlock('000000')  # fake OTP
        >>> b.send(...)  # send coins

        :param otp: can be fake if long-lived access token is used
        :param duration: Desired duration of the unlock in seconds (default=600, max=3600)
        :return: server response
        """

        return self._request('/user/unlock', 'POST', data={
            'otp': otp,
            'duration': duration,
        }, error_handler={
            'type': BitGoError,
            'msg': 'unable to unlock\n {}'
        })

    def create_address(self, wallet_id, chain=0):
        """
        Creates a new address for an existing wallet.

        BitGo wallets consist of two independent chains of addresses, designated 0 and 1.
        The 0-chain is typically used for receiving funds,
        while the 1-chain is used internally for creating change when spending from a wallet.

        It is considered best practice to generate a new receiving address for each new incoming transaction,
        in order to help maximize privacy.

        :param wallet_id: the wallet id
        :param chain: 0 for main or 1 change
        :return: address as a string
        """
        r = self._request('/wallet/{}/address/{}'.format(wallet_id, chain), 'POST', error_handler={
            'type': BitGoError,
            'msg': 'unable to create address\n {}'
        })

        return r['address']

    def get_address(self, address):
        """
        Lookup an address with balance info
        :param address:
        :return: dictionary
        """
        return self._request('/address/{}'.format(address))

    def calculate_fee(self, inputs, outputs, num_blocks=2):
        """
        Returns the recommended fee rate per kilobyte to confirm a transaction within a target number of blocks.
        This can be used to construct transactions.

        Note: The estimation algorithm is only accurate in the production environment and
        for a minimum of 2 blocks ahead.

        :param inputs: number of inputs
        :param outputs: number of outputs
        :param num_blocks:
        :return: recommended fee in satoshis
        """

        r = self._request('/tx/fee?numBlocks={}'.format(num_blocks))
        fee_per_kb = r['feePerKb']

        # poor size estimation - FIXME
        k_bytes = 210 * (inputs+outputs) / 1000.0

        return int(fee_per_kb * k_bytes)

    def send(self, wallet_id, pass_phrase, address, amount, message='', fee=None, fan_unspend=10):
        """
        Send coins to address.
        Requires the session to be unlocked before usage. Can use fake OTP if long-lived access token is used

        :param wallet_id: BitGo wallet id
        :param pass_phrase:
        :param address: bitcoin address
        :param amount: btc amount in satoshis
        :param message:
        :param fee:
        :param fan_unspend:
        :return: response
        """

        wallet = self.get_wallet(wallet_id)

        if not wallet['spendingAccount']:
            raise NotSpendableWallet()

        if not wallet['isActive']:
            raise NotActiveWallet()

        if amount < 10000:
            raise Exception('amount is too small')

        if wallet['confirmedBalance'] < amount:
            raise NotEnoughFunds('Not enough funds: balance {} amount {}'.format(wallet['confirmedBalance'], amount))

        change_address = self.create_address(wallet_id, chain=1)
        usable_keychain = False
        spendables = []
        chain_paths = []
        p2sh = []
        payables = [(address, amount)]
        keychain_path = ''
        keychain = {}

        for keychain in wallet['private']['keychains']:
            keychain_path = keychain['path'][1:]
            keychain = self.get_keychain(keychain['xpub'])
            if 'encryptedXprv' not in keychain:
                continue
            usable_keychain = True
            break

        if not usable_keychain:
            raise BitGoError("didn't found a spendable keychain")

        data = json.loads(keychain['encryptedXprv'])
        # add base64 paddings
        for k in ['iv', 'salt', 'ct']:
            data[k] += '=='
        cipher = sjcl.SJCL()
        xprv = cipher.decrypt(data, pass_phrase)

        # get unspent transactions we have in specified wallet and
        # exclude ones without confirmations

        unspents = self.get_unspents(wallet_id)
        unspents = list(filter(lambda u: u['confirmations'] > 0, unspents['unspents'][::-1]))

        total_value = 0
        for d in unspents:
            path = keychain_path + d['chainPath']
            chain_paths.append(path)
            p2sh.append(h2b(d['redeemScript']))
            spendables.append(
                Spendable(
                    d['value'],
                    h2b(d['script']),
                    h2b_rev(d['tx_hash']),
                    d['tx_output_n']
                )
            )

            total_value += d['value']
            if total_value > amount:
                break

        # make many outputs?
        if len(unspents) < 5 and (total_value > (amount + self.MINIMAL_SPLIT)) and fan_unspend > 0:
            fee = self.calculate_fee(len(spendables), fan_unspend)
            value = (total_value - amount - fee) / fan_unspend
            for i in range(fan_unspend):
                payables.append((change_address, value))
        elif total_value > (amount + self.MINIMAL_FEE):
            # add a change address
            if fee is None:
                fee = self.calculate_fee(len(spendables), 2)
            value = total_value - amount - fee
            if value > 10000:  # avoid dust
                payables.append((change_address, value))

        p2sh_lookup = build_p2sh_lookup(p2sh)

        private_key = BIP32Node.from_hwif(xprv.decode('utf-8'))
        spendable_keys = [private_key.subkey_for_path(path) for path in chain_paths]
        hash160_lookup = build_hash160_lookup([key.secret_exponent() for key in spendable_keys])

        tx = create_tx(spendables, payables)

        tx.sign(hash160_lookup=hash160_lookup, p2sh_lookup=p2sh_lookup)

        r = self._request('/tx/send', 'POST', data={
            'tx': tx.as_hex(),
            'message': message
        })

        return r
