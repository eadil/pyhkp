"""This module provides a class to interact with OpenPGP keyservers using HKP."""

from urllib.request import urlopen
from urllib.parse import urlencode
from urllib.error import HTTPError
from datetime import datetime


class HKP(object):
    """
    Class to interact with keyservers using the OpenPGP HTTP Keyserver Protocol
    (HKP), as defined in
    `RFC draft-shaw-openpgp-hkp-00 <http://tools.ietf.org/html/draft-shaw-openpgp-pyhkp-00#section-3.2.1>`_.
    """
    def __init__(self, host, port=11371):
        """
        :param host: http://-URL to keyserver, without ending backslash
        :type host: str
        :param port: port, default ist 11371
        :type port: int
        """
        self.host = host
        self.port = port
        self.lookup_path = '/pks/lookup'
        self.submit_path = '/pks/add'

    @staticmethod
    def lookup_pubkey_algorithm(alg):
        """
        Lookup public key algorithm string for given algorithm id.

        :param alg: algorithm id as defined in :rfc:`4880#section-9.1`
        :type alg: int
        :returns: algorithm name
        :rtype: str
        """
        public_key_algorithms = {
            1:  'RSA Encrypt or Sign',
            2:  'RSA Encrypt-Only',
            3:  'RSA Sign-Only',
            16: 'ElGamal Encrypt-Only',
            17: 'DSA',
            18: 'Elliptic Curve',
            19: 'ECDSA',
            20: 'Formerly ElGamal Encrypt or Sign',
            21: 'Diffie-Hellman'
        }
        if 100 <= alg <= 110:
            return 'Private/Experimental algorithm'
        return public_key_algorithms.get(alg, 'Unknown')

    def _parse_index(self, mr_keyserver_answer):
        """
        Will parse the machine readable index retrieved with the 'index' operation and returns a list of dicts,
        see :func:`search`.

        :param mr_keyserver_answer: machine readable answer from keyserver
        :type mr_keyserver_answer: str
        :returns: parsed keys
        :rtype: dict
        """
        def convert_date_if_set(date):
            """
            Converts a date string to utc datetime if not None.

            :param date: date string
            :type date: str
            :returns: date
            :rtype: datetime
            """
            if date != '':
                return datetime.utcfromtimestamp(int(date))

        keys = []

        mr_keyserver_answer = mr_keyserver_answer.replace('\n', '').replace('\r', '')

        # first split by pub: to get the keys and their uids
        keys_split = mr_keyserver_answer.split('pub')

        for key_str in keys_split:
            # skip info:<version>:<count> line, we don't need it
            if key_str.startswith('info'):
                continue

            # will hold the return values
            key_dict = {
                'primary_key': {},
                'user_ids':  []
            }

            key_str = key_str.split('uid:')
            for value in key_str:
                value = value.split(':')
                if len(value) > 4:
                    #pub:<keyid>:<algo>:<keylen>:<creationdate>:
                    # <expirationdate>:<flags>
                    key_dict['primary_key'] = {
                        'key_id':       value[1],
                        'algorithm_id': int(value[2]),
                        'algorithm':    self.lookup_pubkey_algorithm(
                            int(value[2])),
                        'key_length':   int(value[3]),
                        'creation':     convert_date_if_set(value[4]),
                        'expiration':   convert_date_if_set(value[5]),
                        'revoked':      'r' in value[6],
                        'disabled':     'd' in value[6],
                        'expired':      'e' in value[6]
                    }
                else:
                    # uid:<escaped uid string>:<creationdate>:
                    # <expirationdate>:<flags>
                    # uid: has been stripped
                    uid = {
                        'user_id':    value[0],
                        'creation':   convert_date_if_set(value[1]),
                        'expiration': convert_date_if_set(value[2]),
                        'revoked':    'r' in value[3],
                        'disabled':   'd' in value[3],
                        'expired':    'e' in value[3]
                    }
                    key_dict['user_ids'].append(uid)
            keys.append(key_dict)
        return keys

    @staticmethod
    def _parse_options(options):
        """
        Check if each option is either 'nm' (no modification) or beginning
        with 'x-'.

        :param options: options to be set
        :type options: tuple(str)
        :returns: comma separated list of options
        :rtype: str
        """
        ops = set()
        ops.add('mr')

        if options is not None and options[0] is not None:
            for option in options:
                if option == 'nm' or option.startswith('x-'):
                    ops.add(option)

        return ','.join(op for op in ops)

    def retrieve(self, key_id, options=(None,)):
        """
        Retrieve a public key from the keyserver by a given key id.
        Retrieval by query is not supported, since queries may be ambiguous.

        :param key_id: key id to get key from
        :type key_id: str
        :param options: nonstandard option starting with 'x-' (see \
        `RFC draft <http://tools.ietf.org/html/draft-shaw-openpgp-hkp-00#section-3.2.1>`_)
        :type options: tuple(str)
        :returns: pgp public key, or None if not available/error
        :rtype: str or None
        """
        if key_id is None or len(key_id) not in (8, 10, 16, 20, 32, 34, 40,
                                                 42):
            # Key id length is limited to:
            # V3 key ids: 32 digits (+ 2 including 0x)
            # V4 key ids: either 8, 16, 32, or 40 digits (+ 2 including 0x)
            raise ValueError('no or invalid key id')

        if not key_id.startswith('0x'):
            key_id = '{0}{1}'.format('0x', key_id)

        params = {
            'search': key_id,
            'op': 'get',
            'options': self._parse_options(options)
        }

        url = '{0}:{1}{2}?{3}'.format(self.host, self.port,
                                      self.lookup_path, urlencode(params))
        try:
            response = urlopen(url)
            return response.read().decode().rstrip()
        except HTTPError:
            return None

    def search(self, query, operation='index', exact='off', options=(None,),
               other_variables=(None,)):
        """
        Search on a keyserver with given query.
        Query can be a key id or a string.

        Structure of returned dict::

          [{
            primary_key: {
                'key_id': str,
                'algorithm_id': int,
                'algorithm': str,
                'key_length': int,
                'creation': datetime or None,
                'expiration': datetime or None,
                'revoked': bool,
                'expired': bool,
                'disabled': bool},
            user_ids: [
                {
                    'user_id': str,
                    'creation': datetime or None,
                    'expiration': datetime or None,
                    'revoked': bool,
                    'disabled': bool,
                    'expired': bool
                },]
          },]

        :param query: search string
        :type query: str
        :param operation: operation is usually index, but can be nonstandard, starting with 'x-'
        :type operation: str
        :param exact: if on, the keyserver will search for an exact match for the contents of the 'query' variable
        :type exact: str
        :param options: non-standard options starting with 'x-'
        :type options: tuple(str)
        :param other_variables: other instructions, must start with 'x-'
        :type other_variables: tuple of tuple of strings
        :returns: dict containing the values described above
        :rtype: dict
        """
        if operation != 'index' and not operation.startswith('x-'):
            raise ValueError('operation not allowed')

        params = {
            'search': query,
            'op': operation,
            'options': self._parse_options(options),
            'exact': exact if exact in ('on', 'off') else 'off'
        }

        if other_variables[0] is not None:
            for var in other_variables:
                if var[0].startswith('x-'):
                    params[var[0]] = var[1]

        url = '{0}:{1}{2}?{3}'.format(self.host, self.port,
                                      self.lookup_path, urlencode(params))

        try:
            response = urlopen(url)
            return self._parse_index(response.read().decode())
        except HTTPError:
            return None

    def submit(self, keys, options=(None,)):
        """
        Submit one or more keys to the keyserver.

        :param keys: key(s) to submit
        :type keys: str
        :param options: 'nm' or nonstandard option starting with 'x-' (see \
        `RFC draft <http://tools.ietf.org/html/draft-shaw-openpgp-hkp-00#section-3.2.1>`_)
        :type options: tuple(str)
        :returns: http status code
        :rtype: int
        """
        if keys is None:
            raise ValueError('no key(s) given')

        params = {
            'keytext': keys,
            'options': self._parse_options(options)
        }

        url = '{0}:{1}{2}'.format(self.host, self.port, self.submit_path)
        try:
            req = urlopen(url, urlencode(params).encode())
            return req.getcode()
        except HTTPError as error:
            return error.getcode()