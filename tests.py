from unittest import TestCase, main, skip
from re import compile, DOTALL
from pyhkp import HKP

# These tests need an internet connection.

# Test keyserver
KEYSERVER = 'http://pgp.mit.edu'
PORT = 11371

# Test key data
KEY_FINGERPRINT = '084750FC01A6D388A643D869010908312D230C5F'
KEY_ID = KEY_FINGERPRINT[-8:]
KEY_ID_0x = '0x' + KEY_ID
KEY_UID = 'Debian Archive Automatic Signing Key (2006) <ftpmaster@debian.org>'
KEY_UID_NAME = 'Debian Archive Automatic Signing Key (2006)'


class TestHKP(TestCase):
    """
    Unit tests for HKP class.
    """
    def strip_pgp_ascii_header(self, key):
        """
        Strip pgp ascii armor header.

        :param key: key with ascii armored header
        :type key: str
        :returns: string index of key data beginning or 0
        :rtype: int
        """
        idx = compile('-----BEGIN PGP (?!SIGNED)(.*)\n\n', flags=DOTALL).\
            search(key)
        if idx is not None:
            return idx.end()
        else:
            return 0

    def setUp(self):
        """
        Setup object instance.
        """
        self.hkp = HKP(KEYSERVER, PORT)

    def test_init(self):
        """
        Test constructor.
        """
        self.hkp = HKP(KEYSERVER, 1337)
        self.assertEqual(self.hkp.host, KEYSERVER)
        self.assertEqual(self.hkp.port, 1337)

    def test_lookup_pub_algorithm(self):
        """
        Test algorithm lookup.
        """
        self.assertEqual(self.hkp.lookup_pubkey_algorithm(109),
                         'Private/Experimental algorithm')
        self.assertEqual(self.hkp.lookup_pubkey_algorithm(1337),
                         'Unknown')
        self.assertEqual(self.hkp.lookup_pubkey_algorithm(19),
                         'ECDSA')

    def test_parse_options(self):
        """
        Test parsing options.
        """
        self.assertEqual(self.hkp._parse_options(None), 'mr')
        self.assertTrue('mr' and ',' and 'x-d' in
                        self.hkp._parse_options(('test', 'x-d')))
        self.assertTrue('mr' and ',' and 'x-d' and 'nm' in
                        self.hkp._parse_options(('x-d', 'test', 'nm', 'ab')))

    def test_retrieve(self):
        """
        Test key retrieval.
        """
        with self.assertRaisesRegex(ValueError, 'no or invalid key id'):
            self.hkp.retrieve('')

        with self.assertRaisesRegex(ValueError, 'no or invalid key id'):
            self.hkp.retrieve(KEY_ID_0x[0:7])

        # None on nonsense key
        self.assertIsNone(self.hkp.retrieve('ABCDEFGH'))

        with open('testdata/debian.asc', 'r') as stored_key:
            key = stored_key.read()
            key = key[self.strip_pgp_ascii_header(key):]
            retrieved = self.hkp.retrieve(KEY_ID_0x)
            retrieved = retrieved[self.strip_pgp_ascii_header(retrieved):]
            self.assertEqual(retrieved, key)

            retrieved = self.hkp.retrieve(KEY_ID_0x)
            retrieved = retrieved[self.strip_pgp_ascii_header(retrieved):]
            self.assertEqual(retrieved, key)

            retrieved = self.hkp.retrieve(KEY_ID_0x, options=('x-test',))
            retrieved = retrieved[self.strip_pgp_ascii_header(retrieved):]
            self.assertEqual(retrieved, key)

    def test_search(self):
        """
        Test searching on a keyserver.
        """
        search_result = self.hkp.search(KEY_ID_0x)
        self.assertIsNotNone(search_result)
        self.assertEqual(len(search_result), 1)

        self.assertEqual(search_result[0]['primary_key']['key_id'], KEY_ID)
        self.assertEqual(search_result[0]['user_ids'][0]['user_id'], KEY_UID)


    #@skip('Skip: Don\'t always submit a key.')
    def test_submit(self):
        """
        Test submitting a key.
        """
        with open('testdata/debian.asc', 'r') as stored_key:
            key = stored_key.read()
            self.assertEqual(200, self.hkp.submit(key))
            self.assertEqual(500, self.hkp.submit(key[:-39]))  # strip crc


if __name__ == '__main__':
    main()