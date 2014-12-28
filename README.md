pyhkp
=====

Python3 module that provides a class to interact with OpenPGP keyservers using HKP.

Documentation can be found at http://rawgit.com/eadil/pyhkp/master/doc/_build/singlehtml/index.html.

Usage:

# setup server
```
k = HKP('http://pgp.mit.edu', 11371)
```

# search for keys
```
result = k.search('0x2D230C5F')
print(result)
[{'primary_key': {'algorithm': 'DSA',
                  'algorithm_id': 17,
                  'creation': datetime.datetime(2006, 1, 3, 11, 12, 19),
                  'disabled': False,
                  'expiration': None,
                  'expired': False,
                  'key_id': '2D230C5F',
                  'key_length': 1024,
                  'revoked': False},
  'user_ids': [{'creation': datetime.datetime(2006, 1, 3, 11, 12, 19),
                'disabled': False,
                'expiration': None,
                'expired': False,
                'revoked': False,
                'user_id': 'Debian Archive Automatic Signing Key (2006) '
                           '<ftpmaster@debian.org>'}]}]
```
```
print(k.search('edward snowden'))

[{'primary_key': {'algorithm': 'RSA Encrypt or Sign',
                  'algorithm_id': 1,
                  'creation': datetime.datetime(2014, 7, 1, 17, 13, 41),
                  'disabled': False,
                  'expiration': None,
                  'expired': False,
                  'key_id': 'EE6AB144',
                  'key_length': 3072,
                  'revoked': False},
  'user_ids': [{'creation': datetime.datetime(2014, 7, 1, 17, 13, 41),
                'disabled': False,
                'expiration': None,
                'expired': False,
                'revoked': False,
                'user_id': 'Help Edward Snowden '
                           '<helpedwardsnowden@outlook.com>'}]},
 {'primary_key': {'algorithm': 'RSA Encrypt or Sign',
                  'algorithm_id': 1,
                  'creation': datetime.datetime(2014, 6, 2, 11, 59, 3),
                  'disabled': False,
                  'expiration': None,
                  'expired': False,
                  'key_id': '3225E189',
                  'key_length': 4096,
                  'revoked': False},
  'user_ids': [{'creation': datetime.datetime(2014, 6, 2, 11, 59, 3),
                'disabled': False,
                'expiration': None,
                'expired': False,
                'revoked': False,
                'user_id': 'Michael Brauckmann (Dank_an_Edward_Snowden) '
                           '<michael.brauckmann@t-online.de>'}]},
...]
```

# retrieve pubkey as str
```
pubkey_str = k.retrieve('0x2D230C5F')
```

# submit a loaded key (as str)
```
k.submit(loaded_key)
```
