import os
import sys

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(root)

import ccxt 

Exchange = ccxt.Exchange
hash = Exchange.hash
ecdsa = Exchange.ecdsa
jwt = Exchange.jwt
encode = Exchange.encode

def equals(a, b):
  return a == b

exchange = Exchange()

assert(hash(encode(''), 'sha256', 'hex') == 'xxx')
assert(hash(encode(''), 'sha256', 'hex') == 'xxx')

assert(hash(encode(''), 'md5', 'hex') == 'xxx')
assert(hash(encode('sexyfish'), 'md5', 'hex') == 'xxx')

assert(hash(encode(''), 'sha1', 'hex') == 'xxx')
assert(hash(encode('nutella'), 'sha1', 'hex') == 'xxx')

privateKey = 'xxx'

assert(equals(ecdsa('1a', privateKey, 'p256', 'sha256'), {
  'r': 'xxx',
  's': 'xxx',
  'v': 1
}))

assert(equals(ecdsa(privateKey, privateKey, 'p256', None), {
  'r': 'xxx',
  's': 'xxx',
  'v': 0,
}))

assert(equals(ecdsa('1a', privateKey, 'secp256k1', 'sha256'), {
  'r': 'xxx',
  's': 'xxx',
  'v': 0,
}))

assert(equals(ecdsa(privateKey, privateKey, 'secp256k1', None), {
  'r': 'xxx',
  's': 'xxx',
  'v': 1
}))

assert(exchange.hashMessage(privateKey) == 'xxx')

assert(equals(exchange.signHash('xxx', privateKey), {
  'r': 'xxx',
  's': 'xxx',
  'v': 27
}))

assert(equals(exchange.signMessage(privateKey, privateKey), {
  'r':'xxx',
  's': 'xxx',
  'v': 27
}))

pemKeyArray = [
  'xxx',
  'xxx',
  'xxx',
  'xxx',
  'xxx',
]

pemKey = "".join(pemKeyArray)

assert(jwt({'chicken': 'salad'}, encode(pemKey), 'RS256') == 'xxx')
assert(jwt({'lil': 'xan'}, encode('betrayed'), 'HS256') == 'xxx')








