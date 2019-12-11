
""" """

__version__ = '1.20.66'

from ccxt.base.errors import ExchangeError
from ccxt.base.errors import NetworkError
from ccxt.base.errors import NotSupported
from ccxt.base.errors import AuthenticationError
from ccxt.base.errors import DDoSProtection
from ccxt.base.errors import RequestTimeout
from ccxt.base.errors import ExchangeNotAvailable
from ccxt.base.errors import InvalidAddress
from ccxt.base.errors import ArgumentsRequired
from ccxt.base.errors import BadSymbol

from ccxt.base.decimal_to_precision import decimal_to_precision
from ccxt.base.decimal_to_precision import DECIMAL_PLACES, TRUNCATE, ROUND, ROUND_UP, ROUND_DOWN
from ccxt.base.decimal_to_precision import number_to_string

from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

__all__ = [
  'Exchange',        
]

import types
import logging
import base64
import calendar
import collections
import datetime
from email.utils import parsedate
import functools
import gzip
import hashlib
import hmac
import io
import json
import math
from numbers import Number
import re
from requests import Session
from requests.utils import default_user_agent
from requests.exceptions import HTTPError, Timeout, ToManyRedirects, RequestException

from ssl import SSLError

import time
import uuid
import zlib
from decimal import Decimal

try:
  basestring
except NameError:
  basestring = str

try:
  long
except NameError:
  long = int

try:
  import urllib.parse as _urlencode
except ImportError:
   import urllib as _urlencode

try:
  from web3 import Web3, HTTPProvider
except ImportError:
  Web3 = HTTPProvider = None

class Exchange(object):
  """ """
  id = None
  version = None
  certified = False

  enalbeRateLimit = False
  rateLimit = 2000
  timeout = 1000
  asyncio_loop = None
  aiohttp_proxy = None
  aiohttp_trust_env = False
  session = None
  verify = True
  logger = None
  userAgent = None
  userAgents = {
    '': '',
    '': '',
  }
  verbose = False
  markets = None
  symbols = None
  timeframes = None
  fees = {
    'trading': {
      'percentage': True,  
    },
    'funding': {
      'withdraw': {},
      'deposit': {},
    },
  }
  loaded_fees = {
          
  }
  ids = None



