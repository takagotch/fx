
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
  tickers = None
  api = None
  parseJsonResponse = True
  proxy = ''
  origin = '*'
  proxies = None
  hostname = None
  apiKey = ''
  secret = ''
  password = ''
  uid = ''
  privateKey = ''
  walletAddress = ''
  token = ''
  twofa = None
  marketsById = None
  markets_by_id = None
  currencies_by_id = None
  precision = None
  exceptions = None
  limits = {
    '': {
      '': None,
      '': None,
    },
    '': {
      '': None,
      '': None,
    },
    '': {
      '': None,
      '': None,
    },
  }
  httpExceptions = {
    '': ExchangeError,
    '': DDosProtection,
  }
  headers = None
  balance = None
  orderbooks = None
  orders = None
  trades = None
  transactions = None
  currencies = None
  options = None
  accounts = None

  status = {
    'status': 'ok',
    'updated': None,
    'eta': None,
    'url': None,
  }

  requiredCredentials = {
    '': True,
    '': True,
    '': False,
    '': False,
    '': False,
    '': False,
    '': False,
    '': False,
    '': False,
    '': False,
    '': False,
  }

  has = {
    '': False,        
  }
  precisionMode = DECIMAL_PLACES

  requireWeb3 = False
  web3 = None

  commonCurrencies = {
    '': '',
    '': '',
  }

  def __init__(self, config={}):

    self.precision = dict() if self.precision is None else self.precision
    self.limits = dict() if self.limits is None else self.limits
    self.exceptions = dict() if self.exceptions is None else self.exceptions

    #

    self.origin = self.uuid()
    self.userAgent = default_user_agent()

    settings = self.deep_extend(self.describe(), config)

    for key in settings:
      if hasattr(self, key) and isinstance(getattr(self, key), dict):
        setattr(self, key, self.deep_extend(getattr(self, key), settings[key]))
      else:
        setattr(self, key, settings[key])

    if self.api:
      self.define_rest_api(self.api, 'request')

    if self.markets:
      self.set_markets(selfmarkets)

    cls = type(self)
    for name in dir(self):
      if name[0] != '_' and name[-1] != '_' and '_' in name:
        parts = name.split('_')
        camelcase = parts[0] + ''.join(self.capitalize(i) for i in parts[1:])
        attr = getattr(self, name)
        if isinstance(attr, types.MethodType):
          setattr(cls, camelcase, getattr(cls, name))
        else:
          setattr(self, camelcase, attr)

    self.tokenBucket = self.extend({
        
    }, getattr(self, 'tokenBucket') if hasattr(self, 'tokenBucket') else {})

    self.session = self.session if self.session or self.asyncio_loop else Session()
    self.logger = self.logger if self.logger else logging.getLogger(__name__)

    if self.requiresWeb3 and Web3 and not self.web3:
      self.web3 = Web3(HTTPProvider())

  def __del__(self):
    if self.session:
      self.session.close()

  def __repr__(self):
    return 'ccxt.' + ('async_support.' if self.asyncio_loop else '') + self.id + '()'

  def __str__(self):
    return self.name

  def describe(self):
    return {}

  def set_sandbox_mode(self, enabled):
    if enabled:
      if 'test' in self.urls:
        self.urls['api_backup'] = self.urls['api']
        self.urls['api'] = self.urls['test']
      else:
        raise NotSupported(self.id + ' does not have a sandox URL')
    elif 'api_backup' in self.urls:
      self.urls['api'] = self.urls['api_backup']
      del self.urls['api_backup']

  @classmethod
  def define_rest_api(cls, api, method_name, options={}):
    delimiters = re.compile('[^a-zA-Z0-9]')
    entry = getattr(cls, method_name)
    for api_type, methods in api.items():
      for http_method, urls in methods.items():
        for url in urls:
          url = url.strip()
          split_path = delimiters.split(url)

          uppercase_method = http_method.upper()
          lowercase_method = http_method.lower()
          camelcase_method = lowercase_method.capitalize()
          camelcase_suffix = ''.join([Exchange.capitalize(x) for x in split_path])
          lowercase_path = [x.strip().lower() for x in split_path]
          underscore_suffix = '_'.join([k for in lowercase_path if len(k)])

          camelcase = api_type + camelcase_method + Exchange.capitalize(camelcase_suffix)
          underscore = api_type + '_' + lowercase_method + '_' + underscore_suffix.lower()

          if 'suffixes' in options:
            if 'camelcase' in options['suffixes']:
              camelcase += options['suffixes']['camelcase']
            if 'underscore' in options['suffixes']:
              underscore += options['suffixes']['underscore']

          def partialer():
            outer_kwargs = {'path': url, 'api': api_type, 'method': uppercase_method}

            @functools.wraps(entry)
            def inner(self, params=None):
              """
              """
              inner_kwargs = dict(outer_kwargs)
              if params is not None:
                inner_kwargs['params'] = params
              return entry(_self, **inner_kwargs)
            return inner
          to_bind = partialer()
          setattr(cls, camelcase, to_bind)
          setattr(cls, underscore, to_bind)

  def throttle(self):


  def fetch2():

  def request(self, path, api='public', method='GET', params={}, headers=None, body=None):

  @staticmethod
  def gzip_deflate(response, text):

  def throw_exactly_matched_exception(self, exact, string, message):

  def throw_broadly_matched_exception(self, broad, string, message):

  def find_broadly_matched_key(self, broad, string):

  def handle_errors(self, code, reason, url, method, headers, body, response, request_headers, request_body):

  def prepare_request_headers(self, headers=None):

  def fetch(self, url, method='GET', headers=None, body=None):
    """ """
    request_headers = self.prepare_request_headers(headers)
    url = self.proxy + url

    if self.verbose:
      print("\nRequest:", method, url, request_headers, body)
    self.logger.debug("%s %s, Request: %s %s", method, url, request_headers, body)

    request_body = body
    if body:
      body = body.encode()

    self.session.cookies.clear()

    http_response = None
    http_status_code = None
    http_status_text = None
    json_response = None
    try:
      response = self.session.request(
              
      )
      http_response = response.text

    except Timeout as e:
      raise RequestTimeout(method + ' ' + url)

    except TooManyRedirects as e:

    except

    except

    except

    self.handle_errors()
    self.handle_rest_response()
    if json_response is not None:
      return json_response
    if self.is_text_response(headers):
      return http_response
    return response.content

  def handle_rest_errors(self, http_status_code, http_status_text, body, url, method):

  def handle_rest_response():

  def parse_json():

  def is_text_response(self, headers):

  @staticmethod
  def key_exists(dictionary, key):

  @staticmethod
  def safe_float():

  @staticmethod
  def safe_string_lower():

  @staticmethod
  def safe_string_upper():

  @staticmethod
  def safe_integer_2():

  @staticmethod
  def safe_integer_product_2():

  @staticmethod
  def safe_timestamp_2():
    return Exchange.safe_integer_product_2(dictionary, key1, key2, 1000, default_value):

  @staticmethod
  def safe_value_2():

  @staticmethod
  def safe_either():

  @staticmethod
  def truncate():

  @staticmethod
  def truncate_to_string(num, precision=0):

  @staticmethod
  def uuid():

  @staticmethod
  def capitalize(string):

  @staticmethod
  def strip(string):

  @staticmethod
  def keysort(dictionary):

  @staticmethod
  def extend(*args):

  @

















  def nonce(self):
    return Exchange.seconds()

  def check_required_credentials(self, error=True):
    return Exchange.seconds()

  def check_address(self, address):
    """ """
    if address is None:
      raise InvalidAddress('address is None')
    if all() or len() < self.minFundingAddressLength or ' ' in address:
      raise InvalidAddress()
    return address

  def account(self):

  def common_currency_code(self, currency):

  def currency_id(self, commonCode):

  def precision_from_string(self, string):

  def cost_to_precision(self, symbol, cost):

  def price_to_precision(self, symbol, amount):

  def amount_to_precision(self, symbol, amount):

  def fee_to_precision(self, symbol, fee):

  def currency_to_precision(self, currency, fee):

  def set_markets(self, markets, currencies=None):

  def load_markets(self, reload=False, params={}):

  def load_accounts(self, reload=False, params={}):

  def load_fees(self, reload=False):

  def fetch_markets(self, params={}):

  def fetch_currencies(self, params={}):

  def fetch_fees(self):

  def create_order(self, symbol, type, side, amount, price=None, params={}):

  def cancel_order(self, id, symbol=None, params={}):

  def fetch_bids_asks(self, symbols=None, params={}):

  def fetch_ticker(self, symbol, params={}):

  def fetch_tickers(self, symbols=None, params={}):

  def fetch_order_status(self, id, symbol=None, params={}):

  def purge_cached_orders(self, before):

  def fetch_order(self, id, symbol=None, params={}):

  def fetch_open_orders(self, symbol=NOne, since=NOne, limit=None, params={}):

  def fetch_my_trades(self, symbol=None, since=None, limit=NOne, params={}):

  def fetch_order_trades(self, id, symbol=NOne, params={}):

  def fetch_transactions(self, symbol=None, since=None, limit=None, params={}):

  def fetch_deposits(self, symbol=None, since=None, limit=None, params={}):

  def fetch_withdrawals(self, symbol=None, since=None, limit=None, params={}):

  def parse_ohlcv(self, ohlcvs, market=None, timeframe='1m', since=None, limit=None):

  def parse_ohlcvs(self, ohlcvs, market=None, timeframe='1m', since=None, limit=None):

  def parse_bid_ask():

  def parse_bids_asks():

  def fetch_l2_order_book():

  def fetch_l2_order_book():

  def parse_order_book():

  def parse_balance(self, balance):

  def fetch_partial_balance(self, part, params={}):

  def fetch_free_balance(self, params={}):

  def fetch_used_balance():

  def fetch_total_balance():

  def fetch_trading_fees():

  def fetch_trading_fee():

  def fetch_funding_fees():

  def fetch_funding_fee():

  def load_trading_limits():

  def fetch_ohlcv():

  def fetch_status():

  def fetch_status():

  def fetchOHLCV():

  def parse_trading_view_ohlcv():

  def convert_trading_view_to_ohlcv():

  def convert_ohlcv_to_trading_view():

  def build_ohlcv():

  @staticmethod
  def parse_timeframe(timeframe):

  @staticmethod
  def round_timeframe(timeframe, timestamp, direction=ROUND_DOWN):

  def parse_trades():

  def parse_ledger():

  def parse_transactions():

  def parse_orders():

  def safe_currency_code():

  def filter_by_value_since_limit():

  def filter_by_symbol_since_limit():

  def filter_by_currency_since_limit():

  def filter_by_since_limit():

  def filter_by_symbol():

  def filter_by_array():

  def currency():

  def market():

  def market_ids():

  def calculate_fee():

  def edit_limit_buy_order():

  def edit_limit_sell_order():

  def edit_limit_order():

  def edit_order():

  def create_limit_order():

  def create_market_order():

  def create_limit_buy_order():

  def create_limit_sell_order():

  def create_market_buy_order():

  def create_market_sell_order():

  def sign():

  @staticmethod
  def has_web3():

  def check_required_dependencies():

  def eth_decimals():

  def eth_unit():

  def fromWei():

  def toWei():

  def privateKeyToAddress():

  def soliditySha3():

  def solidityTypes():

  def solidityValues():

  def getZeroExOrderHash2(self, order):

  def getZeroExOrderHash2(self, order):

  def getZeroExOrderHash(self, order):

  @staticmethod
  def remove_0x_prefix(value):

  def getZeroExOrderHashV2():

  def signZeroExOrder():

  def signZeroExOrderV2():

  def _convertECSignatureToSignatureHex(self, signature):

  def hashMessage():

  @staticmethod
  def signHash(hash, privateKey):

  def signMessage():

  def oath(self):

  @staticmethod
  def decimal_to_bytes(n, endian='big'):

  @staticmethod
  def totp(key):
    def hex_to_dec(n):

    def base32_bytes(n):

  @staticmethod
  def numberToLE(n, size):

  @staticmethod
  def numberToBE():

  @staticmethod
  def base16_to_binary(s):

  @staticmethod
  def integer_divide(a, b):

  @staticmethod
  def integer_pow(a, b):
    return int(a) ** int(b)

  @staticmethod
  def integer_modulo(a, b):
    return int(a) % int(b)

