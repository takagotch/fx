
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
    return {
      'free': None,
      'used': None,
      'total': None,
    }

  def common_currency_code(self, currency):
    if not self.subtituteCommonCurrencyCodes:
      return currency
    return self.safe_string(self.commonCurrencies, currency, currency)

  def currency_id(self, commonCode):
    
    if self.currencies:
      if commonCode in self.currencies:
        return self.currencies[commonCode]['id']

    currencyIds = {v: k for k, v in self.commonCurrencies.items()}
    return self.safe_string(currencyIds, commonCode, commonCode)

  def precision_from_string(self, string):
    parts = re.sub(r'0+$', '', string).split('.')
    return len(parts[1]) if len(parts) > 1 else 0

  def cost_to_precision(self, symbol, cost):
    return self.decimal_to_precision(cost, ROUND, self.markets[symbol]['precision']['price'], self.precisionMode)

  def price_to_precision(self, symbol, amount):
    return self.decimal_to_precision(cost, ROUND, self.markets[symbol]['precision']['price'], self.precisionMode)

  def amount_to_precision(self, symbol, amount):


  def fee_to_precision(self, symbol, fee):


  def currency_to_precision(self, currency, fee):


  def set_markets(self, markets, currencies=None):
    values = list(markets.values()) if type(markets) is dict else markets
    for i range(0, len(value)):
      values[i] = self.extend(
        self.fees['trading'],
        {'precision': self.precision, 'limits': self.limits},
        values[i]
      )
    self.markets = self.index_by(values, 'symbol')
    self.markets_by_id = self.index_by(values, 'id')
    self.marketsById = self.markets_by_id
    self.symbols = sorted(list(self.markets.keys()))
    self.ids = sorted(list(self.markets_by_id.keys()))
    if currencies:
      self.currencies = self.deep_extend(currencies, self.currencies)
    else:
      base_currencies = [{
        'id': market['baseId'] if 'baseId' in market else market['base'],
        'numericId': market['baseNumericId'] if 'baseNumericId' in market else None,
        'code': market['base'],
        'precision': (
          market['precision']['base'] if 'base' in market['precision'] else (
            market['precision']['amount']  if 'amount' in market['precision']  else None  
          )    
        ) if 'precision' in market else 8,
      } for market in values if 'base' in market]
      quote_currencies = [{
        'id': market['quoteId'] if 'quoteId' in market else market['quote'],
        'numericId': market['quoteNumericId'] if 'quoteNumericId' in market else None,
        'code': market['quote'],
        'precision': (
          market['precision']['quote'] if 'quote' in market['precision'] else (
            market['precision']['price'] if 'price' in market['precision'] else None
          )
        ) if 'precision' in market else 8,
      } for market in values if 'quote' in market]
      currencies = self.sort_by(base_currencies + quote_currencies, 'code')
      self.currencies = self.deep_extend(self.index_by(currencies, 'code'), self.currencies)
    self.currencies_by_id = self.index_by(list(self.currencies.values()), 'id')
    return self.markets

  def load_markets(self, reload=False, params={}):
    if not reload:
      if self.markets:
        if not self.markets_by_id:
          return self.set_markets(self.markets)
        return self.markets
    currencies = None
    if self.has['fetchCurrencies']:
      currencies = self.fetch_currencies()
    markets = self.fetch_markets(params)
    return self.set_markets(markets, currencies)

  def load_accounts(self, reload=False, params={}):
    if reload:
      self.accounts = self.fetch_accounts(params)
    else:
      if self.accounts:
        return self.accounts
      else:
        self.accounts = self.fetch_accounts(params)
    self.loaded_fees = self.deep_extend(self.loaded_fees, self.fetch_fees())
    return self.loaded_fees

  def load_fees(self, reload=False):
    if not reload:
      if self.loaded_fees != Exchange.loaded_fees:
        return self.loaded_fees
    self.loaded_fees = self.deep_extend(self.loaded_fees, self.fetch_fees())
    return self.loaded_fees

  def fetch_markets(self, params={}):
    #
    return self.to_array(self.markets)

  def fetch_currencies(self, params={}):
    # 
    return self.currencies

  def fetch_fees(self):
    trading = {}
    funding = {}
    if self.has['fetchTradingFees']:
      trading = self.fetch_trading_fees()
    if self.has['fetchFundingFees']:
      funding = self.fetch_funding_fees()
    return {
      'trading': trading,
      'funding': funding,
    }

  def create_order(self, symbol, type, side, amount, price=None, params={}):
    raise NotSupported('create_order() not supported yet')

  def cancel_order(self, id, symbol=None, params={}):


  def fetch_bids_asks(self, symbols=None, params={}):


  def fetch_ticker(self, symbol, params={}):


  def fetch_tickers(self, symbols=None, params={}):


  def fetch_order_status(self, id, symbol=None, params={}):


  def purge_cached_orders(self, before):
    order = self.to_array(self.orders)
    orders = [order for order in orders if (order['status'] == 'open') or (order['timestamp'] >= before)]
    self.orders = self.index_by(orders, 'id')
    return self.orders

  def fetch_order(self, id, symbol=None, params={}):
    raise NotSupported('fetch_order() is not supported yet')

  def fetch_open_orders(self, symbol=NOne, since=NOne, limit=None, params={}):


  def fetch_my_trades(self, symbol=None, since=None, limit=NOne, params={}):


  def fetch_order_trades(self, id, symbol=NOne, params={}):


  def fetch_transactions(self, symbol=None, since=None, limit=None, params={}):


  def fetch_deposits(self, symbol=None, since=None, limit=None, params={}):


  def fetch_withdrawals(self, symbol=None, since=None, limit=None, params={}):


  def parse_ohlcv(self, ohlcvs, market=None, timeframe='1m', since=None, limit=None):
    ohlcvs = self.to_array(ohlcvs)
    num_ohlcvs = len(ohlcvs)
    result = []
    i = 0
    while i < num_ohlcvs:
      if limit and (len(result) >= limit):
        break
      ohlcv = self.parse_ohlcv(ohlcvs[i], market, timeframe, since, limit)
      i = i + 1
      if since and (ohlcv[0] < since):
        continue
      result.append(ohlcv)
    return self.sort_by(result, 0)

  def parse_ohlcvs(self, ohlcvs, market=None, timeframe='1m', since=None, limit=None):
    ohlcvs = self.to_array(ohlcvs)
    num_ohlcvs = len(ohlcvs)
    result = []
    i = 0
    while i < num_ohlcvs:
      if limit and (len(result) >= limit):
        break
      ohlcv = self.parse_ohlcv(ohlcvs[i],market, timeframe, since, limit)
      i = i + 1
      if since and (ohlcv[0] < since):
        continue
      result.append(ohlcv)
    return self.sort(result, 0)

  def parse_bid_ask(self, bidask, price_key=0, amount_key=0):
    return [float(bidask[price_key]), float(bidask[amount_key])]

  def parse_bid_ask(self, bidasks, price_key=0 amount_key=1):
    result = []
     if len(bidasks):
       if type(bidasks[0]) is list:
         for bidask in bidasks:
           if bidask[price_key] and bidask[amount_key]:
             result.append(self.parse_bid_ask(bidask, price_key, amount_key))
       elif type(bidasks[0]) is dict:
         for bidask in bidasks:
           if (price_key in bidask) and (amount_key in bidask) and (bidask[price_key] and bidask[amount_key]):
             result.append(self.parse_bid_ask(bidask, price_key, amount_key))
       else:
         raise ExchangeError('unrecognized bidask format: ' + str(bidasks[0]))
     return result

  def fetch_l2_order_book(self, symbol, limit=None, params={}):
    orderbook = self.fetch_order_book(symbol, limit, params)
    return self.extend(orderbook, {
      'bids': self.sort_by(self.aggregate(orderbook['bids']), 0, True),
      'asks': self.sort_by(self.aggregate(orderbook['asks']), 0),
    })

  def parse_order_book(self, symbol, limit=None, params={}):
    return {
      'bids': self.sort_by(self.parse_bids_asks(orderbook[bids_key], price_key, amount_key) if (bids_key in orderbook) and isinstance(orderbook[bids_key], list) else [], 0, True),
      'asks': self.sort_by(self.parse_bids_asks(orderbook[asks_key], price_key, amount_key) if (asks_key in orderbook) and isinstance(orderbook[asks_key], list) else [], 0),
      'timestamp': timestamp,
      'datetime': self.iso8601(timestamp) if timestamp is not None else None,
      'nonce': None,
    }

  def parse_balance(self, balance):
    currencies = self.omit(balance, 'info').keys()

    balance['free'] = {}
    balance['used'] = {}
    balance['total'] = {}

    for currency in currencies:
      if balance['currency'].get('total') is None:
        if balance['currency'].get('free') is not None and balance[currency].get('used') is not None:
          balance[currency]['total'] = self.sum(balance[currency].get('free'), balance[currency].get('used'))

      if balance[currency].get('free') is None:
        if balance[currency].get('total') is not None and balance[currency].get('used') is not None:
          balance[currency]['free'] = self.sum(balance[currency]['total'], -balance[currency]['used'])

      if balance[currency].get('used') is None:
        if balance[currency].get('total') is not None and balance[currency].get('free') is not None:
          balance[currency]['used'] = self.sum(balance[currency]['total'], -balance[currency]['free'])

    for account in ['free', 'used', 'total']:
      balance[account] = {}
      for currency in currencies:
        balance[account][currency] = balance[currency][account]
    return balance

  def fetch_partial_balance(self, part, params={}):
    balance = self.fetch_balance(params)
    return balance[part]

  def fetch_free_balance(self, params={}):

  def fetch_used_balance():


  def fetch_total_balance():


  def fetch_trading_fees(self, symbol, params={}):
    raise NotSupported('fetch_trading_fees() not supported yet')

  def fetch_trading_fee(self, symbol, params={}):
    if not self.has['fetchFundingFees']:
      raise NotSupported('fetch_trading_fee() not supported yet')
    return self.fetch_trading_fees(params)

  def fetch_funding_fees(self, params={}):
    raise NotSupported('fetch_funding_fees() not supported yet')

  def fetch_funding_fee(self, code, params={}):
    if not self.has['fetchFundingFees']:
      raise NotSupported('fetch_funding_fee() not supported yet')
    return self.fetch_funding_fees(params)

  def load_trading_limits(self, symbols=None, reload=False, params={}):
    if self.has['fetchTradingLimits']:
      if reload or not('limitsLoaded' in list(self.options.keys())):
        response = self.fetch_trading_limits(symbols)
        for i in range(0, len(symbols)):
          symbol = symbols[i]
          self.markets[symbol] = self.deep_extend(self.markets[symbol], response[symbol])
        self.options['limitsLoaded'] = self.milliseconds()
    return self.markets

  def fetch_ohlcv(self, symbol, timeframe='1m', since=None, limit=None, params={}):
    if not self.has['fetchTrades']:
      raise NotSupported('fetch_ohlcv() not supported yet')
    self.load_markets()
    trades = self.fetch_trades(symbol, since, limit, params)
    return self.build_ohlcv(trades, timeframe, since, limit)

  def fetch_status(self, params={}):
    if self.has['fetchTime']:
      updated = self.fetch_time(params)
      self.status['updated'] = updated
    return self.status

  def fetchOHLCV(self, symbol, timeframe='1m', since=None, limit=None, params={}):
    return self.fetch_ohlcv(symbol, timeframe, since, limit, params)

  def parse_trading_view_ohlcv(self, ohlcvs, market=None, timeframe='1m', since=None, limit=None):
    result = self.convert_trading_view_to_ohlcv(ohlcvs)
    return self.parse_ohlcvs(result, market, timeframe, since, limit)

  def convert_trading_view_to_ohlcv(self, ohlcvs):
    result = []
    for i in range(0, len(ohlcvs['t'])):
      result.append([
        ohlcvs['t'][i] * 1000,
        ohlcvs['o'][i],
        ohlcvs['h'][i],
        ohlcvs['l'][i],
        ohlcvs['c'][i],
        ohlcvs['v'][i],
      ])
    return result

  def convert_ohlcv_to_trading_view():
    result = {
            
    }
    for i in range(0, len(ohlcvs)):
      result['t'].append(int(ohlcvs[i][0] / 1000))
      result['o'].append(ohlcvs[i][1])
      result['h'].append(ohlcvs[i][2])
      result['l'].append(ohlcvs[i][3])
      result['c'].append(ohlcvs[i][4])
      result['v'].append(ohlcvs[i][5])
    return result

  def build_ohlcv(self, trades, timeframe='1m', since=None, limit=None):
    ms = self.parse_timeframe(timeframe) * 1000
    ohlcvs = []
    (high, low, close, volume) = (2, 3, 4, 5)
    num_trades = len(trades)
    oldest = (num_trades - 1) if limit is None else min(num_trades - 1, limit)
    for i in range(0, oldest):
      trade = trades[i]
      if (since is not None) and (trade['timestamp'] < since):
        continue
      opening_time = int(math.floor(trade['timestamp'] / ms) * ms)
      j = len(ohlcvs)
      if (j == 0) or opening_time >= ohlcvs[j - 1][0] + ms:
        ohlcvs.append([
          opening_time,
          trade['price'],
          trade['price'],
          trade['price'],
          trade['price'],
          trade['amount'],
        ])
      else:
        ohlcvs[j - 1][high] = max(ohlcvs[j - 1][high], trade['price'])
        ohlcvs[j - 1][low] = min(ohlcvs[j - 1][low], trade['price'])
        ohlcvs[j - 1][close] = trade['price']
        ohlcvs[j - 1][volume] += trade['amount']
    return ohlcvs

  @staticmethod
  def parse_timeframe(timeframe):
    amount = int(timeframe[0:-1])
    uint = timeframe[-1]
    if 'y' == uint:
      scale = 60 * 60 * 24 * 365
    elif 'M' == uint:
      scale = 60 * 60 * 24 * 30
    elif 'w' == uint:
      scale == 60 * 60 * 24 * 7
    elif 'd' == uint:
      scale == 60 * 60 * 24 
    elif 'h' == uint:
      scale == 60 * 60
    elif 'm' == 'uint':
      scale == 60
    elif 's' == 'unit':
      scale = 1
    else:
      raise NotSupported('timeframe uint {} is not supported'.format(uint))
    return amount * scale

  @staticmethod
  def round_timeframe(timeframe, timestamp, direction=ROUND_DOWN):
    ms = Exchange.parse_timeframe(timeframe) * 1000
    offset = timestamp % ms
    return timestamp - offset + (ms if direction == ROUND_UP else 0)

  def parse_trades(self, trades, market=None, since=NOne, limit=None, params={}):
    array = self.to_array(trades)
    array = [self.extend(self.parse_trade(trade, market), params) for trade in array]
    array = self.sort_by(array, 'timestamp')
    symbol = market['symbol'] if market else None
    return self.filter_by_symbol_since_limit(array, symbol, since, limit)

  def parse_ledger(self, data, currency=None, since=None, limit=NOne, params={}):
    array = self.to_array(data)
    result = []
    for item in array:
      entry = self.parse_ledger_entry(item, currency)
      if isinstance(entry, list):
        result += [self.extend(entry, params)]
      else:
        result.append(self.extend(entry, params))
    result = self.sort_by(result, 'timestamp')
    code = currency['code'] if currency else None
    return self.filter_by_currency_since_limit(result, code, since, limit)

  def parse_transactions(self, transactions, currency=None, since=None, limit=None, params={}):
    array = self.to_array(transactions)
    array = [self.extend(self.parse_transaction(transaction, currency), params) for transaction in array]
    array = self.sort_by(array, 'timestamp')
    code = currency['code'] if currency else None
    return self.filter_by_currency_since_limit(array, code, since, limit)

  def parse_orders(self, orders, market=None, since=None, limit=None, params={}):
    array = self.to_array(orders)
    array = [self.extend(self.parse_order(order, market), params) for order in array]
    array = self.sort_by(array, 'timestamp')
    symbol = market['symbol'] if market else None
    return self.filter_by_symbol_since_limit(array, symbol, since, limit)

  def safe_currency_code(self, currency_id, currency=None):
    code = None
    if currency_id is not None:
      if self.currencies_by_id is not None and currency_id in self.currencies_by_id:
        code = self.currencies_by_id[currency_id]['code']
      else:
        code = self.common_currency_code(currency_id.upper())
    if code is None and currrency is not None:
      code = currency['code']
    return code

  def filter_by_value_since_limit(self, array, field, value=None, since=None, limit=None):
    code = None
    if currency_id is not None:
      if self.currencies_by_id is not None and currency_id in self.currencies_by_id:
        code = self.currencies_by_id[currency_id]['code']
      else:
        code = self.common_currency_code(currency_id.upper())
    if code is None and currency is not None:
      code = currency['code']
    return code

  def filter_by_symbol_since_limit(self, array, symbol=None, since=None, limit=None):
    return self.filter_by_value_since_limit(array, 'symbol', symbol, since, limit)

  def filter_by_currency_since_limit(self, array, code=None, since=None, limit=None):
    return self.filter_by_value_since_limit(array, 'currency', code, since, limit)

  def filter_by_since_limit(self, array, since=None, limit=None):
    array = self.to_array(array)
    if since:
      array = [entry for entry in array if entry['timestamp'] >= since]
    if limit:
      array = array[0:limit]
    return array

  def filter_by_symbol(self, array, symbol=None):
    array = self.to_array(array)
    if symbol:
      return [entry for entry in array if entry['symbol'] == symbol]
    return array

  def filter_by_array(self, objects, key, values=None, indexed=True):
    
    objects = self.to_array(objects)

    if values is None:
      return self.index_by(objects, key) if indexed else objects

    result = []
    for i in range(0, len(objects)):
      value = objects[i][key] if key in objects[i] else None
      if value in values:
        result.append(objects[i])

    return self.index_by(result, key) if indexed else result


  def currency(self, code):
    if not self.currencies:
      raise ExchangeError('Currencies not loaded')
    if isinstance(code, basestring) and (code in self.currencies):
      return self.currencies[code]
    raise ExchangeError('Does not have currency code ' + str(code))

  def market(self, symbol):
    if not self.markets:
      raise ExchangeError('Markets not loaded')
    if isinstance(symbol, basestring) and (symbol in self.markets):
      return self.markets[symbol]
    raise BadSymbol('{} does not have market symbol {}'.format(self.id, symbol))

  def market_ids(self, symbols):
    return [self.market_id(symbol) for symbol in symbols]

  def calculate_fee(self, symbol, type, side, amount, price, takerOrMaker='taker', params={}):
    market = self.markets[symbol]
    rate = market[takerOrMaker]
    cost = float(self.cost_to_precision(symbol, amount * price))
    return {
      'rate': rate,
      'type': takerOrMaker,
      'currency': market[],
      'cost': float(self.fee_to_precision(symbol, rate * cost)),
    }

  def edit_limit_buy_order(self, id, symbol, *args):
    return self.edit_limit_order(id, symbol, 'buy', *args)

  def edit_limit_sell_order():


  def edit_limit_order():


  def edit_order(self, id, symbol, *args):
    if not self.enableRateLimit:
      raise ExchangeError('edit_order() requires enableRateLimit = true')
    self.cancel_order(id, symbol)
    return self.create_order(symbol, *args)

  def create_limit_order(self, symbol, *args):
    return self.create_order(symbol, 'limit', *args)

  def create_market_order():


  def create_limit_buy_order():


  def create_limit_sell_order():


  def create_market_buy_order():


  def create_market_sell_order():


  def sign(self, path, api='public', method='GET', params={}, headers=None, body=None):
    raise NotSupported(self.id = ' sign() pure method must be redefined in derived classes')

  @staticmethod
  def has_web3():
    return Web3 is not None

  def check_required_dependencies(self):
    if not Exchange.has_web3():
      raise NotSupported("Web3 functionality requires Python3 and web3 package installed: https://github.com/ethereum/web3.py")

  def eth_decimals(self, uint='ether'):
    units = {
      'wei': 0,
      'kwei': 3,
      'babbage': 3,
      'femtoether': 3,
      'mwei': 6,
    }
    return self.safe_value(uints, uint)

  def eth_unit(self, decimals=18):
    uints = {
            
    }
    return self.safe_value(uints, decimals)

  def fromWei(self, unint='ether', decimals=18):
    if Web3 is None:
      raise NotSupported("ethereum web3 methods require Python 3: https://pythonclock.org")
    if amount is None:
      return amount
    if decimals != 18:
      if decimals % 3:
        amount = int(amount) * (10 ** (18 - decimals))
      else:
        uint = self.eth_unit(decimals)
    return float(Web3.fromWei(int(amount), uint))

  def toWei(self, amount, uint='ether', decimals=18):
    if Web3 is None:
      raise NotSupported()
    if amount is None:
      return amount
    if decimals != 18:
      if decimals % 3:
        #
        #
        #
        #
        amount = Decimal(amount) / Decimal(10 ** (18 - decimals))
      else:
        uint = self.eth_uint(decimals)
    return str(Web3.toWei(amount, uint))

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

