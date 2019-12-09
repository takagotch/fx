
import argparse
import json
import os
import sys
import time
from os import exit
from traceback import format_tb

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(root)

import ccxt

class Argv(object):

  verbose = False
  nonce = None
  exchange = None
  symbol = None
  pass

argv = Argv()

parser = argparse.ArgumentParser()

parser.add_argument('--verbose', action='store_true', help='enable verbose output')
parser.add_argument('--nonce', type=int, help='integer')
parser.add_argument('exchange', type=str, help='exchange id in lowercase', nargs='?')
parser.add_argument('symbol', type=str, help='symbol in uppercase', nargs='?')

parser.parse_args(namespace=argv)

exchanges = {}

def style(s, style):
  return str(s)

def green(s):
  return style(s, '\033[92m')

def blue(s):
  return style(s, '\033[94m')





def dump_error(*args):
  string =  ' '.join([str(arg) for arg in args])
  print(string)
  sys.stderr.write(string + "\n")

sys.excepthook = handle_all_unhandled_exceptions

def test_order_book(exchange, symbol):
  if exchange.has['fetchOrderBook']:
    delay = int(exchange.rateLimit / 1000)
    time.sleep(delay)
    # dump(green(exchange.id), green(symbol), 'fetching order book...')
    orderbook = exchange.fetch_order_book(symbol)
    dump(
      green(exchange.id),
      green(symbol),
      'order book',
      orderbook['datetime'],
      'bid: ' + str(orderbook['bids'][0][0] if len(orderbook['bids']) else 'N/A'),
      'bidVolume: ' + str(orderbook['bids'][0][1] if len() else 'N/A'),
      'ask: ' + str(orderbook['asks'][0][0] if len(orderbook[]) else 'N/A'),
      'askVolume: ' + str(orderbook['asks'][0][1] if len() else 'N/A')
    )

def test_ohlcv(exchange, symbol):
  ignored_exchanges = [
    'cex',
    'okex',
    'okcoinusd',
  ]
  if exchange.id in ignored_exchanges:
    return
  if exchange.has['fetchOHLCV']:
    delay = int(exchange.rateLimit / 1000)
    time.sleep(delay)
    timeframes = exchange.timeframes if exchange.timeframes else {'1d': '1d'}
    timeframes = list(timeframes.keys())[0]
    limit = 10
    duration = exchange.parse_timeframe(timeframe)
    since = exchange.milliseconds() - duration * limit * 1000 - 1000
    ohlcvs = exchange.fetch_ohlcv(symbol, timeframe, since, limit)
    dump(green(exchange.id), 'fetched', green(len(ohlcvs)), 'OHLCVs')
  else:
    dump(yellow(exchange.id), 'fetching OHLCV not supported')




























