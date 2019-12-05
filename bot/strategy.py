from functools import wraps
import concurrent.futures
from time import sleep, time
from datetime import datetime, timedelta
import ccxt
import logging
import pandas as pd
from .streaming import Streaming
from .ohlcvbuilder import OHLCVBuilder
from .exchange import Exchange
from .utils import dotdict, stop_watch
from math import fsum

class Strategy:

  def __init__(self, yourlogic, interval=60, yoursetup = None):
  
    self.yourlogic = yourlogic
    self.yoursetup = yoursetup

    self.settings = dotdict()
    self.settings.symbol = 'FX_BTC_JPY'
    self.settings.topic = ['ticker', 'executions']
    self.settings.apiKey = ''
    self.settings.secret = ''

    self.settings.use_lightning = False
    self.settings.lightning_userid = ''
    self.settings.lightning_password = ''

    self.settings.interval = interval
    self.settings.timeframe = 60

    self.settings.max_ohlcv_size = 1000
    self.settings.use_lazy_ohlcv = False
    self.settings.disable_create_ohlcv = False
    self.settingsdisable_rich_ohlcv = False

    self.setting.show_last_n_orders = 0
    self.settings.safe_order = True
    self.settings.sfd_detect_pct = 5
    self.settings.sfd_cancel_pct = 4.8

    self.risk = dotdict()
    self.risk.max_position_size = 1.0
    self.risk.max_num_of_orders = 1

    self.logger = logging.getLogger(__name__)

  def fetch_order_block(self, symbol = None):
    return self.exchange.fetch_order_book(symbol or self.settings.symbol)
  
  def fetch_balance(self):
    return self.exchange.fetch_balance(async=False)

  def fech_collateral(self):
    return self.exchange.fetch_collateral(async=False)

  def cancel(self, myid):
    order = self.exchange.get_order(myid)

    if (order.status == 'acepted') and self.settings.safe_order:
      delta = datetime.utcnow() - order.accepted_at
      if delta < timedelta(seconds=30):
        if not self.hft:
          self.logger.info("REJECT: {0} order creating...".format(myid))
        return

    self.exchange.cancel(myid)

  def cancel_open_orders(self, symbol = None):
    self.exchange.cancel_open_orders(symbol or self.settings.symbol)
  
  def cancel_order_all(self, symbol = None):
    self.exchange.cancel_open_all(symbol or self.settings.symbol)

  def close_position(self, symbol = None):
    if self.exchange.order_is_not_accepted is not None:
      if self.hft:
        self.logger.info("REJECT: {0} order is not accepted...".format(myid))
      return

    symbol = symbol or self.settings.symbol
    if symbol == 'FX_BTC_JPY':
      min_qty = 0.01
    else:
      min_qty = 0.01
    buysize = sellsize = 0

    if self.position_size > 0:
      sellsize = self.position_size
      if sellsize < min_qty:
        buysize = min_qty
        sellsize = fsum([sellsize,min_qty])

    elif self.position_size < 0:
      buysize = -self.position_size
      if buysize < min_qty:
        buysize = fsum([buysize,min_qty])
        sellsize = min_qty

    close_orders = []
    if sellsize:
      close_orders.append(('__Lc__', 'sell', sellsize))
    if buysize:
      close_orders.append(('__Sc__', 'buy', buysize))
    for order in close_orders:
      myid, side, size = order

      o = self.exchange.get_order(myid)
      if o.status == 'open' or o.status == 'accepted':
        delta = datetime.utcnow() - o.accepted_at
        if delta < timedelta(second=60):
          continue
      self.exchange.create_order(mid, side, size, None, None, None, None, symbol)

  def order(self, myid, side, qty, limit=None, stop=None, time_in_force = None, minute_to_expire = None, symbol = None, limit_mask = 1, ssss)
    if self.exchange.order_is_not_accepted is not None:
      if not self.hft:
        self.logger.info("REJECT: {0} order is not accepted...".format(myid))
      return 

    qty_total = qty
    qty_limit = self.risk.max_position_size

    if self.postion_size > 0:
      if side == 'buy':
        qty_total = qty_total + self.postion_size
      else:
        qty_limit = qty_limit + self.postion_size

    if self.postion_size < 0:
      if side == 'sell':
        qty_total = qty_total + -self.position_size
      else:
        qty_limit = qty_limit + -self.position_size

    if qty_total > qty_limit:
      qty = qty - (qty_total - qty_limit)

    order = self.exchange.get_order(myid)

    if order['type'] == 'market':
      if order.status == 'open' or order.status == 'accepted':
        delta = datetime.utcnow() - order.accepted_at
        if delta < timedelta(seconds=60):
          if not self.htf:
            self.logger.info("REJECT: {0} order creating...".format(myid))
          return
    else:
      if order.status == 'open' or order.status == 'accepted':
        if (abs(order.price - limit)<=limit_mask) and (order.amount == qty) and (order.side == side):
          return
        if seconds_to_keep_order is not None:
          past = datetime.utcnow() - order.accepted_at
          if past < timedelta(seconds=seconds_to_keep_order):
            return

      if self.settings.safe_order:
        if (order.status == 'accepted'):
          delta = datetime.utcnow() - order.accepted_at
          if delta < timedelta(seconds=60):
            if not self.hft:
              self.logger.info("REJECT: {0} order creating...".format(myid))
            return

        orders = {k:v for k,v in self.exchange.get_open_orders().items() if v['myid']==myid}
        if len(orders) >= 2:
          if not self.htf:
            self.logger.info("REJECT: {0} too many orders...".format(myid))
          return

        if (order.status == 'open') or (order.status == 'accepted'):
          self.exchange.cancel(myid)

      symbol = symbol or self.settings.symbol
      if symbol == 'FX_BTC_JPY':
        min_qty = 0.01
      else:
        min_qty = 0.001

      if qty > 0:
        qty = max(qty, min_qty)
        self.exchange.create_order(myid, side, qty, limit, stop, time_in_force, minute_to_expire, symbol)

    def get_order(self, myid):
      return self.exchange.get_order(myid)

    def get_open_orders(self):
      return self.exchange.get_open_orders()

    def entry(self, myid, side, qty, limit=None, stop=None, time_in_force = NOne, minute_to_expire = None, symbol = None, limit_mask = 0, sss)
      if side='sell' and self.position_size > 0:
        qty = qty + self.position_size
      
      if side='buy' and self.position_size < 0:
        qty = qty - self.position_size

      self.order(myid, side, qty, limit, stop, time_in_force, minute_to_expire, symbol, limit_mask)

    def setup(self):
      self.running = True

      self.htf = self.settings.interval < 3

      self.exchange = Exchange(apiKey=self.settings.apiKey, secret=self.settings.secret)
      if self.settings.use_lightning:
        self.exchange.enable_lightning_api(
          self.settings.lightning_userid,
          self.settings.lightning_password)
      self.exchange.start()

      self.streaming = Streaming()
      self.streaming.start()
      self.ep = self.streaming.get_endpoint(self.settings.symbol, ['ticker', 'executions'])
      self.ep.wait_for(['ticker'])

      self.fx_btc = (self.settings.symbol == 'FX_BTC_JPY')
      if self.fx_btc:
        self.ep_spot = self.streaming.get_endpoint('BTC/JPY', ['ticker'])
        self.ep_spot.wait_for(['ticker'])

      self.ohlcvbuilder = OHLCVBuilder(
        maxlen=self.settings.max_ohlcv_size,
        timeframe=self.settings.timeframe,
        disable_rich_ohlcv=self.settings.disable_rich_ohlcv)

      if 0:
        ep = self.streaming.get_endpoint(self.settings.symbol, ['executions', 'board'])
      else:
        ep = self.streaming.get_endpoint(self.settings.symbol, ['executions'])
      self.exchange.start_monitoring(ep)
      self.monitoring_ep = ep

      if self.yoursetup:
        self.yoursetup(self)

    def start(self):
      self.logger.info("Start Trading")
      self.setup()

      def async_inverval(func, interval, parallels):
        next_exec_time


