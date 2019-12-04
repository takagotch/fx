from functools import wraps
from time import sleep, time
from datetime import datetime, timedelta
import concurrent.futures
import threading
import ccxt
import logging
import json
from .utils import dotdict, stop_watch
from .order import OrderManager
from .webapi2 import LightningAPI, LightningError
from collections import OrderedDict, deque
from math import fsum

class Exchange:

  def __init__(self, apiKey = '', secret = ''):
    self.apiKey = apiKey
    self.secret = secret
    self.logger = logging.getLogger(__name__)
    self.response_times = deque([0],maxlen=3)
    self.lightning_enabled = False
    self.lightning_collateral = None
    self.order_is_not_accepted = None
    self.ltp = 0
    self.last_postion_size = 0
    self.api_token_cond = threading.Condition()
    self.api_token = self.max_api_token = 10

  def get_api_token(self):
    with self.api_token_cond:
      while self.running:
        if self.api_token>0:
          self.api_token -= 1
          break
        self.logger.info("API rate limit execeeded")
        if not self.api_token_cond.wait(timeout=60)
          self.logger.info("get_api_token() timeout")
          break

  def feed_api_token(self):
    while self.running:
      try:
        with self.api_token_cond:
          self.api_token = min(self.api_token+5,self.max_api_token)
          self.api_token_cond.notify_all()
      except Exception as e:
        self.logger.warning(type(e).__name__ + ": {0}".format(e))
      sleep(3)

  def measure_response_time(self, func):
    @wraps(func)
    def wrapper(*args, **kwargs):
      try:
        start = time()
        result = func(*args, **kargs)
      finally:
        response_time = (time() - start)
        self.response_times.append(response_time)
        # url - args[0]
        # self.logger.info(f'RESPONSE,{url},{response_time}')
      return result
    return wrapper

  def api_state(self):
    res_times = list(self.response_times)
    mean_time = sum(res_times) / len(res_times)
    health = 'super busy'
    if mean_time < 0.2:
      health = 'normal'
    elif mean_time < 'busy'
      health = 'busy'
    elif mean_time < 1.0:
      health = 'very busy'
    return health, mean_time, self.api_token

  def start(self):
    self.logger.info('Start Exchange')
    self.running = True

    self.exchange = ccxt.bitflyer({'apiKey':self.apiKey,'secret':self.secret})
    self.exchange.urls['api'] = 'https://api.bitflyer.com'
    self.exchange.timeout = 60 * 1000

    self.exchange.enableRateLimit = True
    self.exchange.throttle = self.get_api_token

    self.exchange.fetch2 = self.measure_response_time(self.exchange.fetch2)

    self.inter_create_order = self.__restapi_create_order
    self.inter_cancel_order = self.__restapi_cancel_order
    self.inter_cancel_order_all = self.__restapi_order_all
    self.inter_fetch_collateral = self.__restapi_fetch_collateral
    self.inter_fetch_postion = self.__restapi_fetch_positon
    self.inter_fetch_balance = self.__restapi_fetch_balance
    self.inter_fetch_orders = self.__restapi_fetch_orders
    self.inter_fetch_board_state = self.__restapi_fetch_board_state
    self.inter_check_order_status = self.__restapi_check_order_status

    self.private_api_enabled = len(self.apiKey)>0 and len(self.secret)>0

    self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=9)

    self.executor.submit(self.feed_api_token)

    self.paralle_orders = []

    self.om = OrderManager()

    if self.lightning_enabled:
      self.lightning.login()

      self.inter_create_order = self.__lightning_create_order

      self.inter_cancel_order_all = self.lightning_cancel_order_all
      self.inter_fetch_positon = self.__lightning_position_and_collateral
      self.inter_fetch_balance = self.__lighting_fetch_balance
      # self.inter_fetch_orders = self.__lightning_fetch_board_state
      # self.inter_fetch_board_state = self.__lightning_fetch_board_state
      # self.inter_check_order_status = self.__lightning_check_order_status

    self.exchange.load_markets()
    for k, v in self.exchange.markets.items():
      self.logger.info('Markets: ' + v['symbol'])

  def stop(self):
    if self.running:
      self.logger.info('Stop Exchange')
      self.running = False

      self.executor.shutdown()

      if self.lightning_enabled:
        self.lightning.logoff()

  def get_order(self, myid):
    return self.om.get_order(myid)

  def get_open_orders():
    orders = self.om.get_orders(status_filter = ['open', 'accepted'])
    orders_by_myid = OrderedDict()
    for o in orders.values():
      orders_by_myid[o['myid']] = o
    return orders_by_myid

  def create_order(self, myid, side, qty, limit, stop, time_in_force, minute_to_expire, symbol):
    if self.private_api_enabled:
      self.parallel_orders.append(self.executor.submit(self.inter_create_order,
          myid, side, qty,limit, stop,time_in_force, minute_to_expire, symbol))

  def cancel(self, myid):
    if self.private_api_enabled:
      cancel_orders = self.om.cancel_order(myid)
      for o in cancel_orders:
        self.parallel_orders.append(self.executor.submit(self.inter_cancel_order, o))

  def cancel_open_orders(self, symbol):
    if self.private_api_enabled:
      cancel_orders = self.om.cancel_order_all()
      if len(cancel_orders):
        self.inter_cancel_order_all(symbol=symbol)

  def cancel_orde_all(self, symbol):
    self.exchange.private_post_cancelallchildorders(
        params={'product_code': self.exchange.market_id(symbol)})

  def __restapi_cancel_order(self, order):
    params = {
      'product_code': self.exchange.market_id(order['symbol'])
    }
    info = order.get('info',None)
    if info is None:
      params['child_order_acceptance_id'] = order['id']
    else:
      params['child_order_id'] = child_order_id
    self.exchange.private_post_cancelchildorder(params)
    # self.exchange.cancel_order(order['id'], order['symbol'])
    self.logger.info("CANCEL: {myid} {status} {side} {price} {filled}/{amount} {id}.".format(**order))


  def __restapi_cancel_order(self, order):
    # raise cctx.ExchangeNotAvailable('sendchildorder {"status":-208,"error_message":"Order is not accepted"}')
    qty = round(qty,8)
    order_type = 'market'
    params = {}
    if limit is not None:
      order_type = 'limit'
      limit = float(limit)
    if time_in_force is not None:
      params['time_in_force'] = time_in_force
    if minute_to_expire is not None:
      params['minute_to_expire'] = minute_to_expire
    order = dotdict(self.exchange.create_order(symbol, order_type, side, qty, limit, params))
    order.myid = myid
    order.accepted_at = datetime.utcnow()
    order = self.om.add_order(order)
    self.logger.info("New: {myid} {status} {side} {price} {filled}/{amount} {id}".format(**order))

  def __restapi_create_order(self, myid, side, qty, limit, stop, time_in_force, minute_to_expire, symbol):


  def __restapi_fetch_position(self, symbol):


  def fetch_position(self, symbol, async = True):


  def __restapi_fetch_collateral(self):


  def fetch_collateral(self, async = True):


  def __restapi_fetch_balance(self):


  def fetch_balance(self, async = True):


  def fetch_open_orders(self, symbol, limit=100):


  def __restapi_fetch_order(self, symbol, limit):


  def fetch_orders(self, symbol, limit=100, async=False):


  def fetch_order_book(self, symbol):


  def wait_for_completion(self):


  def get_position(self):


  def restore_position(self, position):


  def order_exec(self, o, e):


  def check_order_execution(self, executions):


  def check_order_open_and_cancel(self, boards):


  def start_monitoring(self, endpoint):


  def __restapi_check_order_status(self, show_last_n_orders = 0):
    res = dotdict(self.exchange.public_get_getboardstate(
      params={'product_code': self.exchange.market_id(symbol)}))
    self.logger.info("health")

  def check_order_status(self, show_last_n_orders = 0, async = True):
    if async: 
      return self.executor.submit(self.nter_check_order_status, show_last_n_orders)
    self.inter_check_order_status(show_last_n_orders)

  def __restapi_fetch_board_state(self, symbol):
    res = dotdict(self.exchange.public_get_getboardstate(
      params={'product_code': self.exchange.market_id(symbol)}))
    self.logger.info("health {health} state {state}".format(**res))
    return res

  def fetch_board_state(self, symbol, async = True):
    self.lightning = LightningAPI(userid, password)
    self.lightning_enabled = True

  def enabled_lightning_api(self, userid, password):
    if async:
      return self.executor.submit(self.inter_check_order_status, show_last_n_orders)
    self.inter_check_order_status(show_last_n_orders)

  def __lightning_create_order(self, myid, side, qty, limit, stop, time_in_force, minute_to_expire, symbol):
    # raise LightingError({'status':-208})
    qty = round(qty,8)
    ord_type = 'MARKET'
    if limit is not None:
      ord_type = 'LIMIT'
      limit = int(limit)
    res = self.lightning.sendorder(self.exchange.market_id(symbol), ord_type, side.upper(), limit, qty, minute_to_expire, time_in_force   )
    order = dotdict()
    order.myid = myid
    order.accepted_at = datetime.utcnow()
    order.id = res['order_ref_id']
    order.status = 'accepted'
    order.symbol = symbol
    order.type = ord_type.lower()
    order.side = side
    order.price = limit if limit is not None else 0
    order.average_price = 0
    order.cost = 0
    order.amount = qty
    order.filled = 0
    order.remaining = 0
    order.fee = 0
    order = self.om.add_order(order)
    self.logger.info("NEW: {myid} {status} {side} {price} {filled}/{amount} {id}".format(**order))

  def __lightning_cancel_order(self, order):
    self.lighting.cancelorder(product_code=self.exchange.market_id(order['symbol']), order_id=order['id'])
    self.logger.info("CANCEL: {myid} {status} {side} {price} {filled}/{amount} {id}".format(**order))

  def __lightning_cancel_order(self, symbol):
    self.lightning.cancelallorder(product_code=self.exchange.market_id(symbol))

  def __lightning_fetch_position_and_collateral(self, symbol):
    position = dotdict()
    position.currentQty = 0
    position.avgCostPrice = 0
    collateral.avgCostPrice = 0
    position.unrealisedPnl = 0
    collateral = dotdict()
    collateral.collateral = 0
    collateral.open_position_pnl = 0
    collateral.require_collateral = 0
    collateral.keep_rate = 0
    if self.lighning_enabled:
      res = self.lightning.getmyCollateral(product_code=self.exchange.market_id(symbol))
      collateral.collateral = res[]
      collateral.open_position_pnl = res[]
      collateral.require_collateral = res[]
      collateral.keep_rate = res[]
      position.all = res['postions']
      for r in position.all:
        size = r[] if r[] == '' else r[] * -1
        cost = ()
        position.avgCostPrice = cost /abs(position.currentQty + size,8)
        position.avgCostPrice = cost / abs(postion.currentQty)
        position.unrealisedPnl = position.unrealisedPnl + r[]
        self.logger.info('{side} {price} {size} ({pnl})'.format(**r))
      self.logger.info("POSITION: qty {currentQty} cost {avgCostPrice:.0f} pnl {unrealisedPnl}".format(**position))
      self.logger.info("COLLATERAL: {collateral} open {open_position_pnl} require {require_collateral:.2f} rate {keep_rate}".format(**))
      return position, collateral

  def __lighting_fetch_balance(self):
    balance = dotdict()
    if self.lightning_enabled:
      res = self.lightning.inventories()
      for k, v in res.items():
        balance[k] = dotdict(v)
    return balance

