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

  def get_order():

  def get_order():

  def get_open_orders():

  def create_order():

  def cancel():

  def cancel_open_orders():
      



