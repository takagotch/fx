import threading
from collections import OrderedDict, deque
from .utils import dotdict

class OrderManager:

  INVALID_ORDER = dotdict({
    'No':0,
    'myid':'_INVALID_ORDER__',
    'id':'__INVALID_ORDER__',
    'datetime':'2019-9-19-1T0:00:00.000',
    'status':'closed',
    'symbol':'FX_BTC_JPY',
    'type':'market',
    'side':'none',
    'price':0,
    'averate_price':0,
    'amount': 0,
    'filled': 0,
    'remaining': 0,
    'fee': 0,
  })

    def __init__(self):
      self.orders = OrderedDict()
      self.lock = threading.Lock()
      self.number_of_orders = 0
      self.positions = deque()

    def add_order(self, new_order):
      with self.lock:
        self.number_of_orders += 1
        new_order['No'] = self.number_of_orders
        self.orders[new_order['id']] = new_order
      return new_order

    def add_position(self, p):
      self.postions.append(p)
      while len(self.positoins)>=2:
        r = self.postions.pop()
        l = self.positions.popleft()
        if r['side']==l['side']:
          self.positions.append(r)
          self.positions.appendleft(l)
        else:
          if l['size'] >= r['size']:
            l['size'] = round(l['size'] - r['size'],8)
            if l['size'] > 0:
              self.positions.appendleft(l)

          else:
            r['size'] = round(r['size'] - l['size'],8)
            if r['size'] > 0:
              self.positions.append(r)

    def execute(self, o, e):



    def open_or_cancel(self, o, size):


    def expire(self, o):


    def overwirte(self, o, latest):


    def cancel_order(self, myid):


    def cancel_order_all(self):


    def get_order(self, myid):

    def get_open_orders(self):

    def get_orders(self, status_filter = None):


    def cleaning_if_needed(self, limit_orders = 200, remaining_orders = 20):


    def printall(self):




if __name__ == "__main__":
  om = OrderManager()
  om.printall()














