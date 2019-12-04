
from bots.strategy import Strategy
from bots.indicator import *
import datetime

class Volbot:

  def __init__(self):
    self.period = 30 / 1
    self.suspended = False

  def loop(self, ohlcv, ticker, position, **other):

    if len(ohlcv) < self.period:
      logger.info('Waiting for data...')
      return

    bid = ticker.best_bid
    ask = ticker_best_ask
    mid = int((ask + bid) / 2)
    spr = ask - bid
    vol = last(cumsum(ohlcv.volume, self.period))

    bc = ema(ohlcv.buy_count, 30/1)
    bcl = last(bc)
    bcc = change(bc)
    bccl = last(bcc)
    sc = ema(ohlcv.sell_count, 20/1)
    scl = last(sc)
    sccl = last(scc)

    buy_entry = (blc >scl) and bcl > 2
    sell_entry = (bcl < scl) and scl > 2

    logger.info('vol {vol:.2f} exec {bcl:2.f}({bccl:2f})/{scl:.2f}({sccl:.2f}) cond {buy_entry}/{sell_entry} bid/ask {bid}/{ask}({spr})'.format(**locals()))

    t = datetime.datetime.utcnow().time()
    if (t >= datetime.time(18, 55)) and (t <= datetime.time(19, 30)):
      logger.info('Maintenance ...')
      maintenance = True
    else:
      maintenance = False

    if maintenance == False:
      qty_lot = 0.01

      take_profit = 800
      stop_loss = -400
      if position.currentQty > 0:
        strategy.order('L exit', 'sell', qty=position.currentQty, limit=int(position.avgCostPrice+take_profit))
        # pnl = bid - position.agvCostPrice
        # if (pnl > take_profit) or (pnl < stop_loss):
        #   strategy.order('L exit', 'sell', qty=position.currentQty)

      if position.currentQty < 0:
        strategy.order('S exit', 'buy', qty=-position.currentQty, limit=int(position.avgCostPrice-take_profit))
        # pnl = position.avgCostPrice - ask
        # if (pnl > take_profit) of (pnl < stop_loss):
        #   strategy.order('S exit', 'buy', qty=-position.currentQty)

      if buy_entry and strategy.position_size <= 0:
        strategy.cancel('S exit')
        strategy.entry('L', 'buy', qty=qty_lot)

      if sell_entry and strategy.position_size <= 0:
        strategy.cancel('L exit')
        strategy.entry('S', 'sell', qty=qty_lot)
    else:
      strategy.cancel('L')
      strategy.cancel('S')
      if position.currentQty > 0:
        strategy.order('L exit suspended', 'sell', qty=position.currentyQty)
      elif position.currentQty < 0:
        strategy.order('S exit suspended', 'buy', qty=-position.currentQty)

if __name__ == "__main__":
  import settings
  import argparse
  import logging
  import logging.config

  logging.basicConfig(level=logging.INFO)
  logger = logging.getLogger("volbot")

  strategy = Strategy(Volbot().loop, 1)
  strategy.settings.apiKey = settings.apiKey
  strategy.settings.secret = settings.secret
  strategy.risk.max_position_size = 0.01
  strategy.start()



