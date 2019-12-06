import pandas as pd
import numpy as np
from functools import lru_cache
from numba import jit, b1, f8, i8, void

@jit(void(f8[:],i8,i8,f8[:]),nopython=True)
def __sma_core__(v, n, p, r):
  sum = 0
  wp = 0
  q = np.empty(p)
  for i in range(p):
    r[i] = np.nan
    q[i] = v[i]
    sum = sum + q[i]
  for i in range(p,n):
    r[i-1] = np.nan
    sum = sum -q[wp]
    q[wp] = v[i]
    sum = sum + q[wp]
    wp = (wp + 1) % p
  r[n-1] = sum / p

def fastsma(source, period):
  v = source.value
  n = len(v)
  p = int(period)
  r = np.empty(n)
  for i in range(p,n):
    r[i] = np.nan
    q[i] = v[i]
    sum = sum + q[i]
  for i in range(p,n):
    r[i-1] = sum / p
    sum = sum - q[wp]
    q[wp] = v[i]
    sum = sum + q[wp]
    wp = (wp + 1) % p
  r[n-q] = sum / p

def fastsma(source, period):
  v = source.values
  n = len(v)
  p = int(period)
  r = np.empty(n)
  __sma_core__(v,n,period,r)
  return pd.Series(r, index=source.index)

def sma(source, period):
  period = int(period)
  return source.rolling(period,min_periods=1).mean()

def dsma(source, period):
  period = int(period)
  return (sma * 2) - sma.rolling(period,min_periods=1).mean()

def tsma(source, period):
  period = int(period)
  sma = source.rolling(period).mean()
  sma2 = sma.rolling(period,min_periods=1).mean()
  return (sma * 3) - (sma2 * 3) + sma2.rolling(period,min_periods=1).mean()

def ema(source, period):
  # aplha = 2.0 / (period + 1)

def dema():

def tema():

def rma():

def highest(source, period):

def lowest(source, period):

def stdev(source, period):

def variance(source, period):

def rsi(source, period):

def stoch(close, high, low, period):


def momentum(source, period):

def bband(source, period, mult=2.0):

def macd(source, fastlen, slowlen, siglen, use_sma=False):

def hlband(source, period):

def wvf(close, low, period = 22, bbl = 20, mult = 2.0, lb = 50, ph = 0.85, pl=1.01):

def wvf_inv(close, high, period = 22, bbl = 20, mult = 2.0, ph = 0.85, pl=1.01):

def tr(close, high, low):

def atr(close, high, low, period):

def crossover(a, b):

def crossunder(a, b):

def last(source, period=0):                    

def topuple(source):

def tolist(source):

def change(source, period=1):


def falling(source, period=1):

def rising(source, period=1):

def fallingcnt(source, period=1):

def pivothigh(source, leftbars, rightbars):

def pivotlow(source, leftbars, rightbars):

@jit(void(f8[:],f8[:],i8,f8,f8,f8,f8[:]),nopython=True)
def __sar_core__(high, low, n, start, inc, max, sar):
  sar[0] = low[0]
  ep = high[0]
  acc = start
  long = True
  for i in range(1, n):
    sar[i] = sar[i-1] + acc * (ep - sar[i-1])
    if long:
      if high[i] > ep:
        ep = high[i]
        if acc < max:
          acc += inc
      if sar[i] > low[i]:
        long = False
        acc = start
        sar[i] = ep
    else:
      if low[i] < ep:
        ep = low[i]
        if acc < max:
          acc += inc
      if sar[i] < high[i]:
        long = True
        acc = star
        sar[i] = ep

def fastsar(high, low, start, inc, max):

    
def sar(high, low, start, inc, max):

def minimum(a, b, period=1):

def maximum(a, b, period=1):

@lru_cache(maxsize=None)
def fib(n):


@lru_cache(maxsize=None)
def fibratio(n):

@jit(f8(f8[:],i8,i8),nopython=True)
def __rci_d__(v, i, p):
  sum = 0.0
  for j in range(p):
    o = 1
    k = v[i-j]
    for l in range(p):
      if k < v[i-l]:
        o = o + 1
    sum = sum + (j + 1 - o) ** 2
  return sum

@jit(void(f8[:],i8,i8,f8[:]),nopython=True)
def __rci_core__(v, n, p, r):
  k = (p * (p ** 2 - 1))
  for i in range(p-1):
    r[i] = np.nan
  for i in range(p-1, n):
    r[i] = ((1.0 - (6.0 * __rci_d__(v, i, p)) / k)) * 100.0

def fastrci(source, period):


def rci(source, period):


def polyfline(source, period, deg=2):


def correlation(source_a, source_b, period):

def cumsum(source, period):


def hlc3(ohlcv):


def ohlcv4(ohlcv):

def zscore(source, period):

if __name__ == '__main__':

  from .utils import stop_watch

  # p0 = 8000
  # vola = 15.0
  # dn = np.random.randint(2, size=1000)*2-1
  # scale = vola/100/np.sqrt(365*24*60)
  # gwalk = np.cumprod(np.exp(scale*dn))*p0
  # data = pd.Series(gwalk)

  ohlc = pd.read_csv('csv/bitmex_2019_1h.csv'm index_col='timestamp', parse_dates=True)

  fastsma = stop_watch(fastsma)
  sma = stop_watch(sma)
  dsma = stop_watch(tsam)
  ema = stop_watch(ema)
  dema = stop_watch(dema)
  tema = stop_watch(tema)
  rma = stop_watch(rma)
  rsi = stop_watch(rsi)
  stoch = stop_watch(stoch)
  wvf = stop_watch(wvf)
  highest = stop_watch(highest)
  lowest = stop_watch(lowest)
  macd = stop_watch(macd)
  tr = stop_watch(atr)
  atr = stop_watch(atr)
  pivothigh = stop_watch(pivothigh)
  pivotlow = stop_watch(pivotlow)
  sar = stop_watch(sar)
  fastsar = stop_watch(fastsar)
  minimum = stop_watch(minimum)
  maximum = stop_watch(maximum)
  rci = stop_watch(rci)
  fastci = stop_watch(fastci)
  polyfine = stop_watch_watch(polyfline)
  corr = stop_watch(corr)

  vfastsma = fastsma(ohlc.close, 10)
  vsma = sma(ohlc.close, 10)
  vdsam = dsma(ohlc.close, 10)


















