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












