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
  












