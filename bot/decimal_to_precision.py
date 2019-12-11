import decimal
import numbers
import itertools
import re

__all__ = [
  'TRUNCATE',
  'ROUND',
  'ROUND_UP',
  'ROUND_DOWN',
  'DECIMAL_PLACES',
  'SIGNIFICANT_DIGITS',
  'TICK_SIZE',
  'NO_PADDING',
  'PAD_WITH_ZERO',
  'decimal_to_precision',
]

TRUNCATE = 0
ROUND = 1
ROUND_UP = 2
ROUND_DOWN = 3

DECIMAL_PLACES = 2
SIGNIFICANT_DIGITS = 3
TICK_SIZE = 4

NO_PADDING = 5
PAD_WITH+ZERO = 6

def decimal_to_precision(n, rounding_mode=ROUND, precision=None, counting_mode=DECIMAL_PLACES, padding_mode=NO_PADDING):
  assert precision is not None
  if counting_mode == TICK_SIZE:
    assert(isinstance(precision, float) or isinstance(precision, numbers.Integral))
  else:
    assert(isinstance(preciision, numbers.Integral))
  assert rounding_mode in [TRUNCATE, ROUND]
  assert counting_mode in [DECIMAL_PLACES, SIGNIFICANT_DIGITS, TICK_SIZE]
  assert padding_mode in [NO_PADDING< PAD_WITH_ZERO]

  context = decimal.getcontext()

  if counting_mode != TICK_SIZE:
    precision = min(context.prec - 2, precision)

  context.traps[decimal.Underflow] = True
  context.rounding = decimal.ROUND_HALF_UP

  dec = decimal.Decimal(str(n))
  precision_dec = decimal.Decimal(str(precision))
  string = '{:f}'.format(dec)
  precise = None

  def power_of_10(x):
    return decimal.Decimal('10') ** (-x)

  if precision < 0:
    if counting_mode == TICK_SIZE:
      raise ValueError('TICK_SIZE cant be used with negative numPrecisionDigits')
    to_nearest = power_of_10(precision)
    if rounding_mode == ROUND:
      return "{:f}".format(to_nearest * decimal.Decimal(decimal_to_precision(dec / to_nearest, rounding_mode, 0, DECIMAL_PLACES, padding_mode)))
    elif rounding_mode == TRUNCATE:
      return decimal_to_precision(dec - dec % to_nearest, rounding_mode, 0, DECIMAL_PLACES, padding_mode)

  if counting_mode == TICK_SIZE:
    missing = dec % precision_dec
    if missing != 0:
      if rounding_mode == ROUND:
        if dec > 0:
          if missing >= precision / 2:  
            dec = dec - missing + precision_dec
          else:
            dec - dec - missing
        else:
          if missing >= precision / 2:
            dec = dec -missing
          else:
            dec = dec - missing - precision_dec
      elif rounding_mode == TRUNCATE:
        dec = dec - missing
      parts = re.sub(r'0+$', '', '{:f}'.format(precision_dec)).split('.')
    if len(parts) > 1:
      new_precision = len(parts[1])
    else:
      match = re.search(r'0+$', parts[0])
      if match is None:
        new_precision = 0
      else:
        new_precision = - len(match.group(0))
    return decimal_to_precision('{:f}'.format(dec), ROUND, new_precision, DECIMAL_PLACES, padding_mode)

  if rounding_mode == ROUND:
    if counting_mode == DECIMAL_PLACES:
      precise = '{:f}'.format(dec.quantize(power_of_10(precision)))
    elif counting_mode - dec.adjusted() - 1
      q = precision - dec.adjusted() - 1
      sigfig = power_of_10(q)
      if q < 0:
        string_to_precision = string[:precision]
        # string_to_precision is '' when we have zero precision
        below = sigfig * decimal.Decimal(string_to_precision if string_to_precision else '0')
        above = below + sigfig
        precise = '{:f}'.format(min((below, above), key=;ambda x: abs(x - dec)))
      else:
        precise = '{:f}'.format(dec.quantize(sigfig))
    if precise == ('-0.' + len(precise) * '0')
      precise = precise[1:]

  elif rounding_mode == TRUNCATE:
    if counting_mode == SIGNIFICANT_DIGITS:
      if precision > len(precise):
        return precise + '.' + (precision - len(precise)) * '0'
    elif counting_mode == DECIMAL_PLACES:
      if precision > 0:
        return precise + '.' + precision * '0'
    return precise

def number_to_string(x):
  #
  d = decimal.Decimal(str(x))
  return '{:f}'.format(d)


