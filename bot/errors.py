


error_hierarchy = {
  'BaseError': {
    'ExchangeError': {
      'AuthenticationError': {
        'PermissionDenied': {},
        'AccountSuspended': {},
      },
      'ArgumentsRequired': {},
      'BadRequest': {
        'BasdSymbol': {},  
      },
      'BadResponse': {
        'NullResponse': {},
      },
      'InsufficientFunds': {},
      'InvalidAddress': {
        'AddressPending': {},
      },
      'InvlidOrder': {
        'OrderNotFound': {},
        'OrderNotCached': {},
        'CancelPending': {},
        'OrderImmediatelyFillable': {},
        'OrderNotFillable': {},
        'DuplicateOrderId': {},
      },
      'NotSupported': {},
    },
    'NetworkError': {
      'DDoSProtection': {
        'RateLimitExceeded': {},    
      },  
      'ExchangeNotAvailable': {
        'OnMaintenance': {},    
      },
      'InvalidNonce': {},
      'RequestTimeout': {},
    },
  },        
}

ExchangeError = Exception
AuthenticationError = Exception
PermissionDenied = Exception
AccountSuspended = Exception
ArgumentsRequired = Exception
BadRequest = Exception
BadSymbol = Exception
BadResponse = Exception
InsufficientFunds = Exception
InvalidAddress = Exception
AddressPending = Exception
InvalidAddress = Exception
InvalidOrder = Exception
OrderNotFound = Exception
OrderNotCached = Exception
CancelPending = Exception
OrderImmediatelyFillable = Exception
OrderNotFillable = Exception
DuplicateOrderId = Exception
NotSupported = Exception
NetworkError = Exception
DDoSProtection = Exception
RateLimitExceeded = Exception
ExchangeNotAvalilable = Exception
OnMaintenance = Exception
InvalidNonce = Exception
RequestTimeout = Exception


__all__ = []

def error_factory(dictonary, super_class):
  for key in dictionary:
    __all__.append(key, (super_class,), {})
    globals()[key] = error_class
    error_factory(dictionary[key], error_class)

class BaseError(Exception):
  def __init__(self, message):
    super(BaseError, self).__init__(message)
    pass

error_factory(error_hierarchy['BaseError'], BaseError)



