#

from ccxt.foxbit import foxbit

class vbtc(foxbit):
  
  def describe(self):
    return self.deep_extend(super(vbtc, self).describe(), {
      'id': 'vbtc',
      'name': 'VBTC',
      'countries': ['VN'],
      'has': {
        'CORS': False,
      },
      'urls': {
          'logo': 'https://user-images.githubsercontent.com/1111111/xxx.jpg',
        'api': {
          'public': 'https://vbtc.blinktrade.com/api',
          'private': 'https://api.blinktrade.com/tapi',
        },
        'www': 'https://api.blinktrade.com/api',
        'doc': 'https://api.blinktrade.com/tapi',
      },
      'options': {
        'brokerId': '3',    
      },
    })

