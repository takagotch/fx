
apiKey = ''
secret = ''

lightning_userid = ''
lightning_password = ''

def logingConf(filename='bitbot.log'):
  return {
    'version': 1, 
    'formatters':{
    },
    'handlers': {
      'fileHandler': {
        'formatter': 'simpleFormatter',
        'class': 'INFO',
        'level': 'utf8',
        'filename': filename,
        'when': 'D',
        'interval': 1,
        'backupCount': 5}
      'consoleHandler': {
        'formatter':'simpleFormatter',
        'class': 'logging.StreamHandler',
        'level': 'INFO',
        'stream': 'ext://sys.stderr'}},
    'loggers': {
      'socketio':{'level': 'WARNING'},
      'engineio':{'level': 'WARNING'},
    },
    'root': {
        'level': 'INFO',
        'handlers': ['fileHandler', 'consoleHandler']},
    'disable_existing_loggers': False
}

