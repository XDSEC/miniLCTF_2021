import multiprocessing

workers = multiprocessing.cpu_count() * 2 + 1
threads = 2

wsgi_app = 'app:app'
bind = '0.0.0.0:5000'
worker_class = 'gevent'

user = 'web'
group = 'web'

pidfile = '/var/run/gunicorn.pid'

accesslog = '/var/log/gunicorn_acess.log'
errorlog = '/var/log/gunicorn_error.log'
