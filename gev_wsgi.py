from heimdahl import app
from gevent import pywsgi

print('Serving from http://0.0.0.0:7943')
server = pywsgi.WSGIServer(('0.0.0.0', 7943), app)

server.serve_forever()
