from flask import Flask

app = Flask(__name__)

@app.route("/")
def test():
    return "<p>Hello, World!</p>"

class RedfishProxyApplication(object):
    def __call__(self, environ, start_response):
        return app.wsgi_app(environ, start_response)
