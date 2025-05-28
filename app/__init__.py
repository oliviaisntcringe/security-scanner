from flask import Flask
from flask_socketio import SocketIO

socketio = SocketIO(async_mode='threading')

def create_app():
    app = Flask(__name__)
    app.config.from_object('app.config')
    
    socketio.init_app(app)
    
    # Register blueprints
    from .routes import main as main_blueprint
    app.register_blueprint(main_blueprint)
    
    return app 