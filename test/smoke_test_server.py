from flask import Flask

from utils.mock_server import get_mocked_server

app = Flask(__name__)
server = get_mocked_server(app)
