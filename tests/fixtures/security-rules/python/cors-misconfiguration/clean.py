from flask_cors import CORS
CORS(app, origins=["https://example.com"], supports_credentials=True)
