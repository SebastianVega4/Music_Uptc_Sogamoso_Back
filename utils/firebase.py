import firebase_admin
from firebase_admin import credentials, firestore
import os

# Variables globales
_firebase_app = None
_db = None

def initialize_firebase():
    global _firebase_app, _db
    try:
        if _firebase_app is None:
            # Configuración desde variables de entorno
            private_key = os.environ.get("FIREBASE_PRIVATE_KEY", "")
            
            if not private_key:
                raise ValueError("FIREBASE_PRIVATE_KEY no encontrada en las variables de entorno")
            
            # Construir el objeto de configuración completo
            firebase_config = {
                "type": "service_account",
                "project_id": os.environ.get("FIREBASE_PROJECT_ID"),
                "private_key_id": os.environ.get("FIREBASE_PRIVATE_KEY_ID", ""),
                "private_key": private_key.replace('\\n', '\n'),
                "client_email": os.environ.get("FIREBASE_CLIENT_EMAIL"),
                "client_id": os.environ.get("FIREBASE_CLIENT_ID", ""),
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_x509_cert_url": os.environ.get(
                    "FIREBASE_CLIENT_CERT_URL", 
                    f"https://www.googleapis.com/robot/v1/metadata/x509/{os.environ.get('FIREBASE_CLIENT_EMAIL', '').replace('@', '%40')}"
                ),
                "universe_domain": "googleapis.com"
            }
            
            # Filtrar campos vacíos opcionales
            firebase_config = {k: v for k, v in firebase_config.items() if v}
            
            cred = credentials.Certificate(firebase_config)
            _firebase_app = firebase_admin.initialize_app(cred)
            _db = firestore.client()
            print("✅ Firebase inicializado correctamente")
        
        return _firebase_app, _db
    except Exception as e:
        print(f"🔥 Error inicializando Firebase: {str(e)}")
        raise

def get_firebase():
    if _firebase_app is None or _db is None:
        return initialize_firebase()
    return _firebase_app, _db

def get_db():
    if _db is None:
        initialize_firebase()
    return _db

# Inicialización inmediata al importar el módulo
try:
    firebase_app, db = initialize_firebase()
except Exception as e:
    print(f"⚠️  No se pudo inicializar Firebase al importar: {str(e)}")
    firebase_app, db = None, None