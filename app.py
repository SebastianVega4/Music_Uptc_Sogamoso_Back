from flask import Flask, request, jsonify
from flask import redirect
from flask_cors import CORS
import os
import spotipy
from spotipy.oauth2 import SpotifyClientCredentials
import hashlib
import threading
import time
import requests
from datetime import datetime, timedelta , timezone

app = Flask(__name__)

# Configuración CORS simplificada
allowed_origins = [
    "https://4200-firebase-musicuptcsogamoso-1757187604448.cluster-dwvm25yncracsxpd26rcd5ja3m.cloudworkstations.dev",
    "https://music-uptc-sogamoso.vercel.app",
    "https://sebastianvega4.github.io",
    "http://localhost:4200",
    "https://9000-firebase-musicuptcsogamoso-1757187604448.cluster-dwvm25yncracsxpd26rcd5ja3m.cloudworkstations.dev"
]

# Configuración CORS - debe venir antes de cualquier definición de ruta
CORS(app, origins=allowed_origins, supports_credentials=True)

@app.after_request
def after_request(response):
    """Añadir headers CORS a todas las respuestas"""
    origin = request.headers.get('Origin')
    if origin in allowed_origins:
        response.headers.add('Access-Control-Allow-Origin', origin)
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# Importar utilidades de Firebase PRIMERO
try:
    from utils.firebase import initialize_firebase, get_db
    from firebase_admin import auth, firestore
    firebase_available = True
    print("✅ Módulos de Firebase importados correctamente")
except ImportError as e:
    print(f"⚠️  No se pudieron importar módulos de Firebase: {e}")
    firebase_available = False
    db = None
except Exception as e:
    print(f"⚠️  Error al importar Firebase: {e}")
    firebase_available = False
    db = None

# Inicializar Firebase solo si está disponible
if firebase_available:
    try:
        firebase_app, db = initialize_firebase()
        print("✅ Firebase inicializado correctamente")
    except Exception as e:
        print(f"❌ Error inicializando Firebase: {e}")
        firebase_available = False
        db = None
else:
    db = None

# Variables globales para Spotify OAuth
SPOTIFY_CLIENT_ID = os.environ.get("SPOTIFY_CLIENT_ID")
SPOTIFY_CLIENT_SECRET = os.environ.get("SPOTIFY_CLIENT_SECRET")
SPOTIFY_REDIRECT_URI = os.environ.get("SPOTIFY_REDIRECT_URI", "https://music-uptc-sogamoso.vercel.app/api/spotify/callback")

spotify_tokens = {}  # Para usuarios regulares

# Variables para el admin de Spotify
admin_spotify_token = None
currently_playing_cache = None
cache_expiration = None
polling_thread = None
polling_active = False

# Configurar Spotify para búsquedas
try:
    sp = spotipy.Spotify(auth_manager=SpotifyClientCredentials(
        client_id=os.environ.get("SPOTIFY_CLIENT_ID"),
        client_secret=os.environ.get("SPOTIFY_CLIENT_SECRET")
    ))
    print("✅ Spotify configurado correctamente")
except Exception as e:
    print(f"❌ Error configurando Spotify: {e}")
    sp = None

# Middleware simplificado para OPTIONS
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = jsonify()
        response.headers.add("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, OPTIONS")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization")
        response.headers.add("Access-Control-Allow-Credentials", "true")
        return response
    
def start_spotify_polling():
    """Iniciar polling para la canción actual del admin"""
    global polling_active
    polling_active = True
    
    def poll_spotify():
        global currently_playing_cache, cache_expiration
        while polling_active:
            try:
                if not admin_spotify_token or not admin_spotify_token.get('access_token'):
                    print("⚠️  No hay token de Spotify para polling")
                    time.sleep(10)
                    continue
                
                # Verificar si el token necesita refresco - usar UTC
                if datetime.now(timezone.utc) > admin_spotify_token['expires_at']:
                    if not refresh_admin_spotify_token():
                        print("❌ No se pudo refrescar el token de Spotify")
                        time.sleep(30)
                        continue
                
                # Obtener la canción actual
                access_token = admin_spotify_token['access_token']
                headers = {'Authorization': f'Bearer {access_token}'}
                response = requests.get(
                    'https://api.spotify.com/v1/me/player/currently-playing', 
                    headers=headers,
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data['is_playing']:
                        track = data['item']
                        currently_playing_cache = {
                            'is_playing': True,
                            'name': track['name'],
                            'artists': [artist['name'] for artist in track['artists']],
                            'album': track['album']['name'],
                            'image': track['album']['images'][0]['url'] if track['album']['images'] else None,
                            'preview_url': track['preview_url'],
                            'duration_ms': track['duration_ms'],
                            'progress_ms': data['progress_ms'],
                            'id': track['id']
                        }
                        print(f"🎵 Reproduciendo: {currently_playing_cache['name']}")
                    else:
                        currently_playing_cache = {'is_playing': False}
                        print("⏸️  Spotify en pausa")
                    
                    # Cachear por 10 segundos - usar UTC consistentemente
                    cache_expiration = datetime.now(timezone.utc) + timedelta(seconds=10)
                elif response.status_code == 204:
                    currently_playing_cache = {'is_playing': False}
                    cache_expiration = datetime.now(timezone.utc) + timedelta(seconds=10)
                    print("⏸️  No se está reproduciendo nada")
                else:
                    print(f"❌ Error en API de Spotify: {response.status_code}")
                    currently_playing_cache = {'error': f"HTTP {response.status_code}"}
            except Exception as e:
                print(f"❌ Error en polling de Spotify: {e}")
                currently_playing_cache = {'error': str(e)}
            
            time.sleep(5)  # Esperar 5 segundos entre consultas
    
    # Iniciar el hilo de polling
    thread = threading.Thread(target=poll_spotify)
    thread.daemon = True
    thread.start()
    print("✅ Hilo de polling iniciado")
    return thread

def ensure_aware_datetime(dt):
    """Asegurar que un datetime sea timezone-aware (UTC)"""
    if isinstance(dt, str):
        # Convertir string a datetime
        if 'Z' in dt:
            dt = dt.replace('Z', '+00:00')
        return datetime.fromisoformat(dt)
    elif dt.tzinfo is None:
        # Si es naive, convertirlo a aware (UTC)
        return dt.replace(tzinfo=timezone.utc)
    else:
        # Ya es aware, retornar tal cual
        return dt
    
def refresh_admin_spotify_token():
    """Refrescar el token de Spotify del admin"""
    global admin_spotify_token
    
    if not admin_spotify_token or 'refresh_token' not in admin_spotify_token:
        return False
        
    refresh_token = admin_spotify_token['refresh_token']
    token_url = "https://accounts.spotify.com/api/token"
    
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': SPOTIFY_CLIENT_ID,
        'client_secret': SPOTIFY_CLIENT_SECRET
    }
    
    response = requests.post(token_url, data=data)
    if response.status_code != 200:
        return False
        
    token_data = response.json()
    admin_spotify_token['access_token'] = token_data['access_token']
    
    # Usar UTC consistentemente - asegurar que ambas fechas sean aware
    admin_spotify_token['expires_at'] = datetime.now(timezone.utc) + timedelta(seconds=token_data['expires_in'])
    
    if 'refresh_token' in token_data:
        admin_spotify_token['refresh_token'] = token_data['refresh_token']
        
    # Guardar en base de datos si está disponible
    if firebase_available and db:
        try:
            db.collection('admin_settings').document('spotify').set({
                'token_data': admin_spotify_token,
                'updated_at': firestore.SERVER_TIMESTAMP
            })
        except Exception as e:
            print(f"Error guardando token en BD: {e}")
            
    return True

# Nuevo endpoint para obtener la canción actual del admin
@app.route('/api/spotify/admin/currently-playing', methods=['GET'])
def get_admin_currently_playing():
    """Obtener la canción actualmente en reproducción del admin"""
    global currently_playing_cache, cache_expiration
    
    # Verificar si tenemos caché válida - ambos deben ser aware
    if currently_playing_cache and cache_expiration:
        if cache_expiration:
            cache_expiration = ensure_aware_datetime(cache_expiration)
        if datetime.now(timezone.utc) < cache_expiration:
            return jsonify(currently_playing_cache), 200
    
    # Si no hay caché o está expirada, intentar obtener datos
    if admin_spotify_token and admin_spotify_token.get('access_token'):
        # Verificar si el token necesita refresco - usar UTC consistentemente
        if datetime.now(timezone.utc) > admin_spotify_token['expires_at']:
            if not refresh_admin_spotify_token():
                return jsonify({"error": "Token de Spotify expirado"}), 401
        
        # Obtener la canción actual
        access_token = admin_spotify_token['access_token']
        headers = {'Authorization': f'Bearer {access_token}'}
        response = requests.get(
            'https://api.spotify.com/v1/me/player/currently-playing', 
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            if data['is_playing']:
                track = data['item']
                currently_playing_cache = {
                    'is_playing': True,
                    'name': track['name'],
                    'artists': [artist['name'] for artist in track['artists']],
                    'album': track['album']['name'],
                    'image': track['album']['images'][0]['url'] if track['album']['images'] else None,
                    'preview_url': track['preview_url'],
                    'duration_ms': track['duration_ms'],
                    'progress_ms': data['progress_ms'],
                    'id': track['id']
                }
            else:
                currently_playing_cache = {'is_playing': False}
            
            # Cachear por 10 segundos - usar UTC consistentemente
            cache_expiration = datetime.now(timezone.utc) + timedelta(seconds=10)
            return jsonify(currently_playing_cache), 200
        elif response.status_code == 204:
            currently_playing_cache = {'is_playing': False}
            cache_expiration = datetime.now(timezone.utc) + timedelta(seconds=10)
            return jsonify(currently_playing_cache), 200
        else:
            return jsonify({"error": "Error al obtener información de reproducción"}), response.status_code
    else:
        return jsonify({"error": "Admin no autenticado con Spotify"}), 401

# Endpoint para que el admin configure su Spotify
@app.route('/api/spotify/auth', methods=['GET'])
def spotify_auth():
    """Iniciar el flujo de autenticación de Spotify para usuarios regulares"""
    scope = 'user-read-currently-playing user-read-playback-state'
    auth_url = f"https://accounts.spotify.com/authorize?response_type=code&client_id={SPOTIFY_CLIENT_ID}&scope={scope}&redirect_uri={SPOTIFY_REDIRECT_URI}"
    return jsonify({"authUrl": auth_url}), 200

@app.route('/api/spotify/admin/auth', methods=['GET'])
def admin_spotify_auth():
    """Iniciar el flujo de autenticación de Spotify para el admin"""
    scope = 'user-read-currently-playing user-read-playback-state'
    auth_url = f"https://accounts.spotify.com/authorize?response_type=code&client_id={SPOTIFY_CLIENT_ID}&scope={scope}&redirect_uri={SPOTIFY_REDIRECT_URI}&state=admin"
    print(f"🔗 URL de auth de admin: {auth_url}")
    return jsonify({"authUrl": auth_url}), 200

@app.route('/api/spotify/callback', methods=['GET'])
def spotify_callback():
    """Callback para recibir el código de autorización de Spotify"""
    code = request.args.get('code')
    state = request.args.get('state', '')
    
    if not code:
        return jsonify({"error": "Código de autorización no proporcionado"}), 400
        
    # Intercambiar código por token de acceso
    token_url = "https://accounts.spotify.com/api/token"
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': SPOTIFY_REDIRECT_URI,
        'client_id': SPOTIFY_CLIENT_ID,
        'client_secret': SPOTIFY_CLIENT_SECRET
    }
    
    response = requests.post(token_url, data=data)
    if response.status_code != 200:
        return jsonify({"error": "Error al obtener token de acceso"}), 400
        
    token_data = response.json()
    access_token = token_data['access_token']
    refresh_token = token_data.get('refresh_token')
    expires_in = token_data['expires_in']
    
    # Determinar si es para el admin o para usuario general
    if state == 'admin':
        global admin_spotify_token
        
        # Guardar token del admin - usar UTC
        admin_spotify_token = {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_at': datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        }
        
        # Guardar en base de datos si está disponible
        if firebase_available and db:
            try:
                db.collection('admin_settings').document('spotify').set({
                    'token_data': admin_spotify_token,
                    'updated_at': firestore.SERVER_TIMESTAMP
                })
                print("✅ Token de admin guardado en Firebase")
            except Exception as e:
                print(f"Error guardando token en BD: {e}")
        
        # Iniciar polling si no está activo
        global polling_active, polling_thread
        if not polling_active:
            polling_thread = start_spotify_polling()
            print("✅ Polling de Spotify iniciado")
        
        # Redirigir al panel de administración con mensaje de éxito
        return redirect('https://music-uptc-sogamoso.vercel.app/admin-panel?spotify_connected=true')
    else:
        # Para usuarios regulares
        spotify_tokens['app'] = {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_at': datetime.now() + timedelta(seconds=expires_in)
        }
        return jsonify({
            "message": "Autenticación exitosa", 
            "access_token": access_token
        }), 200
    
# Endpoint para verificar estado de autenticación de Spotify del admin
@app.route('/api/spotify/admin/status', methods=['GET'])
def admin_spotify_status():
    
    """Verificar si el admin está autenticado con Spotify"""
    if admin_spotify_token and admin_spotify_token.get('access_token'):
        # Asegurar que ambas fechas sean aware para la comparación
        expires_at = ensure_aware_datetime(admin_spotify_token['expires_at'])
        is_valid = datetime.now(timezone.utc) < expires_at
        return jsonify({
            "authenticated": True,
            "token_valid": is_valid
        }), 200
    else:
        return jsonify({"authenticated": False}), 200

# Endpoint para que el admin desconecte Spotify
@app.route('/api/spotify/admin/disconnect', methods=['POST'])
def admin_spotify_disconnect():
    """Desconectar la cuenta de Spotify del admin"""
    global admin_spotify_token, currently_playing_cache, polling_active
    
    print(f"🔍 Headers recibidos en disconnect: {dict(request.headers)}")  # Debug
    
    # Verificar autenticación para operaciones de admin
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        print("❌ No se encontró header Authorization")
        return jsonify({"error": "Token de autorización requerido"}), 401
        
    if not auth_header.startswith('Bearer '):
        print(f"❌ Formato de Authorization incorrecto: {auth_header}")
        return jsonify({"error": "Formato de token incorrecto"}), 401
        
    try:
        id_token = auth_header.split('Bearer ')[1]
        print(f"🔑 Token recibido (primeros 50 chars): {id_token[:50]}...")  # Debug
        
        decoded_token = auth.verify_id_token(id_token)
        print(f"✅ Token decodificado para UID: {decoded_token['uid']}")
        
        # Limpiar datos de Spotify del admin
        admin_spotify_token = None
        currently_playing_cache = None
        polling_active = False
        
        # Eliminar de la base de datos si está disponible
        if firebase_available and db:
            try:
                db.collection('admin_settings').document('spotify').delete()
                print("✅ Token eliminado de Firebase")
            except Exception as e:
                print(f"Error eliminando token de BD: {e}")
        
        return jsonify({"message": "Spotify desconectado correctamente"}), 200
            
    except auth.InvalidIdTokenError as e:
        print(f"❌ Token inválido: {e}")
        return jsonify({"error": "Token inválido"}), 401
    except Exception as e:
        print(f"❌ Error al desconectar Spotify: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500
    
# Configurar Spotify
try:
    sp = spotipy.Spotify(auth_manager=SpotifyClientCredentials(
        client_id=os.environ.get("SPOTIFY_CLIENT_ID"),
        client_secret=os.environ.get("SPOTIFY_CLIENT_SECRET")
    ))
    print("✅ Spotify configurado correctamente")
except Exception as e:
    print(f"❌ Error configurando Spotify: {e}")
    sp = None

# Middleware simplificado para OPTIONS
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = jsonify()
        response.headers.add("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, OPTIONS")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization")
        response.headers.add("Access-Control-Allow-Credentials", "true")
        return response

@app.route('/api/spotify/currently-playing', methods=['GET'])
def get_currently_playing():
    """Obtener la canción actualmente en reproducción del admin"""
    global admin_spotify_token
    
    if not admin_spotify_token or not admin_spotify_token.get('access_token'):
        return jsonify({"error": "Admin no autenticado con Spotify"}), 401
    
    # Verificar si el token necesita refresco - usar UTC
    if datetime.now(timezone.utc) > admin_spotify_token['expires_at']:
        if not refresh_admin_spotify_token():
            return jsonify({"error": "Token de Spotify expirado"}), 401
    
    # Obtener la canción actual
    access_token = admin_spotify_token['access_token']
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(
        'https://api.spotify.com/v1/me/player/currently-playing', 
        headers=headers
    )
    
    if response.status_code == 200:
        data = response.json()
        if data['is_playing']:
            track = data['item']
            return jsonify({
                'is_playing': True,
                'name': track['name'],
                'artists': [artist['name'] for artist in track['artists']],
                'album': track['album']['name'],
                'image': track['album']['images'][0]['url'] if track['album']['images'] else None,
                'preview_url': track['preview_url'],
                'duration_ms': track['duration_ms'],
                'progress_ms': data['progress_ms'],
                'id': track['id']
            }), 200
        else:
            return jsonify({"is_playing": False}), 200
    elif response.status_code == 204:
        return jsonify({"is_playing": False}), 200
    else:
        return jsonify({"error": "Error al obtener información de reproducción"}), response.status_code

def refresh_admin_spotify_token():
    """Refrescar el token de Spotify del admin"""
    global admin_spotify_token
    
    if not admin_spotify_token or 'refresh_token' not in admin_spotify_token:
        return False
        
    refresh_token = admin_spotify_token['refresh_token']
    token_url = "https://accounts.spotify.com/api/token"
    
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': SPOTIFY_CLIENT_ID,
        'client_secret': SPOTIFY_CLIENT_SECRET
    }
    
    response = requests.post(token_url, data=data)
    if response.status_code != 200:
        return False
        
    token_data = response.json()
    admin_spotify_token['access_token'] = token_data['access_token']
    admin_spotify_token['expires_at'] = datetime.now() + timedelta(seconds=token_data['expires_in'])
    
    if 'refresh_token' in token_data:
        admin_spotify_token['refresh_token'] = token_data['refresh_token']
        
    # Guardar en base de datos si está disponible
    if firebase_available and db:
        try:
            db.collection('admin_settings').document('spotify').set({
                'token_data': admin_spotify_token,
                'updated_at': firestore.SERVER_TIMESTAMP
            })
        except Exception as e:
            print(f"Error guardando token en BD: {e}")
            
    return True

def refresh_spotify_token():
    """Refrescar el token de acceso de Spotify"""
    if 'app' not in spotify_tokens or 'refresh_token' not in spotify_tokens['app']:
        return False
        
    refresh_token = spotify_tokens['app']['refresh_token']
    token_url = "https://accounts.spotify.com/api/token"
    
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': SPOTIFY_CLIENT_ID,
        'client_secret': SPOTIFY_CLIENT_SECRET
    }
    
    response = requests.post(token_url, data=data)
    if response.status_code != 200:
        return False
        
    token_data = response.json()
    spotify_tokens['app']['access_token'] = token_data['access_token']
    spotify_tokens['app']['expires_at'] = datetime.now() + timedelta(seconds=token_data['expires_in'])
    
    # Spotify puede devolver un nuevo refresh_token opcionalmente
    if 'refresh_token' in token_data:
        spotify_tokens['app']['refresh_token'] = token_data['refresh_token']
        
    return True

@app.route('/api/health', methods=['GET'])
def health_check():
    """Endpoint para verificar el estado del servicio"""
    status = {
        "firebase": "connected" if firebase_available and db else "disconnected",
        "spotify": "connected" if sp else "disconnected",
        "status": "ok" if (firebase_available and db and sp) else "degraded"
    }
    return jsonify(status), 200

@app.route('/api/auth', methods=['POST', 'OPTIONS'])
def handle_auth():
    if request.method == 'OPTIONS':
        return '', 200
        
    if not firebase_available:
        return jsonify({"error": "Servicio de autenticación no disponible"}), 503
        
    try:
        data = request.get_json()
        id_token = data.get('idToken')  # Cambiamos a recibir el token de Firebase
        
        if not id_token:
            return jsonify({"error": "Token de Firebase requerido"}), 400
            
        # Verificar el token de Firebase
        decoded_token = auth.verify_id_token(id_token)
        user_uid = decoded_token['uid']
        
        # CUALQUIER usuario autenticado es admin - sin verificar colección
        # Crear token personalizado para uso interno si es necesario
        custom_token = auth.create_custom_token(user_uid)
        
        return jsonify({
            "success": True,
            "token": custom_token,
            "uid": user_uid,
            "message": "Autenticación exitosa"
        }), 200
        
    except auth.InvalidIdTokenError:
        return jsonify({"error": "Token inválido"}), 401
    except Exception as e:
        print(f"Error en autenticación: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

@app.route('/api/search', methods=['GET', 'OPTIONS'])
def handle_search():
    if request.method == 'OPTIONS':
        return '', 200
        
    if not sp:
        return jsonify({"error": "Servicio de búsqueda no disponible"}), 503
        
    query = request.args.get('q')
    if not query:
        return jsonify({"error": 'El parámetro de búsqueda "q" es requerido.'}), 400
        
    try:
        results = sp.search(q=query, type='track', limit=10)
        tracks = []
        for track in results['tracks']['items']:
            tracks.append({
                'id': track['id'],
                'name': track['name'],
                'artists': [artist['name'] for artist in track['artists']],
                'album': track['album']['name'],
                'image': track['album']['images'][0]['url'] if track['album']['images'] else "https://placehold.co/300x300?text=No+Image",
                'preview_url': track['preview_url'],
                'duration_ms': track['duration_ms'],
                'uri': track['uri']
            })
            
        return jsonify(tracks), 200
        
    except Exception as e:
        print(f"Error al buscar en Spotify: {e}")
        return jsonify({"error": "Error al buscar en Spotify."}), 500

# Función para obtener hash de IP (para evitar votos duplicados)
def get_ip_hash():
    # Obtener la IP real considerando proxies
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0]
    else:
        ip = request.remote_addr
    return hashlib.sha256(ip.encode()).hexdigest()

def get_user_fingerprint():
    """Obtener un identificador único basado en IP + User-Agent"""
    # Obtener la IP real considerando proxies
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0]
    else:
        ip = request.remote_addr
    
    # Obtener User-Agent
    user_agent = request.headers.get('User-Agent', '')
    
    # Crear un hash único combinando IP + User-Agent
    fingerprint_string = f"{ip}-{user_agent}"
    return hashlib.sha256(fingerprint_string.encode()).hexdigest()

# Endpoint para votar (accesible sin autenticación)
@app.route('/api/vote', methods=['POST', 'OPTIONS'])
def handle_vote():
    if request.method == 'OPTIONS':
        return '', 200
        
    if not firebase_available or not db:
        return jsonify({"error": "Servicio no disponible"}), 503
        
    try:
        data = request.get_json()
        track_id = data.get('trackId')
        
        if not track_id:
            return jsonify({"error": "ID de canción requerido"}), 400
            
        # Obtener fingerprint único del usuario (IP + User-Agent)
        user_fingerprint = get_user_fingerprint()
        
        # Verificar si este usuario ya votó por esta canción
        vote_ref = db.collection('votes').where('trackId', '==', track_id).where('userFingerprint', '==', user_fingerprint).limit(1).get()
        
        if len(vote_ref) > 0:
            return jsonify({"error": "Ya has votado por esta canción"}), 409
            
        # Obtener información de la canción si es necesario
        track_info = data.get('trackInfo', {})
        
        # Registrar el voto
        vote_data = {
            'trackId': track_id,
            'userFingerprint': user_fingerprint,
            'ipAddress': request.remote_addr,
            'userAgent': request.headers.get('User-Agent', ''),
            'timestamp': firestore.SERVER_TIMESTAMP,
            'name': track_info.get('name', ''),
            'artists': track_info.get('artists', []),
            'image': track_info.get('image', '')
        }
        
        # Añadir el voto
        db.collection('votes').add(vote_data)
        
        # Actualizar el contador de votos en la canción
        song_ref = db.collection('song_ranking').document(track_id)
        song_doc = song_ref.get()
        
        if song_doc.exists:
            # Incrementar el contador existente
            current_votes = song_doc.to_dict().get('votes', 0)
            song_ref.update({'votes': current_votes + 1})
        else:
            # Crear nueva entrada en el ranking
            song_ref.set({
                'id': track_id,
                'name': track_info.get('name', ''),
                'artists': track_info.get('artists', []),
                'image': track_info.get('image', ''),
                'preview_url': track_info.get('preview_url', ''),
                'votes': 1,
                'lastVoted': firestore.SERVER_TIMESTAMP
            })
        
        return jsonify({"message": "Voto registrado correctamente"}), 200
            
    except Exception as e:
        print(f"Error al registrar voto: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

@app.route('/api/votes', methods=['GET', 'DELETE', 'OPTIONS'])
def handle_votes():
    if request.method == 'OPTIONS':
        return '', 200
        
    if not firebase_available or not db:
        return jsonify({"error": "Servicio no disponible"}), 503
        
    if request.method == 'GET':
        try:
            # Obtener canciones ordenadas por votos (descendente)
            songs_ref = db.collection('song_ranking').order_by('votes', direction=firestore.Query.DESCENDING).stream()
            
            songs = []
            for song in songs_ref:
                song_data = song.to_dict()
                song_data['id'] = song.id
                # Asegurar que tenemos la fecha de creación
                if 'lastVoted' in song_data:
                    song_data['createdAt'] = song_data['lastVoted'].isoformat() if hasattr(song_data['lastVoted'], 'isoformat') else song_data['lastVoted']
                songs.append(song_data)
        
            return jsonify(songs), 200
                
        except Exception as e:
            print(f"Error al obtener votos: {e}")
            return jsonify({"error": "Error interno del servidor"}), 500
            
    elif request.method == 'DELETE':
        try:
            # Verificar autenticación para operaciones de eliminación
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({"error": "Token de autorización requerido"}), 401
                
            id_token = auth_header.split('Bearer ')[1]
            
            # Verificar el token de Firebase
            decoded_token = auth.verify_id_token(id_token)
            
            # Obtener trackId de los parámetros de consulta
            track_id = request.args.get('trackId')
            if not track_id:
                return jsonify({"error": "ID de canción requerido"}), 400
                
            # Eliminar la canción del ranking
            song_ref = db.collection('song_ranking').document(track_id)
            song_doc = song_ref.get()
            
            if not song_doc.exists:
                return jsonify({"error": "Canción no encontrada"}), 404
                
            # Eliminar la canción
            song_ref.delete()
            
            # También eliminar todos los votos asociados a esta canción
            votes_ref = db.collection('votes').where('trackId', '==', track_id).stream()
            for vote in votes_ref:
                vote.reference.delete()
                
            return jsonify({"message": "Canción eliminada correctamente"}), 200
                
        except auth.InvalidIdTokenError:
            return jsonify({"error": "Token inválido"}), 401
        except Exception as e:
            print(f"Error al eliminar canción: {e}")
            return jsonify({"error": "Error interno del servidor"}), 500

@app.route('/api/votes/all', methods=['DELETE', 'OPTIONS'])
def delete_all_votes():
    if request.method == 'OPTIONS':
        return '', 200
        
    if not firebase_available or not db:
        return jsonify({"error": "Servicio no disponible"}), 503
        
    try:
        # Verificar autenticación
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Token de autorización requerido"}), 401
            
        id_token = auth_header.split('Bearer ')[1]
        decoded_token = auth.verify_id_token(id_token)
        
        # Eliminar todos los documentos de la colección de votos
        votes_ref = db.collection('votes').stream()
        for vote in votes_ref:
            vote.reference.delete()
            
        # Eliminar todos los documentos del ranking de canciones
        songs_ref = db.collection('song_ranking').stream()
        for song in songs_ref:
            song.reference.delete()
            
        return jsonify({"message": "Todos los votos han sido eliminados"}), 200
            
    except auth.InvalidIdTokenError:
        return jsonify({"error": "Token inválido"}), 401
    except Exception as e:
        print(f"Error al eliminar todos los votos: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500
    
# Cargar token del admin desde la base de datos al iniciar la aplicación
def load_admin_spotify_token():
    """Cargar el token de Spotify del admin desde la base de datos"""
    global admin_spotify_token, polling_thread, polling_active
    
    if firebase_available and db:
        try:
            doc_ref = db.collection('admin_settings').document('spotify').get()
            if doc_ref.exists:
                data = doc_ref.to_dict()
                admin_spotify_token = data.get('token_data')
                
                # Iniciar polling si hay un token válido
                if admin_spotify_token and admin_spotify_token.get('access_token'):
                    # Verificar si el token necesita refresco - usar UTC
                    expires_at = ensure_aware_datetime(admin_spotify_token['expires_at'])
                    if datetime.now(timezone.utc) > expires_at:
                        if refresh_admin_spotify_token():
                            polling_thread = start_spotify_polling()
                    else:
                        polling_thread = start_spotify_polling()
        except Exception as e:
            print(f"Error cargando token de admin: {e}")

# Llamar a la función de carga al iniciar
load_admin_spotify_token()

if __name__ == '__main__':
    app.run(debug=True)