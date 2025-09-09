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
from datetime import datetime, timedelta, timezone
from flask_caching import Cache
from supabase import create_client, Client
import json
import base64

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

# Configuración de Supabase
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Variables globales para Spotify OAuth
SPOTIFY_CLIENT_ID = os.environ.get("SPOTIFY_CLIENT_ID")
SPOTIFY_CLIENT_SECRET = os.environ.get("SPOTIFY_CLIENT_SECRET")
SPOTIFY_REDIRECT_URI = os.environ.get("SPOTIFY_REDIRECT_URI", "https://music-uptc-sogamoso.vercel.app/api/spotify/callback")

# Credenciales fijas para el admin
ADMIN_CREDENTIALS = {
    "email": "sebastian.vegar2015@gmail.com",
    "password": "Sebas.01"
}

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

# Función para verificar autenticación básica
def verify_basic_auth():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Basic '):
        return False
        
    try:
        # Decodificar las credenciales
        encoded_credentials = auth_header.split('Basic ')[1]
        decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
        
        # Verificar contra las credenciales fijas O contra el token almacenado
        if decoded_credentials == f"{ADMIN_CREDENTIALS['email']}:{ADMIN_CREDENTIALS['password']}":
            return True
            
        # También verificar si es el token almacenado
        stored_token = localStorage.getItem('adminToken')
        if stored_token and encoded_credentials == stored_token:
            return True
            
        return False
    except:
        return False

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
        
    # Guardar en base de datos
    try:
        supabase.table('admin_settings').upsert({
            'id': 'spotify',
            'token_data': admin_spotify_token,
            'updated_at': datetime.now(timezone.utc).isoformat()
        }).execute()
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
    scope = 'user-read-currently-playing user-read-playback-state user-modify-playback-state'
    auth_url = f"https://accounts.spotify.com/authorize?response_type=code&client_id={SPOTIFY_CLIENT_ID}&scope={scope}&redirect_uri={SPOTIFY_REDIRECT_URI}"
    return jsonify({"authUrl": auth_url}), 200

# Endpoint para agregar canciones a la cola de reproducción
@app.route('/api/spotify/admin/queue', methods=['POST'])
def add_to_queue():
    """Agregar una canción a la cola de reproducción de Spotify"""
    # Verificar autenticación básica
    if not verify_basic_auth():
        return jsonify({"error": "Credenciales inválidas"}), 401
        
    data = request.get_json()
    track_uri = data.get('uri')
    
    if not track_uri:
        return jsonify({"error": "URI de canción requerida"}), 400
        
    if not admin_spotify_token or not admin_spotify_token.get('access_token'):
        return jsonify({"error": "Admin no autenticado con Spotify"}), 401
    
    # Verificar si el token necesita refresco
    if datetime.now(timezone.utc) > admin_spotify_token['expires_at']:
        if not refresh_admin_spotify_token():
            return jsonify({"error": "Token de Spotify expirado"}), 401
    
    # Agregar a la cola de reproducción
    access_token = admin_spotify_token['access_token']
    headers = {'Authorization': f'Bearer {access_token}'}
    
    response = requests.post(
        f'https://api.spotify.com/v1/me/player/queue?uri={track_uri}',
        headers=headers
    )
    
    if response.status_code == 204:
        return jsonify({"message": "Canción agregada a la cola"}), 200
    else:
        return jsonify({"error": f"Error al agregar a la cola: {response.status_code}"}), response.status_code

# Endpoint para obtener la cola de reproducción actual
@app.route('/api/spotify/admin/queue', methods=['GET'])
def get_queue():
    """Obtener la cola de reproducción actual de Spotify"""
    # Verificar autenticación básica
    if not verify_basic_auth():
        return jsonify({"error": "Credenciales inválidas"}), 401
        
    if not admin_spotify_token or not admin_spotify_token.get('access_token'):
        return jsonify({"error": "Admin no autenticado con Spotify"}), 401
    
    # Verificar si el token necesita refresco
    if datetime.now(timezone.utc) > admin_spotify_token['expires_at']:
        if not refresh_admin_spotify_token():
            return jsonify({"error": "Token de Spotify expirado"}), 401
    
    # Obtener la cola de reproducción
    access_token = admin_spotify_token['access_token']
    headers = {'Authorization': f'Bearer {access_token}'}
    
    response = requests.get(
        'https://api.spotify.com/v1/me/player/queue',
        headers=headers
    )
    
    if response.status_code == 200:
        queue_data = response.json()
        return jsonify(queue_data), 200
    else:
        return jsonify({"error": f"Error al obtener la cola: {response.status_code}"}), response.status_code
        
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
        
        # Guardar en base de datos
        try:
            supabase.table('admin_settings').upsert({
                'id': 'spotify',
                'token_data': admin_spotify_token,
                'updated_at': datetime.now(timezone.utc).isoformat()
            }).execute()
            print("✅ Token de admin guardado en Supabase")
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
        # Para usuarios regulares (si es necesario en el futuro)
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
    
    print(f"🔍 Headers recibidos en disconnect: {dict(request.headers)}")
    
    # Verificar autenticación básica
    if not verify_basic_auth():
        return jsonify({"error": "Credenciales inválidas"}), 401
        
    # Limpiar datos de Spotify del admin
    admin_spotify_token = None
    currently_playing_cache = None
    polling_active = False
    
    # Eliminar de la base de datos
    try:
        supabase.table('admin_settings').delete().eq('id', 'spotify').execute()
        print("✅ Token eliminado de Supabase")
    except Exception as e:
        print(f"Error eliminando token de BD: {e}")
    
    return jsonify({"message": "Spotify desconectado correctamente"}), 200

# Endpoint para autenticación básica
@app.route('/api/auth', methods=['POST', 'OPTIONS'])
def handle_auth():
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if email == ADMIN_CREDENTIALS["email"] and password == ADMIN_CREDENTIALS["password"]:
            # Crear un token básico (solo para compatibilidad con frontend)
            token = base64.b64encode(f"{email}:{password}".encode()).decode()
            return jsonify({
                "success": True,
                "token": token,
                "message": "Autenticación exitosa"
            }), 200
        else:
            return jsonify({"error": "Credenciales inválidas"}), 401
            
    except Exception as e:
        print(f"Error en autenticación: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

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

@app.route('/api/health', methods=['GET'])
def health_check():
    """Endpoint para verificar el estado del servicio"""
    # Verificar conexión a Supabase
    supabase_status = "connected"
    try:
        supabase.table('admin_settings').select('count', count='exact').execute()
    except Exception as e:
        supabase_status = f"disconnected: {str(e)}"
    
    status = {
        "database": supabase_status,
        "spotify": "connected" if sp else "disconnected",
        "status": "ok" if sp and supabase_status == "connected" else "degraded"
    }
    return jsonify(status), 200

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
        
    try:
        data = request.get_json()
        track_id = data.get('trackid') or data.get('trackId')
        
        if not track_id:
            return jsonify({"error": "ID de canción requerido"}), 400
            
        # Obtener fingerprint único del usuario (IP + User-Agent)
        user_fingerprint = get_user_fingerprint()
        
        # Verificar si este usuario ya votó por esta canción
        try:
            existing_vote = supabase.table('votes')\
                .select('*')\
                .eq('trackid', track_id)\
                .eq('userFingerprint', user_fingerprint)\
                .execute()
            
            if len(existing_vote.data) > 0:
                return jsonify({"error": "Ya has votado por esta canción"}), 409
        except Exception as e:
            print(f"Error verificando voto existente: {e}")
            return jsonify({"error": "Error al verificar voto"}), 500
            
        # Obtener información de la canción si es necesario
        track_info = data.get('trackInfo', {})
        
        # Registrar el voto
        vote_data = {
            'trackid': track_id,
            'userFingerprint': user_fingerprint,
            'ipAddress': request.remote_addr,
            'userAgent': request.headers.get('User-Agent', ''),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # Añadir el voto
        supabase.table('votes').insert(vote_data).execute()
        
        # Actualizar el contador de votos en la canción
        try:
            # Verificar si la canción ya existe
            existing_song = supabase.table('song_ranking')\
                .select('*')\
                .eq('id', track_id)\
                .execute()
            
            if len(existing_song.data) > 0:
                # Incrementar el contador existente
                current_votes = existing_song.data[0]['votes']
                supabase.table('song_ranking')\
                    .update({
                        'votes': current_votes + 1,
                        'lastvoted': datetime.now(timezone.utc).isoformat()
                    })\
                    .eq('id', track_id)\
                    .execute()
            else:
                # Crear nueva entrada en el ranking
                song_data = {
                    'id': track_id,
                    'name': track_info.get('name', ''),
                    'artists': track_info.get('artists', []),
                    'image': track_info.get('image', ''),
                    'preview_url': track_info.get('preview_url', ''),
                    'votes': 1,
                    'lastvoted': datetime.now(timezone.utc).isoformat(),
                    'createdat': datetime.now(timezone.utc).isoformat()
                }
                supabase.table('song_ranking').insert(song_data).execute()
        except Exception as e:
            print(f"Error actualizando ranking: {e}")
            return jsonify({"error": "Error al actualizar ranking"}), 500
        
        return jsonify({"message": "Voto registrado correctamente"}), 200
            
    except Exception as e:
        print(f"Error al registrar voto: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

cache = Cache(app, config={'CACHE_TYPE': 'simple'})

@app.route('/api/votes', methods=['GET'])
@cache.cached(timeout=30)  # Cache por 30 segundos
def handle_votes():
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        # Obtener canciones ordenadas por votos (descendente)
        songs = supabase.table('song_ranking')\
            .select('*')\
            .order('votes', desc=True)\
            .execute()
        
        # Formatear las canciones para que coincidan con el formato esperado
        formatted_songs = []
        for song in songs.data:
            formatted_song = {
                'id': song['id'],
                'name': song['name'],
                'artists': song['artists'],
                'image': song['image'],
                'preview_url': song['preview_url'],
                'votes': song['votes'],
                'createdat': song['lastvoted'] 
            }
            formatted_songs.append(formatted_song)
        
        return jsonify(formatted_songs), 200
            
    except Exception as e:
        print(f"Error al obtener votos: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

@app.route('/api/votes', methods=['DELETE'])
def handle_delete_votes():
    try:
        # Verificar autenticación básica
        if not verify_basic_auth():
            return jsonify({"error": "Credenciales inválidas"}), 401
            
        # Obtener trackId de los parámetros de consulta
        track_id = request.args.get('trackid')
        if not track_id:
            return jsonify({"error": "ID de canción requerido"}), 400
            
        # Eliminar la canción del ranking
        supabase.table('song_ranking').delete().eq('id', track_id).execute()
        
        # También eliminar todos los votos asociados a esta canción
        supabase.table('votes').delete().eq('trackid', track_id).execute()
            
        return jsonify({"message": "Canción eliminada correctamente"}), 200
            
    except Exception as e:
        print(f"Error al eliminar canción: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

@app.route('/api/votes/all', methods=['DELETE', 'OPTIONS'])
def delete_all_votes():
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        # Verificar autenticación básica
        if not verify_basic_auth():
            return jsonify({"error": "Credenciales inválidas"}), 401
            
        # Eliminar todos los votos
        supabase.table('votes').delete().neq('id', 0).execute()
            
        # Eliminar todas las canciones del ranking
        supabase.table('song_ranking').delete().neq('id', '').execute()
            
        return jsonify({"message": "Todos los votos han sido eliminados"}), 200
            
    except Exception as e:
        print(f"Error al eliminar todos los votos: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500
    
# Cargar token del admin desde la base de datos al iniciar la aplicación
def load_admin_spotify_token():
    """Cargar el token de Spotify del admin desde la base de datos"""
    global admin_spotify_token, polling_thread, polling_active
    
    try:
        result = supabase.table('admin_settings').select('*').eq('id', 'spotify').execute()
        if result.data and len(result.data) > 0:
            admin_spotify_token = result.data[0]['token_data']
            
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