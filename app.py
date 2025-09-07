from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import spotipy
from spotipy.oauth2 import SpotifyClientCredentials
import hashlib

# Añadir estas importaciones
import requests
from datetime import datetime, timedelta

app = Flask(__name__)

# Configuración CORS simplificada
allowed_origins = [
    "https://4200-firebase-musicuptcsogamoso-1757187604448.cluster-dwvm25yncracsxpd26rcd5ja3m.cloudworkstations.dev",
    "https://music-uptc-sogamoso.vercel.app",
    "https://sebastianvega4.github.io",
    "http://localhost:4200",
    "https://9000-firebase-musicuptcsogamoso-1757187604448.cluster-dwvm25yncracsxpd26rcd5ja3m.cloudworkstations.dev"
]

# Configuración CORS
CORS(app, origins=allowed_origins, supports_credentials=True)

# Variables globales para Spotify OAuth
SPOTIFY_CLIENT_ID = os.environ.get("SPOTIFY_CLIENT_ID")
SPOTIFY_CLIENT_SECRET = os.environ.get("SPOTIFY_CLIENT_SECRET")
SPOTIFY_REDIRECT_URI = os.environ.get("SPOTIFY_REDIRECT_URI", "https://music-uptc-sogamoso.vercel.app/api/spotify/callback")

# Almacenamiento simple de tokens (en producción usar una base de datos)
spotify_tokens = {}

# Importar utilidades de Firebase
try:
    from utils.firebase import initialize_firebase, get_db
    from firebase_admin import auth, firestore
    firebase_available = True
    print("✅ Módulos de Firebase importados correctamente")
except ImportError as e:
    print(f"⚠️  No se pudieron importar módulos de Firebase: {e}")
    firebase_available = False
except Exception as e:
    print(f"⚠️  Error al importar Firebase: {e}")
    firebase_available = False

# Inicializar Firebase solo si está disponible
db = None
if firebase_available:
    try:
        firebase_app, db = initialize_firebase()
        print("✅ Firebase inicializado correctamente")
    except Exception as e:
        print(f"❌ Error inicializando Firebase: {e}")
        firebase_available = False
        db = None

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

# Spotify OAuth Endpoints
@app.route('/api/spotify/auth', methods=['GET'])
def spotify_auth():
    """Iniciar el flujo de autenticación de Spotify"""
    scope = 'user-read-currently-playing user-read-playback-state'
    auth_url = f"https://accounts.spotify.com/authorize?response_type=code&client_id={SPOTIFY_CLIENT_ID}&scope={scope}&redirect_uri={SPOTIFY_REDIRECT_URI}"
    return jsonify({"authUrl": auth_url}), 200

@app.route('/api/spotify/callback', methods=['GET'])
def spotify_callback():
    """Callback para recibir el código de autorización de Spotify"""
    code = request.args.get('code')
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
    
    # Guardar el token (en producción, asociar con un usuario específico)
    spotify_tokens['app'] = {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'expires_at': datetime.now() + timedelta(seconds=expires_in)
    }
    
    return jsonify({"message": "Autenticación exitosa", "access_token": access_token}), 200

@app.route('/api/spotify/currently-playing', methods=['GET'])
def get_currently_playing():
    """Obtener la canción actualmente en reproducción"""
    # Verificar si tenemos un token válido
    if 'app' not in spotify_tokens or datetime.now() > spotify_tokens['app']['expires_at']:
        # Intentar refrescar el token si es necesario
        if not refresh_spotify_token():
            return jsonify({"error": "No autenticado con Spotify"}), 401
    
    access_token = spotify_tokens['app']['access_token']
    
    # Hacer la solicitud a la API de Spotify
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    
    response = requests.get('https://api.spotify.com/v1/me/player/currently-playing', headers=headers)
    
    if response.status_code == 204:
        # No hay nada reproduciéndose
        return jsonify({"is_playing": False}), 200
    elif response.status_code != 200:
        return jsonify({"error": "Error al obtener información de reproducción"}), response.status_code
    
    data = response.json()
    
    # Extraer información relevante
    if data['is_playing']:
        track = data['item']
        current_track = {
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
        return jsonify(current_track), 200
    else:
        return jsonify({"is_playing": False}), 200

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
            
        # Obtener hash de IP para prevenir votos duplicados
        ip_hash = get_ip_hash()
        
        # Verificar si esta IP ya votó por esta canción
        vote_ref = db.collection('votes').where('trackId', '==', track_id).where('ipHash', '==', ip_hash).limit(1).get()
        
        if len(vote_ref) > 0:
            return jsonify({"error": "Ya has votado por esta canción"}), 409
            
        # Obtener información de la canción si es necesario
        track_info = data.get('trackInfo', {})
        
        # Registrar el voto
        vote_data = {
            'trackId': track_id,
            'ipHash': ip_hash,
            'timestamp': firestore.SERVER_TIMESTAMP,
            'userAgent': request.headers.get('User-Agent', ''),
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
    
if __name__ == '__main__':
    app.run(debug=True)