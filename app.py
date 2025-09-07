from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import spotipy
from spotipy.oauth2 import SpotifyClientCredentials
import hashlib

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

app = Flask(__name__)

# Configuración CORS simplificada - SOLUCIÓN AL ERROR MÚLTIPLE
allowed_origins = [
    "https://4200-firebase-musicuptcsogamoso-1757187604448.cluster-dwvm25yncracsxpd26rcd5ja3m.cloudworkstations.dev",
    "https://music-uptc-sogamoso.vercel.app",
    "https://sebastianvega4.github.io",
    "http://localhost:4200",
    "https://9000-firebase-musicuptcsogamoso-1757187604448.cluster-dwvm25yncracsxpd26rcd5ja3m.cloudworkstations.dev"
]

# Configuración CORS MÁS SIMPLE - sin el after_request que causa duplicación
CORS(app, origins=allowed_origins, supports_credentials=True)

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

@app.route('/api/votes', methods=['GET'])
def get_votes():
    if request.method == 'OPTIONS':
        return '', 200
        
    if not firebase_available or not db:
        return jsonify({"error": "Servicio no disponible"}), 503
        
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

if __name__ == '__main__':
    app.run(debug=True)