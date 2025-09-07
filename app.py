from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import spotipy
from spotipy.oauth2 import SpotifyClientCredentials

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
        
    if not firebase_available or not db:
        return jsonify({"error": "Servicio de autenticación no disponible"}), 503
        
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({"error": "Email y contraseña son requeridos"}), 400
            
        # Autenticar con Firebase
        user = auth.get_user_by_email(email)
        
        # Verificar si es admin
        admin_doc = db.collection('admins').document(user.uid).get()
        if not admin_doc.exists:
            return jsonify({"error": "No tienes permisos de administrador"}), 401
            
        # Crear token personalizado
        token = auth.create_custom_token(user.uid)
        
        return jsonify({
            "success": True,
            "token": token,
            "message": "Autenticación exitosa"
        }), 200
        
    except auth.UserNotFoundError:
        return jsonify({"error": "Credenciales inválidas"}), 401
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

@app.route('/api/votes', methods=['GET', 'POST', 'DELETE', 'OPTIONS'])
def handle_votes():
    if request.method == 'OPTIONS':
        return '', 200
        
    if not firebase_available or not db:
        return jsonify({"error": "Servicio de votación no disponible"}), 503
        
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    
    try:
        if request.method == 'POST':
            data = request.get_json()
            track_id = data.get('trackId')
            track_info = data.get('trackInfo')
            
            if not track_id or not track_info:
                return jsonify({"error": "Datos incompletos"}), 400
                
            # Verificar si ya votó
            vote_ref = db.collection('votes').document(f"{track_id}_{client_ip}")
            if vote_ref.get().exists:
                return jsonify({"message": "Ya has votado por esta canción."}), 409
                
            # Actualizar contador
            song_ref = db.collection('song_ranking').document(track_id)
            song_data = track_info.copy()
            song_data.update({
                'votes': firestore.Increment(1),
                'lastUpdated': firestore.SERVER_TIMESTAMP
            })
            song_ref.set(song_data, merge=True)
            
            # Registrar voto
            vote_ref.set({
                'trackId': track_id,
                'ip': client_ip,
                'timestamp': firestore.SERVER_TIMESTAMP
            })
            
            return jsonify({"message": "Voto registrado correctamente."}), 201
            
        elif request.method == 'GET':
            songs_ref = db.collection('song_ranking').order_by('votes', direction=firestore.Query.DESCENDING).limit(50)
            songs = [{'id': doc.id, **doc.to_dict()} for doc in songs_ref.stream()]
            return jsonify(songs), 200
            
        elif request.method == 'DELETE':
            track_id = request.args.get('trackId')
            auth_header = request.headers.get('Authorization')
            
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({"error": "Token de autorización requerido"}), 401
                
            token = auth_header[7:]
            
            try:
                # Verificar token
                decoded_token = auth.verify_id_token(token)
                
                # Verificar admin
                admin_doc = db.collection('admins').document(decoded_token['uid']).get()
                if not admin_doc.exists:
                    return jsonify({"error": "No tienes permisos de administrador"}), 401
                    
                if not track_id:
                    return jsonify({"error": "ID de canción requerido"}), 400
                    
                # Eliminar canción y votos
                db.collection('song_ranking').document(track_id).delete()
                
                votes = db.collection('votes').where('trackId', '==', track_id).stream()
                batch = db.batch()
                for vote in votes:
                    batch.delete(vote.reference)
                batch.commit()
                
                return jsonify({"message": "Canción eliminada correctamente."}), 200
                
            except Exception as e:
                print(f"Error al verificar token: {e}")
                return jsonify({"error": "Token inválido"}), 401
                
    except Exception as e:
        print(f"Error en API votes: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

if __name__ == '__main__':
    app.run(debug=True)