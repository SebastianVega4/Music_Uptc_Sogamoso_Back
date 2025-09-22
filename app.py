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
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any

from voting_manager import voting_manager
from history_manager import history_manager

voting_manager.load_voting_state()
voting_manager.start_voting_polling()
app = Flask(__name__)

# Configuración CORS simplificada
allowed_origins = [
    "https://4200-firebase-musicuptcsogamoso-1757187604448.cluster-dwvm25yncracsxpd26rcd5ja3m.cloudworkstations.dev",
    "https://music-uptc-sogamoso.vercel.app",
    "https://sebastianvega4.github.io",
    "http://localhost:4200",
    "http://uptcmusic.com",
    "https://uptcmusic.com",
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

JWT_SECRET = os.environ.get("JWT_SECRET", "846d56ad337d10a3")
JWT_ALGORITHM = "HS256"

# Función para verificar autenticación
def verify_jwt_auth():
    """Verificar autenticación JWT"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        print("❌ No hay token de autorización")
        return False
        
    try:
        token = auth_header.split('Bearer ')[1]
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        
        # Verificar si el usuario existe en la base de datos y es admin
        result = supabase.table('admin_users').select('*').eq('id', payload['user_id']).execute()
        if not result.data:
            print(f"❌ Usuario no encontrado: {payload['user_id']}")
            return False
            
        return True
    except Exception as e:
        print(f"❌ Error decodificando token: {e}")
        return False

def start_spotify_polling():
    """Iniciar polling para la canción actual del admin con manejo robusto de errores"""
    global polling_active
    polling_active = True
    
    def poll_spotify():
        global currently_playing_cache, cache_expiration, admin_spotify_token
        error_count = 0
        max_errors = 5
        
        while polling_active:
            try:
                if not admin_spotify_token or not admin_spotify_token.get('access_token'):
                    print("⚠️  No hay token de Spotify para polling")
                    time.sleep(30)
                    continue
                
                # Verificar si el token necesita refresco automático
                expires_at_aware = ensure_aware_datetime(admin_spotify_token['expires_at'])
                if datetime.now(timezone.utc) > expires_at_aware:
                    print("🔄 Token expirado en polling, refrescando...")
                    if not refresh_admin_spotify_token():
                        print("❌ No se pudo refrescar el token en polling")
                        error_count += 1
                        if error_count >= max_errors:
                            print("❌ Demasiados errores, deteniendo polling")
                            polling_active = False
                            break
                        time.sleep(30)
                        continue
                    else:
                        error_count = 0  # Reset error count on success
                
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
                    
                    # Cachear por 10 segundos
                    cache_expiration = datetime.now(timezone.utc) + timedelta(seconds=10)
                    error_count = 0  # Reset error count on success
                    
                elif response.status_code == 204:
                    currently_playing_cache = {'is_playing': False}
                    cache_expiration = datetime.now(timezone.utc) + timedelta(seconds=10)
                    print("⏸️  No se está reproduciendo nada")
                    error_count = 0  # Reset error count
                    
                elif response.status_code == 401:
                    # Token inválido, intentar refrescar
                    print("🔄 Token inválido en polling, refrescando...")
                    if refresh_admin_spotify_token():
                        error_count = 0
                    else:
                        error_count += 1
                        if error_count >= max_errors:
                            print("❌ Demasiados errores de autenticación, deteniendo polling")
                            polling_active = False
                            break
                            
                else:
                    print(f"❌ Error en API de Spotify: {response.status_code}")
                    error_count += 1
                    if error_count >= max_errors:
                        print("❌ Demasiados errores, deteniendo polling")
                        polling_active = False
                        break
                        
            except Exception as e:
                print(f"❌ Error en polling de Spotify: {e}")
                error_count += 1
                if error_count >= max_errors:
                    print("❌ Demasiados errores, deteniendo polling")
                    polling_active = False
                    break
            
            time.sleep(5)  # Esperar 5 segundos entre consultas
    
    # Iniciar el hilo de polling
    thread = threading.Thread(target=poll_spotify)
    thread.daemon = True
    thread.start()
    print("✅ Hilo de polling iniciado con manejo robusto de errores")
    return thread

def ensure_aware_datetime(dt):
    """Asegurar que un datetime sea timezone-aware (UTC) - VERSIÓN MEJORADA"""
    if dt is None:
        return None
        
    if isinstance(dt, str):
        # Convertir string a datetime
        try:
            if 'Z' in dt:
                dt = dt.replace('Z', '+00:00')
            parsed_dt = datetime.fromisoformat(dt)
            if parsed_dt.tzinfo is None:
                parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)
            return parsed_dt
        except (ValueError, AttributeError):
            print(f"❌ Error parsing datetime string: {dt}")
            return datetime.now(timezone.utc)
    elif isinstance(dt, datetime):
        if dt.tzinfo is None:
            # Si es naive, convertirlo a aware (UTC)
            return dt.replace(tzinfo=timezone.utc)
        else:
            # Ya es aware, retornar tal cual
            return dt
    else:
        print(f"❌ Tipo de fecha no soportado: {type(dt)}")
        return datetime.now(timezone.utc)
    
def refresh_admin_spotify_token():
    """Refrescar el token de Spotify del admin con mejor manejo de errores"""
    global admin_spotify_token
    
    if not admin_spotify_token or 'refresh_token' not in admin_spotify_token:
        print("❌ No hay refresh token disponible para refrescar")
        return False
        
    refresh_token = admin_spotify_token['refresh_token']
    token_url = "https://accounts.spotify.com/api/token"
    
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': SPOTIFY_CLIENT_ID,
        'client_secret': SPOTIFY_CLIENT_SECRET
    }
    
    try:
        response = requests.post(token_url, data=data, timeout=10)
        if response.status_code != 200:
            print(f"❌ Error al refrescar token: {response.status_code} - {response.text}")
            return False
            
        token_data = response.json()
        admin_spotify_token['access_token'] = token_data['access_token']
        
        # Usar UTC consistentemente y asegurar que es string ISO
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=token_data['expires_in'])
        admin_spotify_token['expires_at'] = expires_at.isoformat()  # Guardar como string ISO
        
        # Spotify puede o no devolver un nuevo refresh_token
        if 'refresh_token' in token_data:
            admin_spotify_token['refresh_token'] = token_data['refresh_token']
            print("✅ Nuevo refresh_token recibido")
        else:
            print("ℹ️  Mismo refresh_token mantenido")
            
        # Guardar en base de datos
        try:
            supabase.table('admin_settings').upsert({
                'id': 'spotify',
                'token_data': admin_spotify_token,  # Ahora expires_at es string ISO
                'updated_at': datetime.now(timezone.utc).isoformat()
            }).execute()
            print("✅ Token refrescado y guardado en Supabase")
        except Exception as e:
            print(f"❌ Error guardando token refrescado en BD: {e}")
            
        return True
        
    except Exception as e:
        print(f"❌ Error en refresh_admin_spotify_token: {e}")
        return False

@app.route('/api/spotify/admin/reconnect', methods=['POST'])
def admin_spotify_reconnect():
    """Forzar reconexión completa de Spotify"""
    global admin_spotify_token, polling_active
    
    # Verificar autenticación
    if not verify_jwt_auth():
        return jsonify({"error": "Credenciales inválidas"}), 401
    
    # Detener polling actual
    polling_active = False
    
    # Limpiar token existente
    admin_spotify_token = None
    
    # Eliminar de la base de datos
    try:
        supabase.table('admin_settings').delete().eq('id', 'spotify').execute()
        print("✅ Configuración de Spotify eliminada para reconexión")
    except Exception as e:
        print(f"Error eliminando configuración: {e}")
    
    return jsonify({"message": "Listo para reconectar Spotify"}), 200

@app.route('/api/spotify/admin/check-playing-song', methods=['POST'])
def check_playing_song():
    """Verificar si la canción en reproducción está en el ranking y procesarla SOLO si no ha sido agregada recientemente"""
    # Verificar autenticación
    if not verify_jwt_auth():
        return jsonify({"error": "Credenciales inválidas"}), 401
        
    global admin_spotify_token, currently_playing_cache
    
    # Verificar si hay una canción reproduciéndose
    if not currently_playing_cache or not currently_playing_cache.get('is_playing'):
        return jsonify({"message": "No hay canción reproduciéndose", "processed": False}), 200
    
    track_id = currently_playing_cache.get('id')
    if not track_id:
        return jsonify({"message": "No se pudo obtener ID de la canción", "processed": False}), 200
    
    try:
        # PRIMERO: Verificar si la canción ya fue agregada al histórico en los últimos 10 minutos
        ten_minutes_ago = datetime.now(timezone.utc) - timedelta(minutes=10)
        
        recent_history_check = supabase.table('song_history')\
            .select('last_played_at')\
            .eq('track_id', track_id)\
            .gte('last_played_at', ten_minutes_ago.isoformat())\
            .execute()
        
        if recent_history_check.data and len(recent_history_check.data) > 0:
            # La canción ya fue agregada al histórico recientemente, no hacer nada
            return jsonify({
                "message": "Canción ya agregada al histórico recientemente",
                "processed": False,
                "recently_added": True,
                "last_added": recent_history_check.data[0]['last_played_at']
            }), 200
        
        # SEGUNDO: Verificar si la canción existe en el ranking
        result = supabase.table('song_ranking').select('*').eq('id', track_id).execute()
        
        if result.data and len(result.data) > 0:
            # Canción ya existe en el ranking - eliminarla y agregar al histórico
            song_data = result.data[0]
            
            # Agregar la canción al histórico
            history_payload = {
                'track_id': track_id,
                'votes': song_data.get('votes', 0),
                'dislikes': song_data.get('dislikes', 0)
            }
            
            history_response = add_to_song_history_internal(history_payload)
            
            # Eliminar la canción del ranking
            supabase.table('song_ranking').delete().eq('id', track_id).execute()
            
            # También eliminar todos los votos asociados a esta canción
            supabase.table('votes').delete().eq('trackid', track_id).execute()
            
            print(f"✅ Canción {track_id} eliminada por estar en reproducción y agregada al histórico")
            return jsonify({
                "message": "Canción eliminada del ranking por estar en reproducción",
                "deleted": True,
                "added_to_history": history_response.get('action') if history_response else False,
                "song": {
                    "id": track_id,
                    "name": currently_playing_cache.get('name'),
                    "artists": currently_playing_cache.get('artists')
                }
            }), 200
        else:
            # Canción NO existe en el ranking - NO la agregamos automáticamente
            # Solo informamos que no está en el ranking
            return jsonify({
                "message": "Canción no encontrada en el ranking",
                "in_ranking": False,
                "song": {
                    "id": track_id,
                    "name": currently_playing_cache.get('name'),
                    "artists": currently_playing_cache.get('artists')
                }
            }), 200
            
    except Exception as e:
        print(f"❌ Error al verificar/eliminar canción: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

@app.route('/api/spotify/admin/add-to-history', methods=['POST'])
def admin_add_to_history():
    """Verificar si se puede agregar al histórico antes de proceder"""
    # Verificar autenticación
    if not verify_jwt_auth():
        return jsonify({"error": "Credenciales inválidas"}), 401
        
    global currently_playing_cache
    
    # Verificar si hay una canción reproduciéndose
    if not currently_playing_cache or not currently_playing_cache.get('is_playing'):
        return jsonify({"error": "No hay canción reproduciéndose actualmente"}), 400
    
    track_id = currently_playing_cache.get('id')
    if not track_id:
        return jsonify({"error": "No se pudo obtener ID de la canción"}), 400
    
    # Verificar si se puede agregar al histórico
    can_add, message = history_manager.can_add_to_history(track_id)
    
    if can_add:
        return jsonify({
            "can_add": True,
            "message": "Puede agregar esta canción al histórico",
            "confirmation_required": True,
            "song": {
                "id": track_id,
                "name": currently_playing_cache.get('name'),
                "artists": currently_playing_cache.get('artists')
            }
        }), 200
    else:
        return jsonify({
            "can_add": False,
            "message": message,
            "confirmation_required": False
        }), 200
            
    except Exception as e:
        print(f"❌ Error al agregar al histórico: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Error interno del servidor"}), 500
        
@app.route('/api/ranking/force-rank-current', methods=['POST'])
def force_rank_current_song():
    """Forzar el ranking de la canción actualmente en reproducción"""
    # Verificar autenticación
    if not verify_jwt_auth():
        return jsonify({"error": "Credenciales inválidas"}), 401
        
    global currently_playing_cache
    
    # Verificar si hay una canción reproduciéndose
    if not currently_playing_cache or not currently_playing_cache.get('is_playing'):
        return jsonify({"error": "No hay canción reproduciéndose actualmente"}), 400
    
    track_id = currently_playing_cache.get('id')
    if not track_id:
        return jsonify({"error": "No se pudo obtener ID de la canción"}), 400
    
    try:
        # Verificar si la canción ya existe en el ranking
        result = supabase.table('song_ranking').select('*').eq('id', track_id).execute()
        
        if result.data and len(result.data) > 0:
            # Canción ya existe - no hacer nada
            return jsonify({
                "message": "La canción ya está en el ranking",
                "action": "none",
                "song": {
                    "id": track_id,
                    "name": currently_playing_cache.get('name'),
                    "artists": currently_playing_cache.get('artists')
                }
            }), 200
        else:
            # Canción NO existe - crearla con un voto
            track_info = {
                'id': track_id,
                'name': currently_playing_cache.get('name'),
                'artists': currently_playing_cache.get('artists', []),
                'image': currently_playing_cache.get('image', ''),
                'preview_url': currently_playing_cache.get('preview_url', ''),
                'votes': 0,
                'dislikes': 0,
                'lastvoted': datetime.now(timezone.utc).isoformat(),
                'createdat': datetime.now(timezone.utc).isoformat()
            }
            
            # Insertar en el ranking
            supabase.table('song_ranking').insert(track_info).execute()
            
            # Crear un voto ficticio para esta canción
            vote_data = {
                'trackid': track_id,
                'userFingerprint': 'manual_force_rank',
                'ipAddress': 'system',
                'userAgent': 'ManualForceRank',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'is_dislike': False
            }
            supabase.table('votes').insert(vote_data).execute()
            
            print(f"✅ Canción {track_id} agregada manualmente al ranking con 1 voto")
            return jsonify({
                "message": "Canción agregada al ranking con 1 voto",
                "action": "added",
                "song": {
                    "id": track_id,
                    "name": currently_playing_cache.get('name'),
                    "artists": currently_playing_cache.get('artists')
                }
            }), 200
            
    except Exception as e:
        print(f"❌ Error al forzar ranking de canción: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500
        
# Función interna para agregar al histórico (para uso interno)
def add_to_song_history_internal(data):
    """Función interna para agregar canciones al histórico - VERSIÓN CORREGIDA"""
    try:
        track_id = data.get('track_id')
        
        if not track_id:
            return {"error": "ID de canción requerido"}
            
        # Obtener información de la canción desde currently_playing_cache
        global currently_playing_cache
        if not currently_playing_cache or not currently_playing_cache.get('is_playing'):
            return {"error": "No hay canción reproduciéndose"}
        
        current_time = datetime.now(timezone.utc).isoformat()
        
        # Verificar si la canción ya existe en el histórico
        result = supabase.table('song_history')\
            .select('*')\
            .eq('track_id', track_id)\
            .execute()
            
        if result.data and len(result.data) > 0:
            # Actualizar canción existente
            existing_song = result.data[0]
            update_data = {
                'times_played': existing_song['times_played'] + 1,
                'last_played_at': current_time,
                'updated_at': current_time
            }
            
            # Si se proporcionan votos, actualizarlos también
            if 'votes' in data:
                update_data['total_votes'] = existing_song['total_votes'] + data['votes']
            if 'dislikes' in data:
                update_data['total_dislikes'] = existing_song['total_dislikes'] + data['dislikes']
                
            # Actualizar en la base de datos
            supabase.table('song_history')\
                .update(update_data)\
                .eq('track_id', track_id)\
                .execute()
                
            print(f"✅ Canción actualizada en histórico: {track_id}")
            return {"action": "updated", "song": currently_playing_cache}
        else:
            # Crear nueva entrada en el histórico
            new_song = {
                'track_id': track_id,
                'name': currently_playing_cache.get('name', ''),
                'artists': currently_playing_cache.get('artists', []),
                'image': currently_playing_cache.get('image', ''),
                'preview_url': currently_playing_cache.get('preview_url', ''),
                'total_votes': data.get('votes', 0),
                'total_dislikes': data.get('dislikes', 0),
                'times_played': 1,
                'last_played_at': current_time,
                'first_played_at': current_time,
                'created_at': current_time,
                'updated_at': current_time
            }
            
            # Insertar en la base de datos
            supabase.table('song_history').insert(new_song).execute()
            
            print(f"✅ Nueva canción agregada al histórico: {track_id}")
            return {"action": "created", "song": currently_playing_cache}
            
    except Exception as e:
        print(f"❌ Error interno al agregar al histórico: {e}")
        return {"error": str(e)}
        
# Nuevo endpoint para obtener la canción actual del admin
@app.route('/api/spotify/admin/currently-playing', methods=['GET'])
def get_admin_currently_playing():
    """Obtener la canción actualmente en reproducción del admin con refresco automático"""
    global currently_playing_cache, cache_expiration, admin_spotify_token
    
    # Verificar si tenemos caché válida
    if currently_playing_cache and cache_expiration:
        cache_expiration_aware = ensure_aware_datetime(cache_expiration)
        if datetime.now(timezone.utc) < cache_expiration_aware:
            return jsonify(currently_playing_cache), 200
    
    # Si no hay token de admin, retornar error
    if not admin_spotify_token or not admin_spotify_token.get('access_token'):
        return jsonify({"error": "Admin no autenticado con Spotify"}), 401
    
    # Verificar si el token necesita refresco automático
    expires_at_aware = ensure_aware_datetime(admin_spotify_token['expires_at'])
    if datetime.now(timezone.utc) > expires_at_aware:
        print("🔄 Token expirado, intentando refrescar automáticamente...")
        if not refresh_admin_spotify_token():
            print("❌ No se pudo refrescar el token automáticamente")
            return jsonify({"error": "Token de Spotify expirado y no se pudo refrescar"}), 401
        else:
            print("✅ Token refrescado automáticamente")
    
    # Obtener la canción actual
    access_token = admin_spotify_token['access_token']
    headers = {'Authorization': f'Bearer {access_token}'}
    
    try:
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
            else:
                currently_playing_cache = {'is_playing': False}
            
            # Cachear por 10 segundos
            cache_expiration = datetime.now(timezone.utc) + timedelta(seconds=10)
            return jsonify(currently_playing_cache), 200
            
        elif response.status_code == 204:
            currently_playing_cache = {'is_playing': False}
            cache_expiration = datetime.now(timezone.utc) + timedelta(seconds=10)
            return jsonify(currently_playing_cache), 200
            
        elif response.status_code == 401:
            # Token inválido, intentar refrescar
            print("🔄 Token inválido, intentando refrescar...")
            if refresh_admin_spotify_token():
                # Reintentar con el nuevo token
                access_token = admin_spotify_token['access_token']
                headers = {'Authorization': f'Bearer {access_token}'}
                response = requests.get(
                    'https://api.spotify.com/v1/me/player/currently-playing', 
                    headers=headers,
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    # Procesar respuesta exitosa...
                    # ... (código similar al de arriba)
                    return jsonify(currently_playing_cache), 200
            return jsonify({"error": "Token inválido y no se pudo refrescar"}), 401
            
        else:
            print(f"❌ Error en API de Spotify: {response.status_code}")
            return jsonify({"error": f"Error en API de Spotify: {response.status_code}"}), response.status_code
            
    except Exception as e:
        print(f"❌ Error al obtener reproducción actual: {e}")
        return jsonify({"error": str(e)}), 500

# Endpoint para que el admin configure su Spotify
@app.route('/api/spotify/auth', methods=['GET'])
def spotify_auth():
    """Iniciar el flujo de autenticación de Spotify para usuarios regulares"""
    scope = 'user-read-currently-playing user-read-playback-state user-modify-playback-state'
    auth_url = f"https://accounts.spotify.com/authorize?response_type=code&client_id={SPOTIFY_CLIENT_ID}&scope={scope}&redirect_uri={SPOTIFY_REDIRECT_URI}"
    return jsonify({"authUrl": auth_url}), 200

@app.route('/api/spotify/admin/queue', methods=['GET'])
def get_queue():
    """Obtener la cola de reproducción actual"""
    if not verify_jwt_auth():
        return jsonify({"error": "Credenciales inválidas"}), 401
        
    if not admin_spotify_token or not admin_spotify_token.get('access_token'):
        return jsonify({"error": "Admin no autenticado con Spotify"}), 401
    
    # Verificar si el token necesita refresco
    expires_at = ensure_aware_datetime(admin_spotify_token['expires_at'])
    if datetime.now(timezone.utc) > expires_at:
        if not refresh_admin_spotify_token():
            return jsonify({"error": "Token de Spotify expirado"}), 401
    
    # Obtener la cola
    access_token = admin_spotify_token['access_token']
    headers = {'Authorization': f'Bearer {access_token}'}
    
    try:
        response = requests.get(
            'https://api.spotify.com/v1/me/player/queue',
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            queue_data = response.json()
            return jsonify({
                "currently_playing": queue_data.get('currently_playing'),
                "queue": queue_data.get('queue', [])
            }), 200
        else:
            print(f"❌ Error obteniendo cola: {response.status_code} - {response.text}")
            return jsonify({"error": f"Error al obtener cola: {response.status_code}"}), response.status_code
            
    except Exception as e:
        print(f"❌ Error al obtener cola: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

# Endpoint para agregar canciones a la cola de reproducción
@app.route('/api/spotify/admin/queue', methods=['DELETE'])
def remove_from_queue():
    """Eliminar una canción específica de la cola"""
    if not verify_jwt_auth():
        return jsonify({"error": "Credenciales inválidas"}), 401
        
    data = request.get_json()
    track_uri = data.get('uri')
    
    if not track_uri:
        return jsonify({"error": "URI de canción requerida"}), 400
        
    if not admin_spotify_token or not admin_spotify_token.get('access_token'):
        return jsonify({"error": "Admin no autenticado con Spotify"}), 401
    
    # Verificar si el token necesita refresco
    expires_at = ensure_aware_datetime(admin_spotify_token['expires_at'])
    if datetime.now(timezone.utc) > expires_at:
        if not refresh_admin_spotify_token():
            return jsonify({"error": "Token de Spotify expirado"}), 401
    
    # Spotify Web API no tiene endpoint directo para eliminar de la cola
    # Esta es una implementación alternativa
    access_token = admin_spotify_token['access_token']
    headers = {'Authorization': f'Bearer {access_token}'}
    
    try:
        # Obtener la cola actual
        queue_response = requests.get(
            'https://api.spotify.com/v1/me/player/queue',
            headers=headers,
            timeout=10
        )
        
        if queue_response.status_code != 200:
            return jsonify({"error": "No se pudo obtener la cola"}), 500
            
        queue_data = queue_response.json()
        
        # Buscar la posición de la canción en la cola
        track_position = None
        for i, item in enumerate(queue_data['queue']):
            if item['uri'] == track_uri:
                track_position = i
                break
                
        if track_position is None:
            return jsonify({"error": "Canción no encontrada en la cola"}), 404
            
        # Para "eliminar" la canción, necesitamos saltar hasta su posición
        # Esto es un workaround ya que Spotify no permite eliminar directamente
        for _ in range(track_position + 1):
            response = requests.post(
                'https://api.spotify.com/v1/me/player/next',
                headers=headers,
                timeout=10
            )
            time.sleep(0.5)  # Pequeña pausa entre saltos
            
        return jsonify({"message": "Canción eliminada de la cola"}), 200
            
    except Exception as e:
        print(f"Error eliminando de la cola: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

# Endpoint para obtener la cola de reproducción actual
@app.route('/api/spotify/admin/queue', methods=['POST'])
def add_to_queue():
    """Agregar una canción a la cola de reproducción"""
    if not verify_jwt_auth():
        return jsonify({"error": "Credenciales inválidas"}), 401
        
    data = request.get_json()
    track_uri = data.get('uri')
    
    if not track_uri:
        return jsonify({"error": "URI de canción requerida"}), 400
        
    if not admin_spotify_token or not admin_spotify_token.get('access_token'):
        return jsonify({"error": "Admin no autenticado con Spotify"}), 401
    
    # Verificar si el token necesita refresco
    expires_at = ensure_aware_datetime(admin_spotify_token['expires_at'])
    if datetime.now(timezone.utc) > expires_at:
        if not refresh_admin_spotify_token():
            return jsonify({"error": "Token de Spotify expirado"}), 401
    
    # Agregar a la cola
    access_token = admin_spotify_token['access_token']
    headers = {'Authorization': f'Bearer {access_token}'}
    
    try:
        response = requests.post(
            'https://api.spotify.com/v1/me/player/queue',
            headers=headers,
            params={'uri': track_uri},
            timeout=10
        )
        
        if response.status_code in [200, 204]:
            return jsonify({"message": "Canción agregada a la cola"}), 200
        else:
            return jsonify({"error": f"Error al agregar a la cola: {response.status_code}"}), response.status_code
            
    except Exception as e:
        print(f"Error agregando a la cola: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500
        
@app.route('/api/spotify/admin/auth', methods=['GET'])
def admin_spotify_auth():
    """Iniciar el flujo de autenticación de Spotify para el admin"""
    scope = 'user-read-currently-playing user-read-playback-state user-modify-playback-state'
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
    
    try:
        response = requests.post(token_url, data=data)
        if response.status_code != 200:
            print(f"❌ Error al obtener token de acceso: {response.status_code} - {response.text}")
            return jsonify({"error": "Error al obtener token de acceso"}), 400
            
        token_data = response.json()
        access_token = token_data['access_token']
        refresh_token = token_data.get('refresh_token')
        expires_in = token_data['expires_in']
        
        print(f"✅ Token obtenido de Spotify. Refresh token presente: {refresh_token is not None}")
        
        # Determinar si es para el admin o para usuario general
        if state == 'admin':
            global admin_spotify_token
            
            # Asegurar que tenemos refresh_token
            if not refresh_token:
                # Si no hay refresh_token en la respuesta, intentar usar uno existente
                if admin_spotify_token and 'refresh_token' in admin_spotify_token:
                    refresh_token = admin_spotify_token['refresh_token']
                    print("ℹ️  Usando refresh_token existente")
                else:
                    print("❌ Error: No se obtuvo refresh_token en la autenticación")
                    return jsonify({"error": "Error de autenticación: falta refresh_token"}), 400
            
            # Guardar token del admin - usar UTC
            admin_spotify_token = {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'expires_at': datetime.now(timezone.utc) + timedelta(seconds=expires_in)
            }
            
            # Guardar en base de datos usando la nueva función
            if not save_admin_spotify_token(admin_spotify_token):
                print("❌ Error crítico: No se pudo guardar el token en la base de datos")
                return jsonify({"error": "Error al guardar configuración"}), 500
            
            # Iniciar polling si no está activo
            global polling_active, polling_thread
            if not polling_active:
                polling_thread = start_spotify_polling()
                print("✅ Polling de Spotify iniciado")
            
            # Redirigir al panel de administración con mensaje de éxito
            return redirect('https://uptcmusic.com/admin-panel')
        else:
            # Para usuarios regulares
            return jsonify({
                "message": "Autenticación exitosa", 
                "access_token": access_token
            }), 200
            
    except Exception as e:
        print(f"❌ Error en callback de Spotify: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500
    
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
    
    # Verificar autenticación
    if not verify_jwt_auth():
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

@app.route('/api/ranking/history', methods=['GET'])
def get_song_history():
    """Obtener el ranking histórico de canciones"""
    try:
        # Obtener parámetros de ordenamiento
        sort_by = request.args.get('sort_by', 'times_played')
        order = request.args.get('order', 'desc')
        
        # Validar parámetros de ordenamiento
        valid_sort_columns = ['times_played', 'total_votes', 'total_dislikes', 'last_played_at', 'first_played_at']
        if sort_by not in valid_sort_columns:
            sort_by = 'times_played'
        
        if order not in ['asc', 'desc']:
            order = 'desc'
            
        # Obtener canciones del histórico
        result = supabase.table('song_history')\
            .select('*')\
            .order(sort_by, desc=(order == 'desc'))\
            .execute()
            
        return jsonify(result.data), 200
        
    except Exception as e:
        print(f"❌ Error al obtener ranking histórico: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

# Endpoint para agregar/actualizar una canción en el histórico
@app.route('/api/ranking/add-to-history', methods=['POST'])
def add_to_song_history():
    """Agregar o actualizar una canción en el histórico"""
    # Verificar autenticación
    if not verify_jwt_auth():
        return jsonify({"error": "Credenciales inválidas"}), 401
        
    try:
        data = request.get_json()
        track_id = data.get('track_id')
        
        if not track_id:
            return jsonify({"error": "ID de canción requerido"}), 400
            
        # Verificar si la canción ya existe en el histórico
        result = supabase.table('song_history')\
            .select('*')\
            .eq('track_id', track_id)\
            .execute()
            
        current_time = datetime.now(timezone.utc).isoformat()
        
        if result.data and len(result.data) > 0:
            # Actualizar canción existente
            existing_song = result.data[0]
            update_data = {
                'times_played': existing_song['times_played'] + 1,
                'last_played_at': current_time,
                'updated_at': current_time
            }
            
            # Si se proporcionan votos, actualizarlos también
            if 'votes' in data:
                update_data['total_votes'] = existing_song['total_votes'] + data['votes']
            if 'dislikes' in data:
                update_data['total_dislikes'] = existing_song['total_dislikes'] + data['dislikes']
                
            # Actualizar en la base de datos
            supabase.table('song_history')\
                .update(update_data)\
                .eq('track_id', track_id)\
                .execute()
                
            return jsonify({"message": "Canción actualizada en histórico", "action": "updated"}), 200
        else:
            # Crear nueva entrada en el histórico
            # Primero obtener información completa de la canción desde song_ranking
            song_result = supabase.table('song_ranking')\
                .select('*')\
                .eq('id', track_id)\
                .execute()
                
            if not song_result.data or len(song_result.data) == 0:
                return jsonify({"error": "Canción no encontrada en ranking"}), 404
                
            song_data = song_result.data[0]
            new_song = {
                'track_id': track_id,
                'name': song_data['name'],
                'artists': song_data['artists'],
                'image': song_data.get('image', ''),
                'preview_url': song_data.get('preview_url', ''),
                'total_votes': song_data.get('votes', 0),
                'total_dislikes': song_data.get('dislikes', 0),
                'times_played': 1,
                'last_played_at': current_time,
                'first_played_at': current_time,
                'created_at': current_time,
                'updated_at': current_time
            }
            
            # Insertar en la base de datos
            supabase.table('song_history').insert(new_song).execute()
            
            return jsonify({"message": "Canción agregada al histórico", "action": "created"}), 201
            
    except Exception as e:
        print(f"❌ Error al agregar al histórico: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

# Endpoint para que los usuarios voten por canciones desde el ranking histórico
@app.route('/api/ranking/vote-from-history', methods=['POST'])
def vote_from_history():
    """Votar por una canción desde el ranking histórico"""
    try:
        data = request.get_json()
        track_id = data.get('track_id')
        
        if not track_id:
            return jsonify({"error": "ID de canción requerido"}), 400
            
        # Obtener información de la canción del histórico
        result = supabase.table('song_history')\
            .select('*')\
            .eq('track_id', track_id)\
            .execute()
            
        if not result.data or len(result.data) == 0:
            return jsonify({"error": "Canción no encontrada en histórico"}), 404
            
        song_data = result.data[0]
        
        # Preparar datos para el voto (similar al endpoint de voto normal)
        track_info = {
            'name': song_data['name'],
            'artists': song_data['artists'],
            'image': song_data.get('image', ''),
            'preview_url': song_data.get('preview_url', '')
        }
        
        # Usar la misma lógica que el endpoint de voto normal
        user_fingerprint = get_user_fingerprint()
        
        # Verificar si este usuario ya votó por esta canción
        existing_vote = supabase.table('votes')\
            .select('*')\
            .eq('trackid', track_id)\
            .eq('userFingerprint', user_fingerprint)\
            .execute()
            
        if len(existing_vote.data) > 0:
            return jsonify({"error": "Ya has votado por esta canción"}), 409
            
        # Registrar el nuevo voto
        vote_data = {
            'trackid': track_id,
            'userFingerprint': user_fingerprint,
            'ipAddress': request.remote_addr,
            'userAgent': request.headers.get('User-Agent', ''),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'is_dislike': False
        }
        
        # Añadir el voto
        supabase.table('votes').insert(vote_data).execute()
        
        # Actualizar el contador de votos en la canción del ranking actual
        try:
            # Verificar si la canción ya existe en el ranking actual
            existing_song = supabase.table('song_ranking')\
                .select('*')\
                .eq('id', track_id)\
                .execute()
                
            if len(existing_song.data) > 0:
                # Incrementar el contador existente
                current_song = existing_song.data[0]
                update_data = {
                    'votes': current_song['votes'] + 1,
                    'lastvoted': datetime.now(timezone.utc).isoformat()
                }
                
                supabase.table('song_ranking')\
                    .update(update_data)\
                    .eq('id', track_id)\
                    .execute()
            else:
                # Crear nueva entrada en el ranking
                song_data = {
                    'id': track_id,
                    'name': track_info['name'],
                    'artists': track_info['artists'],
                    'image': track_info['image'],
                    'preview_url': track_info['preview_url'],
                    'votes': 1,
                    'dislikes': 0,
                    'lastvoted': datetime.now(timezone.utc).isoformat(),
                    'createdat': datetime.now(timezone.utc).isoformat()
                }
                supabase.table('song_ranking').insert(song_data).execute()
                
        except Exception as e:
            print(f"Error actualizando ranking: {e}")
            return jsonify({"error": "Error al actualizar ranking"}), 500
            
        return jsonify({"message": "Voto registrado correctamente"}), 200
            
    except Exception as e:
        print(f"❌ Error al votar desde histórico: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

# Ruta de login mejorada
@app.route('/api/auth/login', methods=['POST'])
def login():
    """Iniciar sesión con JWT"""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        # Buscar usuario en la base de datos
        result = supabase.table('admin_users').select('*').eq('email', email).execute()
        if not result.data:
            return jsonify({"error": "Credenciales inválidas"}), 401
            
        user = result.data[0]
        
        # Verificar contraseña
        if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            return jsonify({"error": "Credenciales inválidas"}), 401
            
        # Generar token JWT
        token = jwt.encode({
            'user_id': user['id'],
            'exp': datetime.now(timezone.utc) + timedelta(hours=24)
        }, JWT_SECRET, algorithm=JWT_ALGORITHM)
        
        return jsonify({
            "token": token,
            "user": {
                "id": user['id'],
                "email": user['email']
            }
        }), 200
            
    except Exception as e:
        print(f"Error en login: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500
        
# Endpoint para autenticación
@app.route('/api/auth', methods=['POST', 'OPTIONS'])
def handle_auth():
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        # Redirigir al nuevo endpoint de login con JWT
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        # Buscar usuario en la base de datos
        result = supabase.table('admin_users').select('*').eq('email', email).execute()
        if not result.data:
            return jsonify({"error": "Credenciales inválidas"}), 401
            
        user = result.data[0]
        
        # Verificar contraseña
        if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            return jsonify({"error": "Credenciales inválidas"}), 401
            
        # Generar token JWT
        token = jwt.encode({
            'user_id': user['id'],
            'exp': datetime.now(timezone.utc) + timedelta(hours=24)
        }, JWT_SECRET, algorithm=JWT_ALGORITHM)
        
        return jsonify({
            "success": True,
            "token": token,
            "user": {
                "id": user['id'],
                "email": user['email']
            },
            "message": "Autenticación exitosa"
        }), 200
            
    except Exception as e:
        print(f"Error en autenticación: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

# Endpoints para control de reproducción de Spotify del admin
@app.route('/api/spotify/admin/play', methods=['POST'])
def admin_play_track():
    """Reproducir una canción específica"""
    if not verify_jwt_auth():
        return jsonify({"error": "Credenciales inválidas"}), 401
        
    data = request.get_json()
    track_uri = data.get('uri')
    
    if not track_uri:
        return jsonify({"error": "URI de canción requerida"}), 400
        
    if not admin_spotify_token or not admin_spotify_token.get('access_token'):
        return jsonify({"error": "Admin no autenticado con Spotify"}), 401
    
    # Verificar si el token necesita refresco
    expires_at = ensure_aware_datetime(admin_spotify_token['expires_at'])
    if datetime.now(timezone.utc) > expires_at:
        if not refresh_admin_spotify_token():
            return jsonify({"error": "Token de Spotify expirado"}), 401
    
    # Reproducir la canción
    access_token = admin_spotify_token['access_token']
    headers = {'Authorization': f'Bearer {access_token}'}
    
    try:
        # Primero pausar la reproducción actual
        requests.put(
            'https://api.spotify.com/v1/me/player/pause',
            headers=headers,
            timeout=10
        )
        
        # Reproducir la canción específica
        response = requests.put(
            'https://api.spotify.com/v1/me/player/play',
            headers=headers,
            json={'uris': [track_uri]},
            timeout=10
        )
        
        if response.status_code in [200, 204]:
            return jsonify({"message": "Canción reproducida"}), 200
        else:
            return jsonify({"error": f"Error al reproducir: {response.status_code}"}), response.status_code
            
    except Exception as e:
        print(f"Error en play_track: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

@app.route('/api/spotify/admin/pause', methods=['PUT'])
def admin_pause_playback():
    """Pausar la reproducción"""
    if not verify_jwt_auth():
        return jsonify({"error": "Credenciales inválidas"}), 401
        
    if not admin_spotify_token or not admin_spotify_token.get('access_token'):
        return jsonify({"error": "Admin no autenticado con Spotify"}), 401
    
    # Verificar si el token necesita refresco
    expires_at = ensure_aware_datetime(admin_spotify_token['expires_at'])
    if datetime.now(timezone.utc) > expires_at:
        if not refresh_admin_spotify_token():
            return jsonify({"error": "Token de Spotify expirado"}), 401
    
    # Pausar reproducción
    access_token = admin_spotify_token['access_token']
    headers = {'Authorization': f'Bearer {access_token}'}
    
    try:
        response = requests.put(
            'https://api.spotify.com/v1/me/player/pause',
            headers=headers,
            timeout=10
        )
        
        if response.status_code in [200, 204]:
            return jsonify({"message": "Reproducción pausada"}), 200
        else:
            return jsonify({"error": f"Error al pausar: {response.status_code}"}), response.status_code
            
    except Exception as e:
        print(f"Error en pause_playback: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

@app.route('/api/spotify/admin/resume', methods=['PUT'])
def admin_resume_playback():
    """Reanudar la reproducción"""
    if not verify_jwt_auth():
        return jsonify({"error": "Credenciales inválidas"}), 401
        
    if not admin_spotify_token or not admin_spotify_token.get('access_token'):
        return jsonify({"error": "Admin no autenticado con Spotify"}), 401
    
    # Verificar si el token necesita refresco
    expires_at = ensure_aware_datetime(admin_spotify_token['expires_at'])
    if datetime.now(timezone.utc) > expires_at:
        if not refresh_admin_spotify_token():
            return jsonify({"error": "Token de Spotify expirado"}), 401
    
    # Reanudar reproducción
    access_token = admin_spotify_token['access_token']
    headers = {'Authorization': f'Bearer {access_token}'}
    
    try:
        response = requests.put(
            'https://api.spotify.com/v1/me/player/play',
            headers=headers,
            timeout=10
        )
        
        if response.status_code in [200, 204]:
            return jsonify({"message": "Reproducción reanudada"}), 200
        else:
            return jsonify({"error": f"Error al reanudar: {response.status_code}"}), response.status_code
            
    except Exception as e:
        print(f"Error en resume_playback: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

@app.route('/api/spotify/admin/next', methods=['POST'])
def admin_next_track():
    """Siguiente canción"""
    if not verify_jwt_auth():
        return jsonify({"error": "Credenciales inválidas"}), 401
        
    if not admin_spotify_token or not admin_spotify_token.get('access_token'):
        return jsonify({"error": "Admin no autenticado con Spotify"}), 401
    
    # Verificar si el token necesita refresco
    expires_at = ensure_aware_datetime(admin_spotify_token['expires_at'])
    if datetime.now(timezone.utc) > expires_at:
        if not refresh_admin_spotify_token():
            return jsonify({"error": "Token de Spotify expirado"}), 401
    
    # Siguiente canción
    access_token = admin_spotify_token['access_token']
    headers = {'Authorization': f'Bearer {access_token}'}
    
    try:
        response = requests.post(
            'https://api.spotify.com/v1/me/player/next',
            headers=headers,
            timeout=10
        )
        
        if response.status_code in [200, 204]:
            return jsonify({"message": "Siguiente canción"}), 200
        else:
            return jsonify({"error": f"Error: {response.status_code}"}), response.status_code
            
    except Exception as e:
        print(f"Error en next_track: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

@app.route('/api/spotify/admin/previous', methods=['POST'])
def admin_previous_track():
    """Canción anterior"""
    if not verify_jwt_auth():
        return jsonify({"error": "Credenciales inválidas"}), 401
        
    if not admin_spotify_token or not admin_spotify_token.get('access_token'):
        return jsonify({"error": "Admin no autenticado con Spotify"}), 401
    
    # Verificar si el token necesita refresco
    expires_at = ensure_aware_datetime(admin_spotify_token['expires_at'])
    if datetime.now(timezone.utc) > expires_at:
        if not refresh_admin_spotify_token():
            return jsonify({"error": "Token de Spotify expirado"}), 401
    
    # Canción anterior
    access_token = admin_spotify_token['access_token']
    headers = {'Authorization': f'Bearer {access_token}'}
    
    try:
        response = requests.post(
            'https://api.spotify.com/v1/me/player/previous',
            headers=headers,
            timeout=10
        )
        
        if response.status_code in [200, 204]:
            return jsonify({"message": "Canción anterior"}), 200
        else:
            return jsonify({"error": f"Error: {response.status_code}"}), response.status_code
            
    except Exception as e:
        print(f"Error en previous_track: {e}")
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
        is_dislike = data.get('is_dislike', False)
        track_info = data.get('trackInfo', {})
        
        if not track_id:
            return jsonify({"error": "ID de canción requerido"}), 400
            
        # Obtener fingerprint único del usuario (IP + User-Agent)
        user_fingerprint = get_user_fingerprint()
        
        # Verificar si este usuario ya votó por esta canción (like o dislike)
        try:
            existing_vote = supabase.table('votes')\
                .select('*')\
                .eq('trackid', track_id)\
                .eq('userFingerprint', user_fingerprint)\
                .execute()
            
            if len(existing_vote.data) > 0:
                # Si ya votó, verificar si está intentando cambiar su voto
                existing_vote_data = existing_vote.data[0]
                if existing_vote_data['is_dislike'] == is_dislike:
                    vote_type = "dislike" if is_dislike else "like"
                    return jsonify({"error": f"Ya has dado {vote_type} a esta canción"}), 409
                else:
                    # Cambiar el voto (de like a dislike o viceversa)
                    return change_vote(track_id, user_fingerprint, is_dislike, track_info)
        except Exception as e:
            print(f"❌ Error verificando voto existente: {e}")
            return jsonify({"error": "Error al verificar voto"}), 500
            
        # Registrar el nuevo voto
        vote_data = {
            'trackid': track_id,
            'userFingerprint': user_fingerprint,
            'ipAddress': request.remote_addr,
            'userAgent': request.headers.get('User-Agent', ''),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'is_dislike': is_dislike
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
                current_song = existing_song.data[0]
                update_data = {
                    'votes': current_song['votes'] + (0 if is_dislike else 1),
                    'dislikes': current_song.get('dislikes', 0) + (1 if is_dislike else 0),
                    'lastvoted': datetime.now(timezone.utc).isoformat()
                }
                
                supabase.table('song_ranking')\
                    .update(update_data)\
                    .eq('id', track_id)\
                    .execute()
            else:
                # Crear nueva entrada en el ranking
                song_data = {
                    'id': track_id,
                    'name': track_info.get('name', 'Unknown'),
                    'artists': track_info.get('artists', []),
                    'image': track_info.get('image', ''),
                    'preview_url': track_info.get('preview_url', ''),
                    'votes': 0 if is_dislike else 1,
                    'dislikes': 1 if is_dislike else 0,
                    'lastvoted': datetime.now(timezone.utc).isoformat(),
                    'createdat': datetime.now(timezone.utc).isoformat(),
                }
                supabase.table('song_ranking').insert(song_data).execute()
            
        except Exception as e:
            print(f"❌ Error actualizando ranking: {e}")
            return jsonify({"error": "Error al actualizar ranking"}), 500
        
        return jsonify({"message": "Voto registrado correctamente"}), 200
            
    except Exception as e:
        print(f"❌ Error al registrar voto: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

def change_vote(track_id, user_fingerprint, new_is_dislike, track_info):
    """Cambiar un voto existente de like a dislike o viceversa"""
    try:
        # Actualizar el tipo de voto
        supabase.table('votes')\
            .update({'is_dislike': new_is_dislike})\
            .eq('trackid', track_id)\
            .eq('userFingerprint', user_fingerprint)\
            .execute()
        
        # Actualizar los contadores en la canción
        existing_song = supabase.table('song_ranking')\
            .select('*')\
            .eq('id', track_id)\
            .execute()
            
        if len(existing_song.data) > 0:
            current_song = existing_song.data[0]
            update_data = {
                'lastvoted': datetime.now(timezone.utc).isoformat()
            }
            
            if new_is_dislike:
                # Cambió de like a dislike
                update_data['votes'] = current_song['votes'] - 1
                update_data['dislikes'] = current_song.get('dislikes', 0) + 1
            else:
                # Cambió de dislike a like
                update_data['votes'] = current_song['votes'] + 1
                update_data['dislikes'] = current_song.get('dislikes', 0) - 1
            
            supabase.table('song_ranking')\
                .update(update_data)\
                .eq('id', track_id)\
                .execute()
                
            # Verificar si la canción tiene 10 dislikes después del cambio
            if new_is_dislike and update_data['dislikes'] >= 10:
                delete_song_from_ranking(track_id)
                return jsonify({
                    "message": "Voto cambiado correctamente", 
                    "deleted": True
                }), 200
                
        return jsonify({
            "message": "Voto cambiado correctamente", 
            "deleted": False
        }), 200
            
    except Exception as e:
        print(f"Error al cambiar voto: {e}")
        return jsonify({"error": "Error al cambiar voto"}), 500

def delete_song_from_ranking(track_id):
    """Eliminar una canción del ranking por tener demasiados dislikes"""
    try:
        # Eliminar la canción del ranking
        supabase.table('song_ranking').delete().eq('id', track_id).execute()
        
        # También eliminar todos los votos asociados a esta canción
        supabase.table('votes').delete().eq('trackid', track_id).execute()
        
        print(f"✅ Canción {track_id} eliminada por alcanzar 10 dislikes")
    except Exception as e:
        print(f"Error eliminando canción por dislikes: {e}")

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
                'dislikes': song.get('dislikes', 0),
                'createdat': song['createdat'] 
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
        if not verify_jwt_auth():
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

def save_admin_spotify_token(token_data):
    """Guardar token de Spotify en Supabase con manejo robusto de errores"""
    try:
        print(f"💾 Intentando guardar token en Supabase: {SUPABASE_URL}")
        
        # Verificar que la conexión a Supabase funciona
        try:
            test_result = supabase.table('admin_settings').select('count', count='exact').execute()
            print(f"✅ Conexión a Supabase verificada: {test_result}")
        except Exception as e:
            print(f"❌ Error de conexión a Supabase: {e}")
            return False
        
        # Convertir datetime a string ISO para serialización JSON
        token_data_copy = token_data.copy()
        if 'expires_at' in token_data_copy and isinstance(token_data_copy['expires_at'], datetime):
            token_data_copy['expires_at'] = token_data_copy['expires_at'].isoformat()
        
        # Preparar datos para upsert
        settings_data = {
            'id': 'spotify',
            'token_data': token_data_copy,  # Usar la copia con datetime convertido
            'updated_at': datetime.now(timezone.utc).isoformat()
        }
        
        print(f"📦 Datos a guardar: {json.dumps(settings_data, indent=2, default=str)}")
        
        # Intentar upsert
        result = supabase.table('admin_settings').upsert(settings_data).execute()
        
        print(f"✅ Token guardado exitosamente en Supabase: {result}")
        return True
        
    except Exception as e:
        print(f"❌ Error crítico al guardar token en Supabase: {e}")
        # Intentar crear el registro si no existe
        try:
            print("🔄 Intentando insert en lugar de upsert...")
            result = supabase.table('admin_settings').insert(settings_data).execute()
            print(f"✅ Token insertado exitosamente: {result}")
            return True
        except Exception as insert_error:
            print(f"❌ Error también en insert: {insert_error}")
            return False

def start_token_verification():
    """Verificar periódicamente el estado del token y refrescar si es necesario"""
    def verify_token():
        while True:
            try:
                if admin_spotify_token and admin_spotify_token.get('access_token'):
                    # Verificar si el token expirará en los próximos 5 minutos
                    expires_at = ensure_aware_datetime(admin_spotify_token['expires_at'])
                    time_until_expiry = expires_at - datetime.now(timezone.utc)
                    
                    if time_until_expiry.total_seconds() < 300:  # 5 minutos
                        print("🔄 Token expirará pronto, refrescando preventivamente...")
                        refresh_admin_spotify_token()
                
                time.sleep(60)  # Verificar cada minuto
            except Exception as e:
                print(f"Error en verificación periódica de token: {e}")
                time.sleep(300)  # Esperar 5 minutos en caso de error
    
    thread = threading.Thread(target=verify_token)
    thread.daemon = True
    thread.start()
    print("✅ Verificación periódica de token iniciada")

@app.route('/api/votes/all', methods=['DELETE', 'OPTIONS'])
def delete_all_votes():
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        # Verificar autenticación 
        if not verify_jwt_auth():
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
    """Cargar el token de Spotify del admin desde la base de datos con verificación robusta"""
    global admin_spotify_token, polling_thread, polling_active
    
    try:
        print("🔍 Intentando cargar token de Spotify desde Supabase...")
        
        result = supabase.table('admin_settings').select('*').eq('id', 'spotify').execute()
        print(f"📦 Resultado de la consulta: {result}")
        
        if result.data and len(result.data) > 0:
            stored_token = result.data[0]['token_data']
            print(f"✅ Token encontrado en BD: {json.dumps(stored_token, indent=2)}")
            
            # Convertir string ISO de vuelta a datetime si es necesario
            if 'expires_at' in stored_token and isinstance(stored_token['expires_at'], str):
                stored_token['expires_at'] = datetime.fromisoformat(stored_token['expires_at'].replace('Z', '+00:00'))
            
            # Resto del código permanece igual...
            admin_spotify_token = stored_token
            
            # Verificar si el token necesita refresco
            expires_at = ensure_aware_datetime(admin_spotify_token['expires_at'])
            time_until_expiry = expires_at - datetime.now(timezone.utc)
            
            print(f"⏰ Tiempo hasta expiración: {time_until_expiry.total_seconds()} segundos")
            
            # Resto del código...
                
    except Exception as e:
        print(f"❌ Error cargando token de admin: {e}")
        admin_spotify_token = None

start_token_verification()

@app.route('/api/spotify/admin/refresh-token', methods=['POST'])
def admin_refresh_token():
    """Forzar el refresco del token de Spotify del admin"""
    global admin_spotify_token
    
    # Verificar autenticación
    if not verify_jwt_auth():
        return jsonify({"error": "Credenciales inválidas"}), 401
        
    if refresh_admin_spotify_token():
        return jsonify({"message": "Token refrescado correctamente"}), 200
    else:
        return jsonify({"error": "No se pudo refrescar el token"}), 500

@app.route('/api/schedules', methods=['GET'])
def get_schedules():
    """Obtener todos los horarios de música"""
    try:
        result = supabase.table('music_schedules').select('*').order('day_of_week').execute()
        
        # Formatear los datos para que coincidan con lo que espera Angular
        formatted_schedules = []
        for schedule in result.data:
            formatted_schedule = {
                'id': schedule['id'],
                'day_of_week': schedule['day_of_week'],
                'lunch_start': schedule['lunch_start'],
                'lunch_end': schedule['lunch_end'],
                'dinner_start': schedule['dinner_start'],
                'dinner_end': schedule['dinner_end'],
                'is_active': schedule['is_active']
            }
            formatted_schedules.append(formatted_schedule)
        
        return jsonify(formatted_schedules), 200
    except Exception as e:
        print(f"Error obteniendo horarios: {e}")
        return jsonify({"error": "Error al obtener horarios"}), 500

@app.route('/api/ranking/stats', methods=['GET'])
def get_ranking_stats():
    """Obtener estadísticas del ranking histórico"""
    try:
        # Obtener total de canciones
        songs_count = supabase.table('song_history')\
            .select('count', count='exact')\
            .execute()
        
        # Obtener total de reproducciones
        total_plays = supabase.table('song_history')\
            .select('times_played')\
            .execute()
        
        total_plays_sum = sum(song['times_played'] for song in total_plays.data) if total_plays.data else 0
        
        # Obtener total de votos y dislikes
        total_votes = supabase.table('song_history')\
            .select('total_votes')\
            .execute()
        
        total_votes_sum = sum(song['total_votes'] for song in total_votes.data) if total_votes.data else 0
        
        total_dislikes = supabase.table('song_history')\
            .select('total_dislikes')\
            .execute()
        
        total_dislikes_sum = sum(song['total_dislikes'] for song in total_dislikes.data) if total_dislikes.data else 0
        
        return jsonify({
            "totalSongs": songs_count.count if songs_count else 0,
            "totalPlays": total_plays_sum,
            "totalVotes": total_votes_sum,
            "totalDislikes": total_dislikes_sum
        }), 200
        
    except Exception as e:
        print(f"❌ Error al obtener estadísticas del ranking: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500

# Ruta para actualizar horarios (requiere autenticación)
@app.route('/api/schedules', methods=['PUT'])
def update_schedules():
    """Actualizar horarios de música"""
    # Verificar autenticación
    if not verify_jwt_auth():
        return jsonify({"error": "No autorizado"}), 401
        
    try:
        data = request.get_json()
        
        # Actualizar cada horario
        for schedule in data:
            supabase.table('music_schedules').update({
                'lunch_start': schedule.get('lunch_start'),
                'lunch_end': schedule.get('lunch_end'),
                'dinner_start': schedule.get('dinner_start'),
                'dinner_end': schedule.get('dinner_end'),
                'is_active': schedule.get('is_active', True),
                'updated_at': datetime.now(timezone.utc).isoformat()
            }).eq('id', schedule['id']).execute()
            
        return jsonify({"message": "Horarios actualizados correctamente"}), 200
    except Exception as e:
        print(f"Error actualizando horarios: {e}")
        return jsonify({"error": "Error al actualizar horarios"}), 500

# Llamar a la función de carga al iniciar
load_admin_spotify_token()

@app.route('/api/voting/status', methods=['GET'])
def get_voting_status():
    """Obtener el estado actual de la votación"""
    try:
        status = voting_manager.get_voting_status()
        return jsonify(status), 200
    except Exception as e:
        print(f"❌ Error obteniendo estado de votación: {e}")
        return jsonify({"error": "Error al obtener estado de votación"}), 500

@app.route('/api/voting/vote', methods=['POST'])
def handle_voting():
    """Manejar votos de usuarios"""
    try:
        data = request.get_json()
        vote_type = data.get('vote_type')
        
        if not vote_type or vote_type not in ['next', 'genre_change', 'repeat']:
            return jsonify({"error": "Tipo de voto no válido"}), 400
        
        user_fingerprint = get_user_fingerprint()
        success, message = voting_manager.vote(vote_type, user_fingerprint)
        
        if success:
            return jsonify({"message": message, "status": voting_manager.get_voting_status()}), 200
        else:
            return jsonify({"error": message}), 400
            
    except Exception as e:
        print(f"❌ Error procesando voto: {e}")
        return jsonify({"error": "Error al procesar voto"}), 500

@app.route('/api/spotify/admin/add-to-history-confirmed', methods=['POST'])
def admin_add_to_history_confirmed():
    """Agregar la canción actual al histórico con confirmación y verificación de tiempo"""
    # Verificar autenticación
    if not verify_jwt_auth():
        return jsonify({"error": "Credenciales inválidas"}), 401
        
    global currently_playing_cache
    
    # Verificar si hay una canción reproduciéndose
    if not currently_playing_cache or not currently_playing_cache.get('is_playing'):
        return jsonify({"error": "No hay canción reproduciéndose actualmente"}), 400
    
    track_id = currently_playing_cache.get('id')
    if not track_id:
        return jsonify({"error": "No se pudo obtener ID de la canción"}), 400
    
    try:
        # Obtener votos actuales si existe en ranking
        votes = 0
        dislikes = 0
        
        result = supabase.table('song_ranking').select('*').eq('id', track_id).execute()
        if result.data and len(result.data) > 0:
            song_data = result.data[0]
            votes = song_data.get('votes', 0)
            dislikes = song_data.get('dislikes', 0)
        
        # Preparar datos de la canción
        track_data = {
            'track_id': track_id,
            'name': currently_playing_cache.get('name', ''),
            'artists': currently_playing_cache.get('artists', []),
            'image': currently_playing_cache.get('image', ''),
            'preview_url': currently_playing_cache.get('preview_url', '')
        }
        
        # Usar el history manager para agregar con verificación
        success, message = history_manager.add_to_history(track_data, votes, dislikes)
        
        if success:
            # Si se agregó correctamente, eliminar del ranking
            if result.data and len(result.data) > 0:
                supabase.table('song_ranking').delete().eq('id', track_id).execute()
                supabase.table('votes').delete().eq('trackid', track_id).execute()
            
            return jsonify({
                "message": message,
                "song": {
                    "id": track_id,
                    "name": currently_playing_cache.get('name'),
                    "artists": currently_playing_cache.get('artists')
                }
            }), 200
        else:
            return jsonify({"error": message}), 400
            
    except Exception as e:
        print(f"❌ Error al agregar al histórico: {e}")
        return jsonify({"error": "Error interno del servidor"}), 500
        
if __name__ == '__main__':
    app.run(debug=True)
