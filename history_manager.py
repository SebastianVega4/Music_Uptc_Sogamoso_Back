from datetime import datetime, timedelta, timezone
from supabase import create_client
import os

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

class HistoryManager:
    def __init__(self):
        self.last_added_time = {}
    
    def can_add_to_history(self, track_id):
        """Verificar si se puede agregar una canción al histórico (mínimo 10 minutos desde la última vez)"""
        try:
            # Verificar en caché local primero
            current_time = datetime.now(timezone.utc)
            if track_id in self.last_added_time:
                time_since_last_add = current_time - self.last_added_time[track_id]
                if time_since_last_add < timedelta(minutes=10):
                    return False, f"Esta canción ya fue agregada al histórico hace {int(time_since_last_add.total_seconds() / 60)} minutos"
            
            # Verificar en base de datos
            ten_minutes_ago = current_time - timedelta(minutes=10)
            
            recent_history = supabase.table('song_history')\
                .select('last_played_at')\
                .eq('track_id', track_id)\
                .gte('last_played_at', ten_minutes_ago.isoformat())\
                .execute()
            
            if recent_history.data and len(recent_history.data) > 0:
                last_played = datetime.fromisoformat(recent_history.data[0]['last_played_at'].replace('Z', '+00:00'))
                time_since_last = current_time - last_played
                minutes_left = 10 - int(time_since_last.total_seconds() / 60)
                return False, f"Esta canción ya fue agregada al histórico recientemente. Espera {minutes_left} minutos"
            
            return True, "Puede agregar al histórico"
            
        except Exception as e:
            print(f"❌ Error verificando histórico: {e}")
            return False, "Error al verificar histórico"
    
    def add_to_history(self, track_data, votes=0, dislikes=0):
        """Agregar una canción al histórico con verificación de tiempo"""
        try:
            track_id = track_data.get('track_id')
            
            # Verificar si se puede agregar
            can_add, message = self.can_add_to_history(track_id)
            if not can_add:
                return False, message
            
            # Proceder con la adición al histórico
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
                
                # Actualizar votos si se proporcionan
                if votes > 0:
                    update_data['total_votes'] = existing_song.get('total_votes', 0) + votes
                if dislikes > 0:
                    update_data['total_dislikes'] = existing_song.get('total_dislikes', 0) + dislikes
                
                supabase.table('song_history')\
                    .update(update_data)\
                    .eq('track_id', track_id)\
                    .execute()
                
                action = "updated"
            else:
                # Crear nueva entrada
                new_song = {
                    'track_id': track_id,
                    'name': track_data.get('name', ''),
                    'artists': track_data.get('artists', []),
                    'image': track_data.get('image', ''),
                    'preview_url': track_data.get('preview_url', ''),
                    'total_votes': votes,
                    'total_dislikes': dislikes,
                    'times_played': 1,
                    'last_played_at': current_time,
                    'first_played_at': current_time,
                    'created_at': current_time,
                    'updated_at': current_time
                }
                
                supabase.table('song_history').insert(new_song).execute()
                action = "created"
            
            # Actualizar caché local
            self.last_added_time[track_id] = datetime.now(timezone.utc)
            
            return True, f"Canción agregada al histórico ({action})"
            
        except Exception as e:
            print(f"❌ Error agregando al histórico: {e}")
            return False, "Error al agregar al histórico"

# Instancia global del administrador de histórico
history_manager = HistoryManager()