from datetime import datetime, timedelta, timezone
from supabase import create_client
import os
import threading
import time

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

class VotingManager:
    def __init__(self):
        self.current_song_id = None
        self.voting_start_time = None
        self.active_votes = {
            'next': 0,
            'genre_change': 0,
            'repeat': 0
        }
        self.voting_lock = threading.Lock()
        self.polling_thread = None
        self.polling_active = False
        
    def start_voting_polling(self):
        """Iniciar polling para verificar cambios en la canción actual"""
        self.polling_active = True
        
        def poll_voting():
            while self.polling_active:
                try:
                    from app import currently_playing_cache

                    if currently_playing_cache and currently_playing_cache.get('is_playing'):
                        current_id = currently_playing_cache.get('id')

                        with self.voting_lock:
                            if current_id != self.current_song_id:
                                # Canción ha cambiado, reiniciar votación y limpiar votos de usuario
                                print(f"🎵 Canción cambiada. Reiniciando votación. Anterior: {self.current_song_id}, Nueva: {current_id}")

                                # Limpiar votos de usuario para la sesión anterior
                                if self.current_song_id:
                                    self.clear_user_votes_for_session(self.current_song_id)

                                self.current_song_id = current_id
                                self.voting_start_time = datetime.now(timezone.utc)
                                self.active_votes = {'next': 0, 'genre_change': 0, 'repeat': 0}

                                # Guardar en base de datos
                                self.save_voting_state()

                    time.sleep(5)  # Reducir a 5 segundos para mayor responsividad

                except Exception as e:
                    print(f"❌ Error en polling de votación: {e}")
                    time.sleep(30)
        
        self.polling_thread = threading.Thread(target=poll_voting)
        self.polling_thread.daemon = True
        self.polling_thread.start()
        print("✅ Hilo de polling de votación iniciado")
    
    def stop_voting_polling(self):
        """Detener el polling de votación"""
        self.polling_active = False
    
    def save_voting_state(self):
        """Guardar el estado actual de votación en la base de datos"""
        try:
            voting_data = {
                'current_song_id': self.current_song_id,
                'voting_start_time': self.voting_start_time.isoformat() if self.voting_start_time else None,
                'next_votes': self.active_votes['next'],
                'genre_change_votes': self.active_votes['genre_change'],
                'repeat_votes': self.active_votes['repeat'],
                'updated_at': datetime.now(timezone.utc).isoformat()
            }
            
            supabase.table('current_voting').upsert({
                'id': 'current',
                'voting_data': voting_data
            }).execute()
            
        except Exception as e:
            print(f"❌ Error guardando estado de votación: {e}")
    
    def load_voting_state(self):
        """Cargar el estado de votación desde la base de datos"""
        try:
            result = supabase.table('current_voting').select('*').eq('id', 'current').execute()

            if result.data and len(result.data) > 0:
                voting_data = result.data[0]['voting_data']
                self.current_song_id = voting_data.get('current_song_id')

                if voting_data.get('voting_start_time'):
                    self.voting_start_time = datetime.fromisoformat(voting_data['voting_start_time'].replace('Z', '+00:00'))

                self.active_votes = {
                    'next': voting_data.get('next_votes', 0),
                    'genre_change': voting_data.get('genre_change_votes', 0),
                    'repeat': voting_data.get('repeat_votes', 0)
                }

                print(f"✅ Estado de votación cargado: {self.active_votes}")

        except Exception as e:
            print(f"❌ Error cargando estado de votación: {e}")

    def clear_user_votes_for_session(self, session_id):
        """Eliminar todos los votos de usuario para una sesión específica"""
        try:
            supabase.table('user_votes').delete().eq('vote_session', session_id).execute()
            print(f"✅ Votos de usuario eliminados para sesión: {session_id}")
        except Exception as e:
            print(f"❌ Error eliminando votos de usuario: {e}")
    
    def vote(self, vote_type, user_fingerprint):
        """Registrar un voto - PERMITIR VOTOS EN TODAS LAS CATEGORÍAS"""
        from app import get_user_fingerprint
        with self.voting_lock:
            try:
                recent_votes = supabase.table('user_votes').select('*').eq(
                    'user_fingerprint', user_fingerprint
                ).eq('vote_session', self.current_song_id).eq('vote_type', vote_type).execute()
                if recent_votes.data and len(recent_votes.data) > 0:
                    return False, f"Ya has votado por {self.get_vote_type_name(vote_type)} en esta sesión"
            except Exception as e:
                print(f"❌ Error verificando voto de usuario: {e}")
                return False, "Error al verificar voto"
            if vote_type in self.active_votes:
                self.active_votes[vote_type] += 1

                # Registrar voto de usuario
                supabase.table('user_votes').insert({
                    'user_fingerprint': user_fingerprint,
                    'vote_type': vote_type,
                    'vote_session': self.current_song_id,
                    'voted_at': datetime.now(timezone.utc).isoformat()
                }).execute()

                # Guardar estado actual
                self.save_voting_state()

                return True, f"Voto para {self.get_vote_type_name(vote_type)} registrado correctamente"

            return False, "Tipo de voto no válido"

    def get_vote_type_name(self, vote_type):
        """Obtener nombre legible del tipo de voto"""
        names = {
            'next': 'siguiente canción',
            'genre_change': 'cambiar de género', 
            'repeat': 'repetir género'
        }
        return names.get(vote_type, vote_type)
    
    def get_voting_status(self):
       """Obtener el estado actual de la votación"""
        with self.voting_lock:
            # Asegurar que siempre retorne una estructura válida
            return {
                'current_song_id': self.current_song_id or '',
                'voting_start_time': self.voting_start_time.isoformat() if self.voting_start_time else None,
                'votes': {
                    'next': self.active_votes.get('next', 0),
                    'genre_change': self.active_votes.get('genre_change', 0),
                    'repeat': self.active_votes.get('repeat', 0)
                },
                'total_votes': sum(self.active_votes.values()) if self.active_votes else 0
            }

# Instancia global del administrador de votaciones
voting_manager = VotingManager()