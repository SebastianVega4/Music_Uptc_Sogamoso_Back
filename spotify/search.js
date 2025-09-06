const SpotifyWebApi = require('spotify-web-api-node');
const cors = require('cors')({ origin: true });

const spotifyApi = new SpotifyWebApi({
  clientId: process.env.SPOTIFY_CLIENT_ID,
  clientSecret: process.env.SPOTIFY_CLIENT_SECRET,
});

// Función para obtener y refrescar el token de Spotify
async function getAccessToken() {
  try {
    const data = await spotifyApi.clientCredentialsGrant();
    spotifyApi.setAccessToken(data.body['access_token']);
    return true;
  } catch (error) {
    console.error('Error al obtener token de Spotify:', error);
    return false;
  }
}

module.exports = async (req, res) => {
  cors(req, res, async () => {
    if (req.method === 'OPTIONS') {
      return res.status(200).end();
    }

    if (req.method !== 'GET') {
      res.setHeader('Allow', ['GET']);
      return res.status(405).end(`Method ${req.method} Not Allowed`);
    }

    const { q } = req.query;
    if (!q) {
      return res.status(400).json({ error: 'El parámetro de búsqueda "q" es requerido.' });
    }

    try {
      const tokenSuccess = await getAccessToken();
      if (!tokenSuccess) {
        return res.status(500).json({ error: 'Error de autenticación con Spotify.' });
      }

      const searchResults = await spotifyApi.searchTracks(q, { limit: 10 });
      const tracks = searchResults.body.tracks.items.map((track) => ({
        id: track.id,
        name: track.name,
        artists: track.artists.map((artist) => artist.name),
        album: track.album.name,
        image: track.album.images[0]?.url || 'https://placehold.co/300x300?text=No+Image',
        preview_url: track.preview_url,
        duration_ms: track.duration_ms,
        uri: track.uri,
      }));

      res.status(200).json(tracks);
    } catch (error) {
      console.error('Error al buscar en Spotify:', error);
      res.status(500).json({ error: 'Error al buscar en Spotify.' });
    }
  });
};
