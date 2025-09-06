const admin = require('firebase-admin');
const cors = require('cors')({ origin: true });

// Inicializa Firebase Admin SDK
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    }),
  });
}

const db = admin.firestore();

module.exports = async (req, res) => {
  cors(req, res, async () => {
    const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    // POST: Registrar un nuevo voto
    if (req.method === 'POST') {
      try {
        const { trackId, trackInfo } = req.body;

        // Verificar si ya votó por esta canción desde esta IP
        const voteRef = db.collection('votes').doc(`${trackId}_${clientIP}`);
        const doc = await voteRef.get();

        if (doc.exists) {
          return res.status(409).json({ message: 'Ya has votado por esta canción.' });
        }

        // Actualizar contador de votos
        await db
          .collection('song_ranking')
          .doc(trackId)
          .set(
            {
              ...trackInfo,
              votes: admin.firestore.FieldValue.increment(1),
              lastUpdated: new Date(),
            },
            { merge: true }
          );

        // Registrar el voto
        await voteRef.set({
          trackId,
          ip: clientIP,
          timestamp: new Date(),
        });

        return res.status(201).json({ message: 'Voto registrado correctamente.' });
      } catch (error) {
        console.error('Error al registrar voto:', error);
        return res.status(500).json({ error: 'Error interno del servidor.' });
      }
    }

    // GET: Obtener la lista de canciones más votadas
    if (req.method === 'GET') {
      try {
        const snapshot = await db
          .collection('song_ranking')
          .orderBy('votes', 'desc')
          .limit(50)
          .get();

        const songs = snapshot.docs.map((doc) => ({
          id: doc.id,
          ...doc.data(),
        }));

        return res.status(200).json(songs);
      } catch (error) {
        console.error('Error al obtener canciones:', error);
        return res.status(500).json({ error: 'Error interno del servidor.' });
      }
    }

    // DELETE: Eliminar una canción (para el admin)
    if (req.method === 'DELETE') {
      try {
        const { trackId } = req.query;
        const { authorization } = req.headers;

        // Verificación básica de autenticación
        if (!authorization || authorization !== `Bearer ${process.env.ADMIN_SECRET}`) {
          return res.status(401).json({ error: 'No autorizado.' });
        }

        await db.collection('song_ranking').doc(trackId).delete();

        // También eliminamos los votos asociados
        const votesSnapshot = await db.collection('votes').where('trackId', '==', trackId).get();

        const batch = db.batch();
        votesSnapshot.docs.forEach((doc) => {
          batch.delete(doc.ref);
        });
        await batch.commit();

        return res.status(200).json({ message: 'Canción eliminada correctamente.' });
      } catch (error) {
        console.error('Error al eliminar canción:', error);
        return res.status(500).json({ error: 'Error interno del servidor.' });
      }
    }

    // Método no permitido
    res.setHeader('Allow', ['GET', 'POST', 'DELETE']);
    return res.status(405).end(`Method ${req.method} Not Allowed`);
  });
};
