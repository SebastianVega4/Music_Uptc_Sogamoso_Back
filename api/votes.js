const admin = require("firebase-admin");

// Inicializa Firebase Admin SDK
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    }),
  });
}

const db = admin.firestore();

module.exports = async (req, res) => {
  // Habilitar CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const clientIP =
    req.headers["x-forwarded-for"] || req.connection.remoteAddress;

  try {
    // POST: Registrar un nuevo voto
    if (req.method === "POST") {
      const { trackId, trackInfo } = req.body;

      if (!trackId || !trackInfo) {
        return res.status(400).json({ error: "Datos incompletos" });
      }

      // Verificar si ya votó por esta canción desde esta IP
      const voteRef = db.collection("votes").doc(`${trackId}_${clientIP}`);
      const doc = await voteRef.get();

      if (doc.exists) {
        return res
          .status(409)
          .json({ message: "Ya has votado por esta canción." });
      }

      // Actualizar contador de votos
      await db
        .collection("song_ranking")
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

      return res
        .status(201)
        .json({ message: "Voto registrado correctamente." });
    }

    // GET: Obtener la lista de canciones más votadas
    if (req.method === "GET") {
      const snapshot = await db
        .collection("song_ranking")
        .orderBy("votes", "desc")
        .limit(50)
        .get();

      const songs = snapshot.docs.map((doc) => ({
        id: doc.id,
        ...doc.data(),
      }));

      return res.status(200).json(songs);
    }

    // DELETE: Eliminar una canción (para el admin)
    if (req.method === "DELETE") {
      const { trackId } = req.query;
      const authHeader = req.headers.authorization;

      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res
          .status(401)
          .json({ error: "Token de autorización requerido" });
      }

      const token = authHeader.substring(7);

      try {
        // Verificar el token de Firebase
        const decodedToken = await admin.auth().verifyIdToken(token);

        // Verificar si el usuario es administrador
        const userDoc = await db
          .collection("admins")
          .doc(decodedToken.uid)
          .get();

        if (!userDoc.exists) {
          return res
            .status(401)
            .json({ error: "No tienes permisos de administrador" });
        }

        if (!trackId) {
          return res.status(400).json({ error: "ID de canción requerido" });
        }

        await db.collection("song_ranking").doc(trackId).delete();

        // También eliminamos los votos asociados
        const votesSnapshot = await db
          .collection("votes")
          .where("trackId", "==", trackId)
          .get();

        const batch = db.batch();
        votesSnapshot.docs.forEach((doc) => {
          batch.delete(doc.ref);
        });
        await batch.commit();

        return res
          .status(200)
          .json({ message: "Canción eliminada correctamente." });
      } catch (error) {
        console.error("Error al verificar token:", error);
        return res.status(401).json({ error: "Token inválido" });
      }
    }

    // Método no permitido
    res.setHeader("Allow", ["GET", "POST", "DELETE"]);
    return res.status(405).json({ error: `Método ${req.method} no permitido` });
  } catch (error) {
    console.error("Error en API votes:", error);
    return res.status(500).json({ error: "Error interno del servidor" });
  }
};
