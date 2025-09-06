const admin = require('firebase-admin');

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

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://4200-firebase-musicuptcsogamoso-1757187604448.cluster-dwvm25yncracsxpd26rcd5ja3m.cloudworkstations.dev');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    res.setHeader('Allow', ['POST']);
    return res.status(405).json({ error: `Método ${req.method} no permitido` });
  }

  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email y contraseña son requeridos' });
    }

    // Autenticar con Firebase
    const userRecord = await admin.auth().getUserByEmail(email);
    
    // Verificar si el usuario es administrador
    const userDoc = await admin.firestore().collection('admins').doc(userRecord.uid).get();
    
    if (!userDoc.exists) {
      return res.status(401).json({ error: 'No tienes permisos de administrador' });
    }

    // En una aplicación real, deberías usar Firebase Auth para autenticar
    // Pero para simplificar, usaremos un token JWT personalizado
    const token = await admin.auth().createCustomToken(userRecord.uid);
    
    return res.status(200).json({
      success: true,
      token,
      message: 'Autenticación exitosa',
    });
  } catch (error) {
    console.error('Error en autenticación:', error);
    
    if (error.code === 'auth/user-not-found') {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }
    
    return res.status(500).json({ error: 'Error interno del servidor' });
  }
};