module.exports = async (req, res) => {
  // Habilitar CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    res.setHeader('Allow', ['POST']);
    return res.status(405).json({ error: `Método ${req.method} no permitido` });
  }

  try {
    const { username, password } = req.body;

    // Credenciales hardcodeadas (en producción usar una base de datos)
    const validUsername = 'admin';
    const validPassword = 'uptc2023';

    if (username === validUsername && password === validPassword) {
      // Generar un token simple (en producción usar JWT)
      const token = process.env.ADMIN_SECRET;
      return res.status(200).json({
        success: true,
        token,
        message: 'Autenticación exitosa',
      });
    } else {
      return res.status(401).json({
        success: false,
        error: 'Credenciales inválidas',
      });
    }
  } catch (error) {
    console.error('Error en autenticación:', error);
    return res.status(500).json({ error: 'Error interno del servidor' });
  }
};
