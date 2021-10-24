const jwt = require('jsonwebtoken');

const validateUser = (request, response, next) => {
  const tokenFromHeader = request.header('jwt-auth');
  if (!tokenFromHeader) {
    return response.status(401).send({
      ok: false,
      error: 'Operación no autorizada',
    });
  }

  try {
    const tokenInfo = jwt.verify(tokenFromHeader, process.env.JWT_SECRET);
    // millis desde 1/1/1970
    if (!tokenInfo) {
      return response.status(401).send({
        ok: false,
        error: 'Operación no autorizada',
      });
    }
    request.userId = tokenInfo.id;
  } catch (e) {
    return response.status(500).send({
      ok: false,
      error: e.message,
    });
  }

  next();
};

// petición -> middleware -> función del controller

module.exports = {
  validateUser,
};