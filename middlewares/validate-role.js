const User = require('./../models/user-model')

const validateRole = async (request, response, next) => {
  const { userId } = request;

  const user = await User.findOne({ _id: userId });
  if (user.role === 'Pending') {
    return response.status(401).send({
      ok: false,
      error: 'El usuario no tiene rol asignado, ni permisos',
    });
  }

  next();
}

module.exports = {
  validateRole,
}