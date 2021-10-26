// Crear, Leer, Actualizar, Eliminar
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('./../models/user-model');
const users = [];

// POST
const createUser = async (request, response) => {
  const user = request.body;

  if (!user.userName) {
    return response.status(400).send({
      ok: false,
      error: 'No ingresó el nombre',
    });
  }

  if (!user.email) {
    return response.status(400).send({
      ok: false,
      error: 'No ingresó el email',
    });
  }

  if (!user.withGoogle && !user.password) {
    return response.status(400).send({
      ok: false,
      error: 'No indicó la contraseña',
    });
  }

  let encryptedPassword;
  if (!user.withGoogle) {
    const salt = bcrypt.genSaltSync();
    encryptedPassword = bcrypt.hashSync(user.password, salt);
  }

  const existingUser = await User.findOne({ email: user.email });
  if (existingUser && existingUser._id) {
    return response.status(302).send({
      ok: false,
      error: 'El usuario ya está registrado',
    });
  }

  const newUser = new User({ ...user, password: encryptedPassword })
  newUser.save((error, result) => {
    if (error) {
      return response.status(500).send({ error })
    }
    return response.send(result)
  })

};

// GET
const readUsers = (request, response) => {

  const id= request.query._id;
  const userName = request.query.userName;
  const email = request.query.email;
  const userId = request.query.userId;

  const filter = {};
  if (id) {
    filter._id = id;
  }
  if (userId) {
    filter.userId = userId;
  }
  if (userName) {
    filter.userName = userName;
  }
  if (email) {
    filter.email = email;
  }
  User.find(filter, (error, result) => {
    if (error) {
      return response.status(500).send({ error })
    }
    return response.status(200).send(result)
  })
};

const readSellers = (request, response) => {

  const id= request.query._id;
  const userName = request.query.userName;
  const email = request.query.email;
  const userId = request.query.userId;

  const filter = {};
  filter.rol = 'seller'
  if (id) {
    filter._id = id;
  }
  if (userId) {
    filter.userId =userId;
  }
  if (userName) {
    filter.userName = userName;
  }
  if (email) {
    filter.email = email;
  }
  User.find(filter, (error, result) => {
    if (error) {
      return response.status(500).send({ error })
    }
    return response.status(200).send(result)
  })
};

const readAdmins = (request, response) => {

  const id= request.query._id;
  const userName = request.query.userName;
  const email = request.query.email;
  const userId = request.query.userId;

  const filter = {};
  filter.rol = 'admin'
  if (id) {
    filter._id = id;
  }
  if (userId) {
    filter.userId =userId;
  }
  if (userName) {
    filter.userName = userName;
  }
  if (email) {
    filter.email = email;
  }
  User.find(filter, (error, result) => {
    if (error) {
      return response.status(500).send({ error })
    }
    return response.send(result)
  })
};

const authUser = async (request, response) => {
  const user = request.body;
  const userFromDb = await User.findOne({ email: user.email });
  if (userFromDb) {
    const isValid = userFromDb.withGoogle ? true : bcrypt.compareSync(user.password || '', userFromDb.password);

    if (!isValid) {
      return response.status(401).send({
        ok: false,
        error: 'Usuario no autorizado',
      });
    }

    // 3. generar un token
    const token = jwt.sign({ id: userFromDb._id, rol: userFromDb.rol }, process.env.JWT_SECRET, {
      expiresIn: '6h',
    });
    return response.send({ ok: isValid, token });
  } else {
    if (!user.name) {
      return response.status(400).send({
        ok: false,
        error: 'Falta nombre',
      });
    }

    if (!user.email) {
      return response.status(400).send({
        ok: false,
        error: 'Falta correo',
      });
    }

    if (!user.withGoogle && !user.password) {
      return response.status(400).send({
        ok: false,
        error: 'Falta contraseña',
      });
    }

    let encryptedPassword;
    if (!user.withGoogle) {
      const salt = bcrypt.genSaltSync();
      encryptedPassword = bcrypt.hashSync(user.password, salt);
    }

    const existingUser = await User.findOne({ email: user.email });
    if (existingUser && existingUser._id) {
      return response.status(302).send({
        ok: false,
        error: 'El usuario ya está registrado',
      });
    }

    const newUser = new User({ ...user, password: encryptedPassword })
    newUser.save((error, result) => {
      if (error) {
        return response.status(500).send({ error })
      }
      const token = jwt.sign({ id: result._id, rol: result.rol }, process.env.JWT_SECRET, {
        expiresIn: '6h',
      });
      return response.send({ ok: true, token });
    })
  }
};



// PATCH
const updateUser = (request, response) => {
  const id = request.params.id;
  if (!id) {
    return response.status(400).send({ error: 'No hay id, para modificar' });
  }

  const user = request.body
  console.log(user)

  let encryptedPassword;
  if (!user.withGoogle && user.password) {
    const salt = bcrypt.genSaltSync();
    encryptedPassword = bcrypt.hashSync(user.password, salt);
    User.updateOne({ _id: id }, { ...user, password: encryptedPassword }, (error, result) => {
      if (error) {
        return response.status(500).send({ error });
      }

      User.find({ _id: id }, (error, result) => {
        if (error) {
          return response.status(500).send({ error });
        }
        return response.send(result);
      });
    });
  } else {
    User.updateOne({ _id: id }, user, (error, result) => {
      if (error) {
        return response.status(500).send({ error });
      }

      User.find({ _id: id }, (error, result) => {
        if (error) {
          return response.status(500).send({ error });
        }
        return response.send(result);
      });
    });
  }

};

// DELETE
const deleteUser = (request, response) => {
  const id = request.params.id;
  if (!id) {
    return response.status(400).send({ error: 'No hay id, para eliminar' });
  }
  User.remove({ _id: id }, (error, result) => {
    if (error) {
      return response.status(500).send({ error });
    }
    return response.send(result);
  });
};

module.exports = {
  createUser,
  readUsers,
  readAdmins,
  readSellers,
  updateUser,
  deleteUser,
  authUser,
};