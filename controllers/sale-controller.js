/// CRUD = Create Read Update Delete
// Crear, Leer, Actualizar, Eliminar
const Sale = require('./../models/sale-model');
const Sales = [];

// POST
const createSale = (request, response) => {
  const newSale = new Sale(request.body)
  newSale.save((error, result)=>{
    if(error) {
      return response.status(500).send({error})
    }
    return response.send(result)
  })

};

// GET
const readSales = (request, response) => {
  const id = request.query._id;
  const clientId = request.query.clientId;
  const clientName = request.query.clientName;
  const saleDate = request.query.saleDate;
  


  const filter = {};
  if (id) {
    filter._id = id;
  }
  if (clientId) {
    filter.clientId = clientId;
  }
  if (clientName) {
    filter.clientName = clientName;
  }
  if (saleDate) {
    filter.saleDate = saleDate;
  }

  Sale.find(filter, (error, result) => {
    if (error) {
      return response.status(500).send({ error })
    }
    return response.send(result)
  })
};

// PATCH
const updateSale = (request, response) => {
  const id = request.params._id;
  if (!idSale) {
    return response.status(400).send({ error: 'No hay id, para modificar' });
  }

  Sale.updateOne({ _id: idSale }, request.body, (error, result) => {
    if (error) {
      return response.status(500).send({ error });
    }

    Sale.find({ _id: idSale }, (error, result) => {
      if (error) {
        return response.status(500).send({ error });
      }
      return response.send(result);
    });
  });
};

// DELETE
const deleteSale = (request, response) => {
  const idSale = request.params.idSale;
  if (!idSale) {
    return response.status(400).send({ error: 'No hay id, para eliminar' });
  }
  Sale.remove({ _id: idSale }, (error, result) => {
    if (error) {
      return response.status(500).send({ error });
    }
    return response.send(result);
  });
};

module.exports = {
  createSale,
  readSales,
  updateSale,
  deleteSale,
};