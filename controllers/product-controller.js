const Product = require('./../models/product-model');
const products = [];

// POST
const createProduct = (request, response) => {
  const product = request.body;
  const newProduct = new Product(product);
  newProduct.save((error, result) => {
    if (error) {
      return response.status(500).send({ error })
    }
    return response.send(result)
  })
};

// GET
const readProducts = (request, response) => {
  const id= request.query._id;
  const productName = request.query.productName;
  const unitPrice = request.query.unitPrice;
  const stock = request.query.stock;

  const filter = {};
  if (id) {
    filter._id = id;
  }
  if (productName) {
    filter.productName = productName;
  }
  if (unitPrice) {
    filter.unitPrice = unitPrice;
  }
  if (stock) {
    filter.stock = stock;
  }

  Product.find(filter, (error, result) => {
    if (error) {
      return response.status(500).send({ error })
    }
    return response.send(result)
  })
};

// PATCH
const updateProduct = (request, response) => {
  const id = request.params._id;
  if (!id) {
    return response.status(400).send({ error: 'No hay producto, para modificar' });
  }

  Product.updateOne({ _id: id }, request.body, (error, result) => {
    if (error) {
      return response.status(500).send({ error });
    }

    Product.find({ _id: id}, (error, result) => {
      if (error) {
        return response.status(500).send({ error });
      }
      return response.send(result);
    });
  });
};

// DELETE
const deleteProduct = (request, response) => {
  const id = request.params._id;
  if (!id) {
    return response.status(400).send({ error: 'No hay producto, para eliminar' });
  }
  Product.remove({ _id: id}, (error, result) => {
    if (error) {
      return response.status(500).send({ error });
    }
    return response.send(result);
  });
};

module.exports = {
  createProduct,
  readProducts,
  updateProduct,
  deleteProduct,
};