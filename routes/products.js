const express = require('express');
const { createProduct, readProducts, updateProduct, deleteProduct } = require('./../controllers/product-controller');

const {validateRole} = require('./../middlewares/validate-role')
const {validateUser} = require('./../middlewares/validate-user')

// Router
const router = express.Router();

router.post('/', createProduct);

router.get('/', readProducts);

router.patch('/:id', updateProduct)

router.delete('/:id', deleteProduct)

// GET, POST, PATCH, DELETE // Products

module.exports = router;