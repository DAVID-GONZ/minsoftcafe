const express = require('express');
const { createSale, readSales, updateSale, deleteSale } = require('./../controllers/sale-controller');

const {validateRole} = require('./../middlewares/validate-role')
const {validateUser} = require('./../middlewares/validate-user')


// Router
const router = express.Router();

router.post('/', createSale);

router.get('/', readSales);

router.get('/', readSales);

router.patch('/:id', updateSale);

router.delete('/:id', deleteSale);

// GET, POST, PATCH, DELETE // Sales

module.exports = router;