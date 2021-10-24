const express = require('express');
const { createUser, readUsers, readAdmins, readSellers, updateUser, deleteUser, authUser } = require('./../controllers/user-controller');

// Router
const router = express.Router();

router.post('/', createUser);

router.get('/', readUsers);
router.get('/sellers', readSellers);
router.get('/admins', readAdmins);

router.patch('/:id', updateUser);

router.delete('/:id', deleteUser);

router.post('/auth/', authUser);

// GET, POST, PATCH, DELETE // Users

module.exports = router;