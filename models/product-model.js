const mongoose = require('mongoose');
const { Schema } = mongoose;

const productSchema = new Schema(
{
    idProduct: {
        type: String,
        required: true,
        unique: true
    },
    productName:{
        type: String,
        required: true,
    },
    unitPrice: {
        type: Number,
        required: true,
    },
    stock: {
        type: String,
        required: true,
    },
}, {
    versionKey: false 
});

module.exports = mongoose.model('products', productSchema);