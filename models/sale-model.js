const mongoose = require("mongoose");
const { Schema } = mongoose;

const saleSchema = new Schema(
  {
    idSale: {
      type: String,
      required: true,
    },
    sellerName: {
      type: String,
      required: true,
    },
    saleDate: {
      type: Date,
      required: true,
    },
    sale: [
      {
        productName: String,
        amount: Number,
        unitPrice: Number,
      },
    ],
    clientId: {
      type: String,
      required: true,
    },
    clientName: {
      type: String,
      required: true,
    },
    totalPrice: {
      type: Number,
      required: true,
    },
    saleStatus: String,
  },
  {
    versionKey: false,
  }
);

module.exports = mongoose.model("sales", saleSchema);
