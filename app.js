require("dotenv").config();
const chalk = require("chalk");
const express = require("express");
const cors = require("cors");

require("./drivers/mongo-connection");

const productsRouter = require("./routes/products");
const salesRouter = require("./routes/sales");
const usersRouter = require("./routes/users");

const port = process.env.PORT || 8080;
const app = express();

app.use(cors());
app.use(express.json());

app.use("/api/users", usersRouter);
app.use("/api/sales", salesRouter);
app.use("/api/products", productsRouter);

app.get("/", (req, res) => {
  res.send("Bienvenido a la API de Minsoft");
});
app.get("*", (req, res) => {
  return res.send("Not found!");
});

// routes // controllers // models
// app.post("/api/pruebas", (req, res) =>
// {


async function main() {
  await app.listen(port);
  console.log(chalk.green(`El servidor está listo en el puerto: ${port}!`));
}
main();
