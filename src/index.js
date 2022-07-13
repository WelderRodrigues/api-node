require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
//Config JSON response
app.use(express.json());

//Models
const User = require("./models/User");

//Route - Public
app.get("/", (request, response) => {
  response.status(200).json({ message: "Api is ok!" });
});

//Route - Private
app.get("/user/:id", checkToken, async (request, response) => {
  const id = request.params.id;

  //check if user exists
  const user = await User.findById(id, "-password");

  if (!user) {
    return response.status(404).json({ message: "Usuário não encontrado" });
  }

  response.status(200).json({ user });
});

function checkToken(request, response, next) {
  const authHeader = request.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return response.status(401).json({ message: "Acesso negado" });
  }

  try {
    const secret = process.env.SECRET;

    jwt.verify(token, secret);

    next();
  } catch (err) {
    response.status(400).json({ message: "Token inválido" });
  }
}

//Register
app.post("/auth/register", async (request, response) => {
  const { name, email, password, confirmPassword } = request.body;

  //validations
  if (!name) {
    return response.status(422).json({ message: "Nome obrigatório!" });
  }
  if (!email) {
    return response.status(422).json({ message: "E-mail obrigatório!" });
  }
  if (!password) {
    return response.status(422).json({ message: "Senha obrigatório!" });
  }
  if (password !== confirmPassword) {
    return response.status(422).json({ message: "As senhas não conferem!" });
  }

  //check if user exists
  const userExists = await User.findOne({ email: email });

  if (userExists) {
    return response
      .status(422)
      .json({ message: "Por favor, utilize outro e-mail" });
  }

  //create password
  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  //create user
  const user = new User({
    name,
    email,
    password: passwordHash,
  });

  try {
    await user.save();

    response.status(201).json({ message: "Usuário criado com sucesso!" });
  } catch (err) {
    console.log(err);

    response.status(500).json({
      message: "Aconteceu um erro no servidor, tente novamente mais tarde!",
    });
  }
});

//Login User
app.post("/auth/login", async (request, response) => {
  const { email, password } = request.body;
  //validations
  if (!email) {
    return response.status(422).json({ message: "E-mail obrigatório!" });
  }
  if (!password) {
    return response.status(422).json({ message: "Senha obrigatório!" });
  }

  //check if user exists
  const user = await User.findOne({ email: email });

  if (!user) {
    return response.status(404).json({ message: "Usuário não encontrado!" });
  }

  //check if password match
  const checkPassword = await bcrypt.compare(password, user.password);

  if (!checkPassword) {
    return response.status(422).json({ message: "Senha inválida!" });
  }

  try {
    const secret = process.env.SECRET;

    const token = jwt.sign(
      {
        id: user._id,
      },
      secret
    );

    response
      .status(200)
      .json({ message: "Autenticação realizada com sucesso!", token });
  } catch (err) {
    console.log(err);

    response.status(500).json({
      message: "Aconteceu um erro no servidor, tente novamente mais tarde!",
    });
  }
});

//Credencials
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPassword}@cluster0.zah6b.mongodb.net/?retryWrites=true&w=majority`
  )
  .then(() => {
    app.listen(3000);
    console.log("Conectou ao banco");
  })
  .catch((err) => console.log(err));
