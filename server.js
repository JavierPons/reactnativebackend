const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const crypto = require("crypto");


let app = express();

app.use(bodyParser.json());


// DB

let registeredUsers = [];
let loggedSessions = [];


app.listen(3009)
console.log("Running in port 3009")