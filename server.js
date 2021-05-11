const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const crypto = require("crypto");


let app = express();

app.use(bodyParser.json());


// DB

let registeredUsers = [];
let loggedSessions = [];

const time_to_live_diff = 360000

app.listen(3009)
console.log("Running in port 3009")

//MIDDLEWARE

createToken = () => {
    let token = crypto.randomBytes(128);
    return token.toString("hex");

}

//LOGIN API

app.post("/login", (req,res) => {
    if(!req.body){
        return res.status(400).json({message:"Bad Request 1"});
    }
    if(!req.body.password || !req.body.username){
        return res.status(400).json({message:"Bad Request 2"})
    }
    if(req.body.username.length < 4 || req.body.password.length < 8){
        return res.status(400).json({message:"Bad Request 3"})
    }

    for(let i = 0; registeredUsers.length; i ++){
        if(registeredUsers[i].username === req.body.username){
            bcrypt.compare(req.body.password, registeredUsers[i].password, (err, succes) => {
                if(err){
                    return res.status(400).json({message:"Bad Request"})
                }
                if(!succes){
                    return res.status(401).json({message:"Unauthorized"})
                }
                let token = createToken();
                if(!token){
                    return res.status(400).json({message:"Bad Request 4"})
                }
                let now = Date.now();
                let session = {
                    user:req.body.username,
                    ttl: now + time_to_live_diff,
                    token: token
                }
                loggedSessions.push(session)
                return res.status(200).json({token: token})
            })
            return;
        }
    }
    return res.status(401).json({message:"Unauthorized"});

})
