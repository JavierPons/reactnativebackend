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

isUserLogged = (req, res, next) => {
    console.log(req.headers)
    if(!req.headers.token){
        return res.status(403).json({message:"forbidden"})
    }
    for(let i = 0; i < loggedSessions.length; i++){
        if(req.headers.token === loggedSessions[i].token){
            let now = Date.now();
            if(now > loggedSessions[i].ttl){
                loggedSessions.splice(i,1);
                return res.status(403).json({message:"forbidden"})
            }
            loggedSessions[i].ttl = now + time_to_live_diff;
            req.session = {};
            req.session.user = loggedSessions[i].user;
            return next();
        }
    }
    return res.status(403).json({message:"forbidden"})
}

//LOGIN API

app.post("/register", (req, res) => {
    if(!req.body){
        return res.status(400).json({message:"Bad request 1a"});
    }
    if(!req.body.password || !req.body.username){
        return res.status(400).json({message:"Bad request 2a"})
    }
    if(req.body.password < 4 || req.body.username < 8 ){
        return res.status(400).json({message:"Bad request 3a"})
    }

    for(let i = 0; i < registeredUsers.length; i++){
        if(req.body.username === registeredUsers[i].username){
            return res.status(409).json({message:"Username is already in use"})
        }

    }

    bcrypt.hash(req.body.password,14, (err,hash) => {
        if(err){
            return res.status(400).json({message:"Bad request 4a"})
        }
        let user = {
            username: req.body.username,
            password: hash
        }
        registeredUsers.push(user);
        console.log(registeredUsers);
        return res.status(201).json({message:"User registered"})

    })

})

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
