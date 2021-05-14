const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const mongoose = require("mongoose");
const config = require("./config");
const userModel = require("./models/user");
const sessionModel = require("./models/session");

let app = express();

//DB
mongoose.connect("mongodb+srv://"+config.username+":"+config.password+"@"+config.url+"/shop?retryWrites=true&w=majority").then( ()=>
 console.log("Connected to mongoDB"),
 (error) => console.log("Failed to connect to mongodb. Reason: ", error)
)

app.use(bodyParser.json());

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

    bcrypt.hash(req.body.password,14, (err,hash) => {
        if(err){
            return res.status(400).json({message:"Bad request 4a"})
        }
        let user =  new userModel({
            username: req.body.username,
            password: hash
        })
       user.save((err,user) => {
           if(err){
               console.log("Failed to register new user, ", err);
               if(err.code === 11000){
                   return res.status(409).json({message:"Username is already in use"})
               }
               return res.status(500).json({message: "Internal server error"})
           }
            return res.status(201).json({message:"User registered"})
       })
       

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

    userModel.findOne({"username":req.body.username}, (err,user) => {
        if(err){
            console.log("Login failed. Reason: ", err)
            return res.status(500).json({message:"Internal server error"})
        }
        if(!user){
            return res.status(401).json({message:"Unauthorized"})
        }
        bcrypt.compare(req.body.password, user.password, (error, success) => {
            if(error){
                console.log("Compariing password failed. Reason: ", error);
                return res.status(400).json({message:"Bad reguest a"})
            }
            if(!success){
                return res.status(401).json({message:"Unauthorized"})
            }

            let token = createToken();
            let now = Date.now();
            let session = new sessionModel({
                user: user.username,
                ttl: now + time_to_live_diff,
                token: token
            })

            session.save(err => {
                if(err){
                    console.log("Failed to save session. Reason: ", err);
                    return res.status(500).json({message:"Internal server error"})
                }
                return res.status(200).json({"token": token})
            })
        })
    })
    return res.status(401).json({message:"Unauthorized"});

})
