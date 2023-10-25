import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import dotenv from 'dotenv'
import userModel from '../models/User.js'

dotenv.config()

const hashedPassword = async(password)=>{
    let salt = await bcrypt.genSalt(Number(process.env.SALT_ROUNDS))
    console.log(salt)
    let hash = await bcrypt.hash(password,salt)
    return hash
}

const hashCompare = async(password,hash)=>{
    return await bcrypt.compare(password,hash)
}

const createToken = async(payload)=>{
   const token = jwt.sign(payload,process.env.JWT_SECRET,{
    expiresIn:process.env.JWT_EXPIRE
   }) 
   return token
}

const decodeToken = async (token) => {
    try {
        const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
        return decodedToken;
    } catch (error) {
        return null; // Handle invalid or expired tokens
    }
}

// const decodeToken = async(token)=>{
//     const payload = await jwt.decode(token)
//     return payload
// }

// const validate = async(req,res,next)=>{
//     let token = req.headers.authorization?.split(" ")[1]
//     if(token)
//     {
//         let payload = await decodeToken(token)
//         let currentTime = (+new Date())/1000

//         if(currentTime<payload.exp)
//             next()
        
//         else
//             res.status(400).send({
//                 message:"Token Expired"
//             })
//     }
//     else
//     {
//         res.status(400).send({
//             message:"No Token Found"
//         })
//     }

// }

const validate = async(req,res,next)=>{
    let authHeader = req.headers.authorization;

    if(!authHeader){
        res.status(400).send({
            message:"Missing Token"
        })
    }

    const token = authHeader.split(" ")[1];

    jwt.verify(token, process.env.JWT_SECRET, async(err, decodedToken)=>{
        if(err){
            return res.status(400).send({
                message: "Invalid Token"
            })
        }
        const users = await userModel.findOne({_id:decodedToken.id})

        if(!users){
            return res.status(400).send({
                message:"User not found"
            })
        }
        console.log("Decoded Token:", decodedToken);
        console.log("User ID:", decodedToken.id);
        
        req.users = users;
        next()
    })
}

export default {
    hashedPassword,
    hashCompare,
    createToken,
    decodeToken,
    validate
}