import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

const hashPassword = async(password)=>{
    let salt = await bcrypt.genSalt(Number(process.env.SALT_ROUNDS))
    let hash = await bcrypt.hash(password,salt)
    return hash
}

const hashCompare = async(password,hash)=>{
    return await bcrypt.compare(password,hash)
}

const createToken = async(payload)=>{
    const token = await jwt.sign(payload, process.env.JWT_SECRET,{
        expiresIn:process.env.JWT_EXPIRE
    })
    return token
}

const decodeToken = async(token)=>{
    let payload = await jwt.decode(token)
    return payload
}

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
        
        req.users = decodedToken;
        next()
    })
}

export default {
    hashPassword,
    hashCompare,
    createToken,
    decodeToken,
    validate
}
