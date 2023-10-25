import userModel from '../models/User.js'
import Auth from '../common/auth.js'
import nodemailer from 'nodemailer'

const getEmail = async(req,res)=>{
try {
    let users = await userModel.find({},{password:0})
    res.status(200).send({
    message:"API get Successfully",
    users
    
    })
} catch (error) {
    res.status(500).send({
        message:"Internal Server Error",
        error:error.message
    })
}
}

const postEmail = async(req,res)=>{
try {
    const { email, password } = req.body;

    const users = await userModel.findOne({email})

    if(!users){
        const hashPassword = await Auth.hashedPassword(req.body.password)

        const newUser = new userModel({email, password:hashPassword})

        await newUser.save();

        return res.status(201).send({
            message:"Users created Successfully"
        })

    }
    res.status(400).send({
        message:"Email Already Exists"
    })
} catch (error) {
    res.status(500).send({
        message:"Internal Server Error",
        error:error.message
    })
}
}

const loginEmail = async(req,res)=>{
    try {
      const { email, password } = req.body;
      
      const users = await userModel.findOne({ email })
      if(!users)
      {
        return res.status(400).send({
            message:"User not found"
        })
      }

      const userMatch = await Auth.hashCompare(password, users.password);
      if(!userMatch)
      {
        return res.status(400).send({
            message:"Invalid Password"
        })
      }
      let token = await Auth.createToken({email:users.email})
        res.status(200).send({
            message:"Login Successfull",
            token
        })
    }

    catch (error) {
        res.status(500).send({
            message:"Internal Server Error",
            error:error.message
        })
    }
}

const verifyToken = async(req,res)=>{
  try {
    if(!req.users){
        return res.status(400).send({
            message:"users not Authorized"
        })
    }
    
    res.status(200).send({
        message: `Welcome ${req.users.email}! is Protected`
    })
  } catch (error) {
    res.status(500).send({
        message:"Internal Server Error",
        error:error.message
    })
  }
}

const resetPassword = async(req,res)=>{
      const { email } = req.body;

      const users = await userModel.findOne({email})

      if(!users){
        return res.status(400).send({
            message:"User not found"
        })
      }

    // create random numder, length is six
      const token = Math.random().toString(36).slice(-8); // set password as 8 character
      users.resetPasswordToken = token;
      users.resetPasswrodExpires = Date.now() + 3600000; // Expires time set for an hour

      await users.save();

      const transporter = nodemailer.createTransport({
        service : "gmail",
        auth:{
            user:"sumaiyanisu29@gmail.com",
            pass:"dvxk nmpy fztw ffty" // app password from the account
        }
      })

      const message = {
        from : "sumaiyanisu29@gmail.com",
        to : users.email,
        subject : "Password Reset Request",
        text : `You are receiving this email because you has requested a password reset for your account. \n\n Please use the following token to reset your password: ${token}\n\n If you didn't request a password reset, please ignore this Email.`
      }

      transporter.sendMail(message,(err, info)=>{
        if(err){
            res.status(400).send({
                message:"Something went Wrong, Try Again!"
            })
        }
            res.status(200).send({
                message:"Password Reset Email Sent" + info.response
            });
        
      })
}

const getResetPassword = async(req,res)=>{
    const { token } = req.params;
    const { password } = req.body;

    const users = await userModel.findOne({
        resetPasswordToken : token,
        resetPasswordExpires : { $gt: Date.now() },
    })
    
    if(!users){
        return res.status(400).send({
            message:"Invalid Token",
            
        })
    }

    const hashpswd = await Auth.hashedPassword(req.body.password)
    if(!hashpswd){
        return res.status(500).send({
            message:"Password hashing error"
        })
    }
    users.password = hashpswd;
    users.resetPasswordToken = null;
    users.resetPasswordExpires = null;

    await users.save();

    res.status(200).send({
        message:"Password Reset Successfully"
    })

}


export default {
    getEmail,
    postEmail,
    loginEmail,
    verifyToken,
    resetPassword,
    getResetPassword
}