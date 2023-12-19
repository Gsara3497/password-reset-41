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

const postEmail = async(req,res) => {
    try {
        let user = await userModel.findOne({email:req.body.email})
        if(!user){
            req.body.password = await Auth.hashPassword(req.body.password)
            await userModel.create(req.body)
            res.status(201).send({
                message:"User Created Successfully"
            })
        }
        else{
            res.status(400).send({
                message:`User with ${req.body.email} already exits`
})
        }
    } catch (error) {
        res.status(500).send({
            message:"Internal Server Error",
            error:error.message
        })
    }
}

const loginEmail = async(req,res)=>{
    try {
        let user = await userModel.findOne({email:req.body.email})

        if(user){
            let hashCompare = await Auth.hashCompare(req.body.password, user.password)
            if(hashCompare){
                let token = await Auth.createToken({
                    id:user._id,
                    name:user.name,
                    email:user.email,
                })
                let userData = await userModel.findOne({email:req.body.email},{_id:0,password:0,email:0})
                res.status(200).send({
                    message:"Login Successfully",
                    token,
                    userData
                })
            }
            else{
                res.status(400).send({
                    message:"Invalid Password"
                })
            }
        }
        else
        {
            res.status(400).send({
                message:`Account with ${req.body.email} doesn't exists!`
            })
        }
    } catch (error) {
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

      const users = await userModel.findOne({email:email})

      if(!users){
        return res.status(400).send({
            message:"User not found"
        })
      }

    // create random numder, length is six
      const token = Math.random().toString(36).slice(-8); // set password as 8 character
      users.resetPasswordToken = token;
      users.resetPasswordExpires = Date.now() + 3600000; // Expires time set for an hour

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
        text: `https://luminous-dolphin-1bd766.netlify.app/forgotpassword/${users._id}/${token}`
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
    try{
    const { id, token } = req.params;
    // console.log('Received Token:', token);

    const users = await userModel.findOne({
        resetPasswordToken : token,
        resetPasswordExpires : { $gt: Date.now() },
    })
    

    const hashpswd = await Auth.hashPassword(req.body.password)
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
catch(error){
    console.error('Error:', error);
    res.status(500).send({
      message: "Internal Server Error"
    });
}

}


export default {
    getEmail,
    postEmail,
    loginEmail,
    verifyToken,
    resetPassword,
    getResetPassword
}