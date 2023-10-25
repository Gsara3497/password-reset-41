import mongoose from "./index.js";

const validateEmail = (e)=>{
    var emailPattern = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/;
    return emailPattern.test(e); 
}
const userSchema = new mongoose.Schema({
    email : {type:String, validate:validateEmail},
    password : {type:String},
    resetPasswordToken : {type:String},
    resetPasswordExpires : {type:Date}
},
{
    versionKey:false
})

const userModel = mongoose.model("users", userSchema)

export default userModel