import mongoose from "mongoose";
import dotenv from 'dotenv'

dotenv.config()
try {
  

    mongoose.connect(`${process.env.dbUrl}/${process.env.dbName}`)
    
       console.log("Database connected successfully!")
} catch (error) {
    console.log(error)
}

export default mongoose