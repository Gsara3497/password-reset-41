import mongoose from "mongoose";
import dotenv from 'dotenv'

dotenv.config()
try {
    // console.log(process.env.dbUrl,process.env.dbName,'\n')

    mongoose.connect(`${process.env.dbUrl}/${process.env.dbName}`)
    
    console.log("Database connected successfully!")
} catch (error) {
    console.log(error)
}

export default mongoose