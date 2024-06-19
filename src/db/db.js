import mongoose from "mongoose"
import dotenv from "dotenv"
import { DB_NAME } from "../../constants.js"

dotenv.config()

const connectDB = async () => {
    try{
        await mongoose.connect(`${process.env.MONGO_URI}/${DB_NAME}`)
        console.log("You are connected to the database !")
    }catch{
        console.log("DB connection error !!")
    }
}

export default connectDB