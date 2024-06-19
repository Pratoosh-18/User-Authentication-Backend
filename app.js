import express from "express";
import cors from "cors"
import cookieParser from "cookie-parser";

const app = express()
app.use(cors()) 

app.use(express.json({limit:"16kb"}))
app.use(express.urlencoded())
app.use(cookieParser())


import userRoute from "./src/routes/user.routes.js"

app.use("/api/v1/users",userRoute)

export default app  