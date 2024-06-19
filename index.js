import app from "./app.js";
import connectDB from "./src/db/db.js";
   
connectDB()
.then(()=>{
    app.get("/",(req,res)=>{
        res.send("Hello world")
    })
    app.listen(process.env.PORT || 8000,()=>{
        console.log(`App is listening on http://localhost:${process.env.PORT}`)
    })
    app.on("error",(error)=>{
        console.log(`Unexpected error occured`)
    })
})
.catch((error)=>{
    console.log("Mongo DB connection failed")
    console.log(error)
})