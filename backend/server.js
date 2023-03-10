const app=require('./app');
const connectDatabase=require("./config/database")
const dotenv=require("dotenv")
process.on("uncaughtException",(err)=>{
    console.log(`Error: ${err.stack}`)
    console.log(`Shutting down the server due to Uncaugh Exception`)
    process.exit(1);
})

dotenv.config({path:"backend/config/config.env"})

// connecting to database:-
connectDatabase();


const server=app.listen(process.env.PORT,()=>{
    console.log(`Server is working on http://localhost:${process.env.PORT}`)
})

process.on("unhandledRejection",(err)=>{
    console.log(`Error:${err.stack}`);
    console.log(`Shutting down the server due to Unhandled Promise Rejection`);

    server.close(()=>{
        process.exit(1);
    });
});