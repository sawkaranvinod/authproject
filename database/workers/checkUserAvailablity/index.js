import {connectDB} from "./connection/db.connect.js";
import {config} from "dotenv";
import {startServer} from "./grpc/server/checkUserIdAvailablity.grpcServer.js"


config();

const uri = process.env.URI;

(async ()=>{
    try {
        const connection = await connectDB(uri);
        console.log("database is connected");
        startServer();
    } catch (error) {
        console.log(error);
        process.exit(-1);
        
    }
})();