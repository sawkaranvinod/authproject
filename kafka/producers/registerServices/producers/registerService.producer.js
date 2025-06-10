import {producer} from "./config/redpanda.config.js";
import {startServer} from "./grpc/server/producerServer.grpc.js"


;(async()=>{
    await producer.connect();
    console.log("producer connected");
    startServer();
    console.log("grpc server started")
})();