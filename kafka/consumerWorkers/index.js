import {startServer} from "./grpc/server/worker.server.js";



(()=>{
    try {
        startServer();
    } catch (error) {
        console.log(error);
        process.exit(-1);
    }
})();