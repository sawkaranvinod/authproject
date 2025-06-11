import { producer } from "./config/redpanda.config.js";
import { startServer } from "./grpc/server/resendOTP.server.js";


(async () => {
    await producer.connect();
    console.log("producer connected");
    startServer();
})();