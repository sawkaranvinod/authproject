import {consumer} from "./config/redapanda.config.js";
import {startConsuming} from "./grpc/function/services.js";



;(async () => {
    try {
        console.log("starting server of consumer")
        await consumer.connect();
        await startConsuming();
    } catch (error) {
        console.log(error);
        process.exit(-1);
    }
})();