import {SendInQueue} from "../server/server.grpc.js";
import {consumer} from "../../config/redapanda.config.js"
import {config} from "dotenv";

config();


const topic = process.env.REDPANDA_TOPIC || "registerServices";
const groupId = process.env.REDPANDA_GROUPID || "consumers"


SendInQueue.sendInQueue();


async function startConsuming() {
    try {
        
    } catch (error) {
        console.log(error);
        process.exit(-1);
    }
}



