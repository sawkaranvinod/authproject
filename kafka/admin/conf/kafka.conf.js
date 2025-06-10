import {Kafka} from "kafkajs";
import dotenv from "dotenv";

dotenv.config();

const brokers = process.env.BROKERS_PORT||9092;
const clientId = process.env.CLIENTID || "admin"


export const kafka = new Kafka(
    {
        brokers: [`localhost:${brokers}`],
        clientId:clientId,
    }
);
