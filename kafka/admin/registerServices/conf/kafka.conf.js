import {Kafka} from "kafkajs";
import dotenv from "dotenv";

dotenv.config();

export const kafka = new Kafka(
    {
        brokers: [process.env.BROKERS],
        clientId: process.env.CLIENTID,
    }
);
