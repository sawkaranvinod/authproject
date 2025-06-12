import { Kafka } from "kafkajs";
import dotenv from "dotenv";

dotenv.config();

const brokersString = process.env.REDPANDA_CONSUMER_BROKERS;
const brokerPort = process.env.REDPANDA_CONSUMER_BROKER_PORT || "9092";
const clientId = process.env.REDPANDA_CONSUMER_CLIENTID || "producerRegister";
const groupId = process.env.REDPANDA_CONSUMER_GROUPID || "consumers";

function getBroker(brokersString, brokerPort) {
    if (brokersString) {
        return brokersString.split("-");
    }

    const port = Number(brokerPort);
    if (isNaN(port)) {
        throw new Error("Enter valid Port number");
    }

    // Use localhost for local development
    return [`localhost:${port}`];
}

const brokers = getBroker(brokersString, brokerPort);

const kafka = new Kafka({
    brokers,
    clientId,
});

export const consumer = kafka.consumer({groupId:`${groupId}`})