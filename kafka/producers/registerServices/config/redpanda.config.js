import {Kafka} from "kafkajs";
import {config} from "dotenv";

config();

const clientId = process.env.REDPANDA_CLIENT_ID || "producer-client";
const brokers = process.env.REDPANDA_PORT || "9092";

const kafka = new Kafka({
  clientId: `${clientId}`,
  brokers: [`localhost:${brokers}`], // Redpanda broker address
});


export const producer = kafka.producer();


