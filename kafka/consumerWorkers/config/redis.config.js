import Redis from "ioredis";
import {config} from "dotenv";
config();


const redisQueuePort = process.env.REDIS_QUEUE_PORT || 6384;
const redisDeadLetterQueuePort = process.env.REDIS_DEAD_LETTER_QUEUE || 6385;

export const redisQueue = new Redis(Number(redisQueuePort));
export const redisDeadLetterQueue = new Redis(Number(redisDeadLetterQueuePort))