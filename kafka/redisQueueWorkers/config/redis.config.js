import Redis from "ioredis";
import {config} from "dotenv";
config();

const queuePort = process.env.REDIS_QUEUE_PORT || 6384;
const userDataCache = process.env.REDIS_USERDATA_CACHE || 6379;

export const redisQueue = new Redis(Number(queuePort));
export const redisUserDataCache = new Redis(Number(userDataCache));