import Redis from "ioredis";
import {config} from "dotenv";
config();


const redisUserDataCachePort = process.env.REDIS_USERDATA_CACHE || 6379;
export const redisUserDataCache = new Redis(Number(redisUserDataCachePort));