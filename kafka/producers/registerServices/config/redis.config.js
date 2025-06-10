import Redis from "ioredis";
import {config} from "dotenv";
config();

const redisUserDataCachePort = process.env.REDIS_REGISTER_USERDATA_CACHE || 6379;
const redisEncryptingDataCachePort = process.env.REDIS_REGISTER_ENCRYPTINGDATA_CACHE || 6380;   

export const redisUserDataCache = new Redis(Number(redisUserDataCachePort));
export const redisEncryptingDataCache = new Redis(Number(redisEncryptingDataCachePort));