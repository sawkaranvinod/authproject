import Redis from "ioredis";

export const redisUserDataCache = new Redis();
export const redisEncryptingDataCache = new Redis(6380);


