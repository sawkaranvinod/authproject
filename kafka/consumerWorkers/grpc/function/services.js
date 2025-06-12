import {redisQueue,redisDeadLetterQueue} from "../../config/redis.config.js"

export const services = {
    sendInQueue: async (call,callback)=>{
        const userId = call.request?.userId;
        const context = call.request?.context;
        const data = {userId,context};
        const pushedInQueue = await redisQueue.lpush(`sendOTP`,JSON.stringify(data));
        if (pushedInQueue) {
            callback(null,{pushedInQueue:true})
        };
        const retry = await redisDeadLetterQueue.lpush(`sendOTP`,JSON.stringify(data));
        if (retry) {
            callback(null,{pushedInQueue:true})
            
        }
        callback(null,{pushedInQueue:false});
    }
}