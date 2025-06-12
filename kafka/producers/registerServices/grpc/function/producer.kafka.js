import {producer} from "../../config/redpanda.config.js";
import {config} from "dotenv";
import {redisEncryptingDataCache,redisUserDataCache} from "../../config/redis.config.js"
config();
const topic = process.env.REDPANDA_REGISTER_PRODUCER_TOPIC || "registerServiceOTP";
const partition = process.env.REDPANDA_REGISTER_PRODUCER_PARTITION|| 0;
const faultTolaranceTopic = process.env.REDPANDA_REGISTER_FAULT_TOLARANCE_TOPIC ||"registerServicesOTPFaultTolarance";
const faultTolarancePartiton = process.env.REDPANDA_REGISTER_FAULT_TOLARANCE_PARTITION || 0;


export const services = {
    register: async (call, callback) => {
        const userData = call.request; // <-- no JSON.parse
        const userId = userData.userId;
        // console.log(userId);
        const result = {
            acknowledgement: "otp is sending",
            userId: userId,
        }
        const problem = {
            acknowledgement: "internal server error",
            userId: "",
        };
        try {
            let encryptionData = await redisEncryptingDataCache.get(`encryptionData:${userId}`);
            // console.log("encryptionData for", userId, ":", encryptionData);
            if (!encryptionData) {
                callback(null, problem);
                return;
            }
            encryptionData = await JSON.parse(encryptionData);
            userData.privateKey = encryptionData.privateKey;
            userData.r = encryptionData.r;
            userData.p = encryptionData.p;
            userData.n = encryptionData.n;
            userData.iv = encryptionData.iv;
            userData.salt = encryptionData.salt;
            userData.publicKey = encryptionData.publicKey;
            const kafkaData = {
                userId,
                context:"registerServices"
            }
            const produce = await producer.send(
                {
                    topic: `${topic}`,
                    partition: Number(partition),
                    messages: [{ key: "sendOTP", value: JSON.stringify(kafkaData) }],
                }
            );
            if (produce) {
                const cacheData = await redisUserDataCache.set(`userData:${userId}`,JSON.stringify(userData),"EX",300);
                callback(null, result);
                return;
            }
            callback(null, problem);
        } catch (error) {
            console.log(error);
            try {
                const kafkaData = {
                userId,
                email:userData.email,
                context:"registerServices"
                }
                const produce = await producer.send(
                    {
                        topic: `${faultTolaranceTopic}`,
                        partition: Number(faultTolarancePartiton),
                        messages: [{ key: "sendOTP", value: JSON.stringify(kafkaData) }],
                    }
                );
                if (produce) {
                    const cacheData = await redisUserDataCache.set(`userData:${userId}`,JSON.stringify(userData),"EX",300);
                    callback(null, result);
                    return;
                }
                callback(null, problem);
            } catch (error) {
                console.log("error in fault tolarance", error);
                callback(null, problem);
            }
        }
    },
}