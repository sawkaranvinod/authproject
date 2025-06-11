import {User} from "../schema/user.model.js";
import {redisEncryptingDataCache,redisUserDataCache} from "../config/redis.config.js";
import {generateKeysAndSecrets} from "../helper/encyptionData.js"


export async function checkUserIdAvailablity(userId,method) {
    const available = await User.findOne({userId});
    const availableInRedisEncryptingCache = await  redisEncryptingDataCache.get(`encryptionData:${userId}`);
    const availableInredisUserDataCache = await redisUserDataCache.get(`userData:${userId}`)

    // console.log(availableInRedis,"          ",available);
    if (available || availableInRedisEncryptingCache || availableInredisUserDataCache) {
        return {
            isExist: true,
            iv:"",
            publicKey:"",
            salt:"",
            userId:"",
            r:0,
            p:0,
            n:0,
        }
    }
    // logic of public privateKey
    const {publicKey,privateKey,salt,iv,p,n,r} = generateKeysAndSecrets(`${method}`);
    const encryptionData = {publicKey,privateKey,salt,iv,p,n,r};
    const cache = await redisEncryptingDataCache.set(`encryptionData:${userId}`,JSON.stringify(encryptionData),"EX",300);
    if (!cache) {
        return {
            isExist:false,
            iv:"",
            publicKey:"",
            salt:"",
            userId:"intrnal server error",
            r:0,
            p:0,
            n:0,
        }
    }
    return {
        isExist:false,
        iv:iv,
        publicKey:publicKey,
        salt:salt,
        userId:userId,
        r:r,
        p:p,
        n:n,
    }
};