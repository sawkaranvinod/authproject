import {User} from "../schema/user.model.js";
import {redis} from "../config/redis.config.js";
import {generateKeysAndSecrets} from "../helper/encyptionData.js"


export async function checkUserIdAvailablity(userId) {
    const available = await User.findOne({userId});
    const availableInRedis = await  redis.get(`encryptionData:${userId}`);
    console.log(availableInRedis,"          ",available);
    if (available || availableInRedis) {
        return {
            isExist: true,
            iv:"",
            publicKey:"",
            salt:"",
            userId:"",
        }
    }
    // logic of public privateKey
    const {publicKey,privateKey,salt,iv,p,n,r} = await generateKeysAndSecrets();
    const encryptionData = {publicKey,privateKey,salt,iv,p,n,r};
    const cache = await redis.set(`encryptionData:${userId}`,JSON.stringify(encryptionData),"EX",300);
    if (!cache) {
        return {
            isExist:false,
            iv:"",
            publicKey:"",
            salt:"",
            userId:"intrnal server error",
        }
    }
    return {
        isExist:false,
        iv:iv,
        publicKey:publicKey,
        salt:salt,
        userId:userId,
    }
};