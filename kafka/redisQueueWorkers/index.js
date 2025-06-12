import {redisQueue,redisUserDataCache} from "./config/redis.config.js";
import {sendMail} from "./helper/sendMail.js";
import {generateOTP} from "./helper/generateOTP.js"


(async ()=>{
    while (true) {
        let otpSendingData = await redisQueue.rpop("sendOTP");
        if (!otpSendingData) {
            console.log("no work");
            continue;
        }
        otpSendingData = await JSON.parse(otpSendingData);
        if (otpSendingData) {
            let userData = await redisUserDataCache.get(`userData:${otpSendingData.userId}`);
            if (!userData) {
                console.log("user data not found");
                continue;
            };
            const otp = generateOTP();
            userData.otp = otp;
            const to = userData.hashedEmail ;
            // logic of decrypting email
            const text = `your otp is ${otp}`
            const sentMail = sendMail(to,"",text);
            if (!sentMail) {
                console.log("unable to send email");
                continue;
            };
            const setUserData = await redisUserDataCache.set(`userData:${userData.userId}`);
            if(setUserData){
                console.log("used cached");
                continue;
            }
            console.log("problem in caching user");
            continue;
        }
    }
})();