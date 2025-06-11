import {producer} from "../../config/redpanda.config.js";
import {config} from "dotenv"
config();
const topic = process.env.REDPANDA_RESEND_OTP_TOPIC || "resendOTPRegisterServics";
const partition = process.env.REDPANDA_RESEND_OTP_PARTITION || 0;
const faultTolaranceTopic = process.env.REDPANDA_RESEND_OTP_FAULT_TOLARANCE_TOPIC ||"resendOTPRegisterServicesFaultTolarance";
const faultTolarancePartiton = process.env.REDPANDA_RESEND_OTP_FAULT_TOLARANCE_PARTITION || 0;


export const services = {
    resendOTP: async (call, callback) => {
        const userData = call?.request;
        let result;
        // console.log(call); // used for debuging

        if (userData) {
            result = {
                acknowledgement:"otp is sending",
                userId: userData.userId,
                context: userData.context,
            }
        }
        const problem = {
            acknowledgement:"internal server error",
            userId: "",
            context:"",
        };
       try {
         const produce = await producer.send(
             {
                 topic: `${topic}`,
                 partition: Number(partition),
                 messages: [{ key: "sendOTP", value: JSON.stringify(userData) }], // <-- fix here
             }
         );
         
            callback(null,result);
         
         
       } catch (error) {
        console.log(error);
        try {
             const produce = await producer.send(
                 {
                     topic: `${faultTolaranceTopic}`,
                     partition: Number(faultTolarancePartiton),
                     messages: [{ key: "sendOTP", value: JSON.stringify(userData) }], // <-- fix here
                 }
             );
             
                
                callback(null,result);
             
             
        } catch (error) {
            console.log("error in fault tolarance",error);
            callback(null,problem);
        }
       }
    },
    
}