import {producer} from "../../config/redpanda.config.js";
import {config} from "dotenv"
config();
const topic = process.env.REDPANDA_TOPIC || "registerServiceOTP";
const partition = process.env.REDPANDA_PARTITION || 0;


export const services = {
    register:async (call,callback)=>{
        const userData = call?.request;
        const produce = await producer.send(
            {
                topic: `${topic}`,
                partition: Number(partition),
                messages: [{ key: "sendOTP", value: JSON.stringify(userData) }], // <-- fix here
            }
        );

        const result = {
            acknowledgement:"message produced",
            userId: call.request.userId,
        }
        const error = {
            acknowledgement:"internal server error",
            userId: "",
        };
        if(!produce){
            callback(null,error);
        };
        callback(null,result);
    },
    resendOTP:async (call,callback) => {
        const userId = call.request.userId;
        if(!userId){
            callback(null,{acknowledgement:"internal server error",userId:""});
        };
        const resendOTP = await producer.send(
            {
                topic: `registerServicesResendOTP`,
                partition: 0,
                messages: [{ key: "resendOTP", value: userId }] // <-- fix here
            }
        );
         const result = {
            acknowledgement:"otp resendded",
            userId: call.request.userId,
        }
        const error = {
            acknowledgement:"internal server error",
            userId: "",
        };
        if(!resendOTP){
            callback(null,error);
        };
        callback(null,result);
    },
    verifyOTP:async (call,callback) => {
        const {OTP,userId} = call.request;
        console.log(OTP,userId);
        const result = {
            isVerified : false,
            userId:userId,
            acknowledgement:"user doest verified"
        }
        callback(null,result)
        
    }
}