import {ClientCheckUserIdAvailablity} from "../../grpcClientServer/registerService.grpcClient.js";


const Mutation = {
    checkUserIdExist: async (_, { userId }) => {
        return new Promise((resolve, reject) => {
            ClientCheckUserIdAvailablity.checkUserIdAvailablity({ userId }, (err, res) => {
                if (err) {
                    console.log(err);
                    return reject(err);
                }
                // Defensive: ensure non-nullable fields are always present
                if (!res) {
                    return resolve({
                        isExist: false,
                        userId,
                        publicKey: null,
                        salt: null,
                        iv: null
                    });
                }
                resolve({
                    isExist: res.isExist ?? false,
                    userId: res.userId ?? userId,
                    publicKey: res.publicKey ?? null,
                    salt: res.salt ?? null,
                    iv: res.iv ?? null
                });
            });
        });
    },
    register: async (_, { userId, hashedPassword, hashedName, email, hashedFatherName, hashedMotherName, longitude, latitude, browser, deviceName, method }) => {
        console.log(userId);
        return {
            message:"ok",
            userId:userId,
        }
    },
    resendOTP:async (_,{userId}) =>{
        console.log(userId);
        return {
            acknowledgement:"otp Sent",
            userId:userId
        }
    },
    verifyOTP: async (_,{userId,OTP}) => {
        console.log(userId,OTP);
        return {
            acknowledgement:"otp verified",
            userId:userId
        }
    }
};


export const resolver = { Mutation }