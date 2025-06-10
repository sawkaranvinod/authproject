import {ClientCheckUserIdAvailablity,ClientRegister} from "../../grpcClientServer/registerService.grpcClient.js";

const Mutation = {
    checkUserIdAvailablity: async (_, { userId }) => {
        return new Promise((resolve, reject) => {
            ClientCheckUserIdAvailablity.checkUserIdAvailablity({ userId }, (err, res) => {
                if (err) {
                    console.log(err);
                    return reject(err);
                }
                // Defensive: ensure non-nullable fields are always present
                // for any fault this is given to ensure that server will not be down
                if (!res) {
                    return resolve({
                        isExist: false,
                        userId,
                        publicKey: null,
                        salt: null,
                        iv: null
                    });
                }
                // upto this
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
    register: async (_, { 
        userId, 
        hashedPassword, 
        hashedName, 
        email, 
        hashedFatherName, 
        hashedMotherName, 
        longitude, 
        latitude, 
        browser, 
        deviceName, 
        method, 
        gender, 
        twoFactorAuthentication, 
        dateOfBirth, 
        hashedIpAddress // if needed
    }) => {
        return new Promise((resolve, reject) => {
            ClientRegister.register({
                userId,
                hashedPassword,
                hashedName,
                email,
                hashedFatherName,
                hashedMotherName,
                longitude,
                latitude,
                browser,
                deviceName,
                method,
                gender,
                twoFactorAuthentication,
                dateOfBirth,
                hashedIpAddress // if needed
            }, (err, res) => {
                if(err){
                    console.log(err);
                    return reject(err);
                };

                if(!res){
                    return resolve(
                        {
                            acknowledgement:"internal server error",
                            userId:userId,
                        }
                    )
                }
                resolve(
                    {
                        acknowledgement: res.acknowledgement ?? "interal server error",
                        userId: res.userId ?? userId,
                    }
                )
                
            })
        })
    },
    resendOTP:async (_,{userId}) =>{
        return new Promise((resolve,reject)=>{
            ClientRegister.resendOTP({userId},(err,res)=>{
                if(err){
                    console.log(err);
                    return reject(err);
                };
                if (!res) {
                    return resolve(
                        {
                            acknowledgement:"internal server error",
                            userId:userId,
                        }
                    )
                };
                resolve(
                    {
                        acknowledgement:res.acknowledgement ?? "internal server error",
                        userId: userId,
                    }
                )
            })
        })
    },
    verifyOTP: async (_,{userId,OTP}) => {
        return new Promise((resolve,reject)=>{
            ClientRegister.verifyOTP({userId,OTP},(err,res)=>{
                if(err){
                    console.log(err);
                    return reject(err);
                };
                if (!res) {
                    return resolve(
                        {
                            isVerified: false,
                            acknowledgement: "internal server error",
                            userId:userId,
                        }
                    )
                };
                resolve(
                    {
                        isVerified: res.isVerified ?? false,
                        acknowledgement: res.acknowledgement ?? "internal server error",
                        userId: userId,
                    }
                );
            })
        })
    }
};


export const resolver = { Mutation }