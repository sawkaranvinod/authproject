import {ClientCheckUserIdAvailablity,ClientRegister,ResendOTPRegisterServices,VerifyOTPRegisterServices} from "../../grpcClientServer/registerService.grpcClient.js";

const Mutation = {
    checkUserIdAvailablity: async (_, { userId,method }) => {
        return new Promise((resolve, reject) => {
            ClientCheckUserIdAvailablity.checkUserIdAvailablity({ userId,method }, (err, res) => {
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
                        iv: null,
                        r:0,
                        p:0,
                        n:0,
                    });
                }
                // console.log(res)
                // upto this
                resolve({
                    isExist: res.isExist ?? false,
                    userId: res.userId ?? userId,
                    publicKey: res.publicKey ?? null,
                    salt: res.salt ?? null,
                    iv: res.iv ?? null,
                    r: res.r ?? 0,
                    p: res.p ?? 0,
                    n: res.n ?? 0,
                });
            });
        });
    },
    register: async (_, { 
        userId, 
        hashedPassword, 
        hashedName, 
        hashedEmail, 
        hashedFatherName, 
        hashedMotherName, 
        hashedLongitude, 
        hashedLatitude, 
        hashedBrowser, 
        hashedDeviceName, 
        hashedMethod, 
        hashedGender, 
        hashedTwoFactorAuthentication, 
        hashedIpAddress // if needed
    }) => {
        return new Promise((resolve, reject) => {
            ClientRegister.register({
                userId,
                hashedPassword,
                hashedName,
                hashedEmail,
                hashedFatherName,
                hashedMotherName,
                hashedLongitude,
                hashedLatitude,
                hashedBrowser,
                hashedDeviceName,
                hashedMethod,
                hashedGender,
                hashedTwoFactorAuthentication,
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
                console.log("gRPC register response:", res);
                resolve({
                    acknowledgement: res.acknowledgement ?? "internal server error",
                    userId: res.userId ?? userId,
                });
                
            })
        })
    },
    resendOTP: async (_,{userId, context}) =>{
        return new Promise((resolve,reject)=>{
            ResendOTPRegisterServices.resendOTP({userId, context},(err,res)=>{
                if(err){
                    console.log(err);
                    return reject(err);
                };
                if (!res) {
                    return resolve(
                        {
                            acknowledgement:"internal server error",
                            userId:userId,
                            context: context,
                        }
                    )
                };
                resolve(
                    {
                        acknowledgement:res.acknowledgement ?? "internal server error",
                        userId: userId,
                        context: context,
                    }
                )
            })
        })
    },
    verifyOTP: async (_,{userId,OTP}) => {
        return new Promise((resolve,reject)=>{
            VerifyOTPRegisterServices.verifyOTP({userId,OTP},(err,res)=>{
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