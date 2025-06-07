import mongoose from "mongoose";


const userSchema = new mongoose.Schema(
    {
        userId:{
            type:String,
            required:true,
            unique:true,
            trim:true,
            lowercase:true,
        },
        hashedPassword:{
            // hashed by using argon2 mechenism because it is best to hashPassword one way hashing
            type:String,
            required:true,
        },
        hashedPersonalDetail:{
            type:mongoose.Schema.Types.ObjectId,
            ref:"hashedPersonalDetail",
        },
        personalDetailHashingDetail:{
            type:mongoose.Schema.Types.ObjectId,
            ref:"personalDetailHashingDetail",
        },
        multiFactorAuthentication:{
            type: Boolean,
            default: false,
        },
        multifactorAuthenticationType:{
            type:String,
            trim:true,
            lowercase:true,
            enum:["phone","email","key","none"],
            default:"none"
        },
        userSignUpDetail:{
            type:mongoose.Schema.Types.ObjectId,
            ref:"UserSignUpDetail",
            required: true,
        },
        loginDetail:{
            type:[mongoose.Schema.Types.ObjectId],
            ref:"LoginDetail",
            required:true,
        },
        TypeOfSecurityKey:{
            type: String,
            lowercase:true,
            default: "none",
            enum: ['faceId', 'fingerprint', 'securityKey',"none"],
        },
        hashedSecurityKeyDetail:{
            type:mongoose.Schema.Types.ObjectId,
            ref:"HashedSecurityKeyDetail",
        },
        securityKeyHasingDetail:{
            type:mongoose.Schema.Types.ObjectId,
            ref:"SecurityKeyHashingDetail",
        },
        hashedByPassKeys:{
            // hashed using argon2 mechenism one time you can see only this byPasskey
            type:[String],
        },
        accountBasedOn:{
            type:String,
            required:true,
            lowercase:true,
            trim:true,
        },
        bannedInCountry:{
            type:[String],
            default:[],
        },
        paymentMethod:{
            type:[String],
            required:true,
            lowercase:true,
            default:"none",
            enum:["none","creditCard","debitCard","UpiId"]
        },
        hashedPaymentDetail:{
            type:mongoose.Schema.Types.ObjectId,
            ref:"HashedPaymentDetail",
        },
        paymentDetailHashingDetail:{
            type:mongoose.Schema.Types.ObjectId,
            ref:"PaymentDetailHashingDetail"
        },
        hashedAddress:{
            type: mongoose.Schema.Types.ObjectId,
            ref:"HashedAddress",
        },
        addressHasingDetail:{
            type: mongoose.Schema.Types.ObjectId,
            ref:"AddressHashingDetail",
        }
    },
    {
        timestamps:true,
    }
);


export const User = mongoose.model("User",userSchema);