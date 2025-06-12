import mongoose from "mongoose";


const userSchema = new mongoose.Schema(
    {
        userId:{
            type:String,
            required:true,
            unique:true,
            trim:true,
        },
        hashedUserId:{
            type:String,
            required:true,
            trim:true,
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
        hashedAccountBasedOn:{
            type:String,
            required:true,
            trim:true,
        },
        hashedBannedInCountry:{
            type:[String],
            default:[],
        },
        paymentMethod:{
            type:[String],
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
        },
        noOfDeviceActiveLogin:{
            type: [mongoose.Schema.Types.ObjectId],
            ref:"LoginDetail",
        },
        context:{
            type:[String],
            lowercase:true,
            default:[]
        },
        hashedEmail:{
            type:String,
            required:true,
            unique:true,
            trim:true,
        },
        currentStatus:{
            type: String,
            default:"active",
            enum:["active","suspended","freez","suspect","warning"],
            lowercase:true,
        }
    },
    {
        timestamps:true,
    }
);


export const User = mongoose.model("User",userSchema);