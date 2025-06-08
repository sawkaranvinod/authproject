import mongoose from "mongoose";

// this is hahed by the userdatahashingDetail hashing mechenism
const userSignUpDetailSchema = mongoose.Schema(
    {
        hashedIpAddress:{
            type:String,
            required:true,
            trim:true,
        },
        hashedCoordinate:{
            type:{
                longitude:{
                    type:Number,
                    trim:true,
                },
                latitude:{
                    type:Number,
                    trim:true,
                }
            },
            required:true,
        },
        browser:{
            type:String,
            required:true,
            trim:true,
            lowercase:true,
        },
        deviceName:{
            type:String,
            required:true,
            trim:true,
            lowercase:true,
        },
    },
    {
        timestamps:true,
    }
);



export const UserSignUpDetail = mongoose.model("UserSignUpDetail",userSignUpDetailSchema);