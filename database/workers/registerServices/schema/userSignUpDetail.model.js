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
                    type:String,
                    trim:true,
                },
                latitude:{
                    type:String,
                    trim:true,
                }
            },
            required:true,
        },
        hashedBrowser:{
            type:String,
            required:true,
            trim:true,
            lowercase:true,
        },
        hashedDeviceName:{
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