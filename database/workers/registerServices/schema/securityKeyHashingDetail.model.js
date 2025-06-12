import mongoose from "mongoose";


const securityKeyHashingDetailSchema = mongoose.Schema(
    {
        method:{
            type:String,
            required:true,
            trim:true,
        },
        iv:{
            type:String,
            required:true,
            trim:true,
        },
        publicKey:{
            type:String,
            required:true,
            trim:true,
        },
        privateKey:{
            type:String,
            required:true,
            trim:true,
        },
        salt:{
            type:String,
            required:true,
            trim:true,
        },
        parameters:{
            type:{
                rParameter:{
                type:Number,
                required:true,
                },
                pParameter:{
                type:Number,
                required:true,
                },
                nParameter:{
                type:Number,
                required:true,
                },
            },
            required:true,
        },
    },
    {
        timestamps:true,
    }
);


export const SecurityKeyHashingDetail = mongoose.model("SecurityKeyHashingDetail",securityKeyHashingDetailSchema);