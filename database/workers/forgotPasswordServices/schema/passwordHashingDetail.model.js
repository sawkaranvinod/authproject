import mongoose from "mongoose";



const passwordHashingDetailSchema = mongoose.Schema(
    {
        method:{
            type:String,
            required:true,
            trim:true,
        },
        byte:{
            type:Number,
            required:true,
            enum:[32,64],
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
        authTag:{
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


export const PasswordHashingDetail = mongoose.model("PasswordHashingDetail",passwordHashingDetailSchema);