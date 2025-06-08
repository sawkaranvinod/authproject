import mongoose from "mongoose";


const hashedSecurityKeyDetailSchema = mongoose.Schema(
    {
        faceId:{
            type:{
                hashedSting:{
                    type:String,
                    required:true,
                    trim:true,
                },
            },
        },
        fingerprint:{
            type:{
                hashedSting:{
                    type:String,
                    required:true,
                    trim:true,
                },
            },
        },
        securityKey:{
            type:{
                hashedSting:{
                    type:String,
                    required:true,
                    trim:true,
                },
            },
        },
    },
    {
        timestamps:true,
    }
);


export const HashedSecurityDetail = mongoose.model("HashedSecurityDetail",hashedSecurityKeyDetailSchema);