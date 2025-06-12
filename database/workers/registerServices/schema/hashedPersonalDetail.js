import mongoose from "mongoose";
import { type } from "os";



const hashedPersonalDetailSchema = new mongoose.Schema(
    {
        hashedName:{
            type:String,
            required:true,
        },
        hashedMotherName:{
            type:String,
            required:true,
        },
        hashedFatherName:{
            type:String,
            required:true,
        },
        hashedDOB:{
            type:String,
            required:true,
        }
    }
);


export const HashedPersonalDetail = mongoose.model("HashedPersonalDetail",hashedPersonalDetailSchema);