import mongoose from "mongoose";


const hashedAddressSchema = new mongoose.Schema(
    {
        buildingName:{
            type:String,
            required:true,
            trim:true,
        },
        roomNo:{
            type:String,
            required:true,
            trim:true,
        },
        landMark:{
            type:String,
            required:true,
            trim:true,
        },
        city:{
            type:String,
            required:true,
            trim:true,
        },
        pincode:{
            type:String,
            required:true,
            trim:true,
        },
        state:{
            type:String,
            required:true,
            trim:true,
        }
    },
    {
        timestamps:true,
    }
);


export const HashedAddress = mongoose.model("HashedAddress",hashedAddressSchema);