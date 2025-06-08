import mongoose from "mongoose";


const hashedPaymentDetailSchema = mongoose.Schema(
    {
        creditcardDetail:{
            type:{
                typeOfCard:{
                    type:String,
                    required:true,
                    trim:true,
                },
                cardNo:{
                    type:String,
                    required:true,
                    trim:true,
                },
                cvv:{
                    type:String,
                    required:true,
                    trim:true,
                },
                cardHolderName:{
                    type:String,
                    required:true,
                    trim:true,
                }
            }
        },
        debitcardDetail:{
            type:{
                typeOfCard:{
                    type:String,
                    required:true,
                    trim:true,
                },
                cardNo:{
                    type:String,
                    required:true,
                    trim:true,
                },
                cvv:{
                    type:String,
                    required:true,
                    trim:true,
                },
                cardHolderName:{
                    type:String,
                    required:true,
                    trim:true,
                }
            }
        },
        upiId:{
            type:String,
        }
    },
    {
        timestamps:true,
    }
);


export const HashedPaymentDetail = mongoose.model("HashedPaymentDetail",hashedPaymentDetailSchema);