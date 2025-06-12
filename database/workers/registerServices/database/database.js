import mongoose from "mongoose";

/**
 * 
 * @param {String} URI - this is the string passed for connection to the database
 */


export async function connectDB (URI){
    try {
        const connection = await mongoose.connect(String(URI))
    } catch (error) {
        console.log(error);
        process.exit(-1);
    }
}
