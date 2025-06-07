import mongoose from "mongoose";

/**
 * this is the url which will connect to the mongodb database
 * @param {string} URI 
 */

export async function connectDB(URI) {
    try {
        const connection = await mongoose.connect(String(URI));
        console.log("database is connected successfully");
    } catch (error) {
        console.log(error);
        proccess.exit(-1);
    }
};
