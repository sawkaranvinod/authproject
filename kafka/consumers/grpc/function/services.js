import {SendInQueue} from "../server/server.grpc.js";
import {consumer} from "../../config/redapanda.config.js"
import {config} from "dotenv";
import { error } from "console";

config();


const topic = process.env.REDPANDA_CONSUMER_TOPIC || "registerServices";




export async function startConsuming() {
    try {
        await consumer.subscribe(
            {
                topic:  `${topic}`,
                fromBeginning:true,
            }
        );
        await consumer.run(
            {
                eachMessage: async ({topic,partition,message})=>{
                    SendInQueue.sendInQueue({userid:message.userId?.toStrong(),context:message.context?.toString()},(err,res)=>{
                        if (err) {
                            console.log(error);
                            process.exit(-1);
                        };
                        console.log(res.pushedInQueue)
                    })

                }
            }
        )
    } catch (error) {
        console.log(error);
        process.exit(-1);
    }
}



