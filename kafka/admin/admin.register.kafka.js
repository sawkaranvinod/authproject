import {kafka} from "./exports/kafka.conf.js";
import {config} from "dotenv";
config();

const topic = process.env.TOPIC || "registerServicesOtp";
const faultTolaranceTopic = process.env.FAULTTOLARANCE_TOPIC || "registerServicesOTPFaultTolarance";
const faultTolarancePartition = process.env.FAULTTOLARANCE_NO_PARTITION || 6;
const partition = process.env.NO_PARTITION || 6;

async function init() {
     const admin = kafka.admin();
     console.log("admin connecting");
     await admin.connect();
     console.log("admin connected sucessfully");
    await admin.createTopics(
        {
            topics:[
                {
                    topic:`${topic}`,
                    numPartitions:Number(partition),
                },
                {
                    topic:`${faultTolaranceTopic}`,
                    numPartitions:Number(faultTolarancePartition),
                }
            ]
        }
     );

     console.log("topics created");
     await admin.disconnect();
     console.log("admin disconnected");
     
     
};

init()