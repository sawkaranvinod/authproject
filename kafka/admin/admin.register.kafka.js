import {kafka} from "./exports/kafka.conf.js";
import {config} from "dotenv";
config();

const topic = process.env.REDPANDA_TOPIC || "registerServicesOtp";
const faultTolaranceTopic = process.env.REDPANDA_FAULT_TOLERANCE_TOPIC || "registerServicesOTPFaultTolarance";
const faultTolarancePartition = process.env.REDPANDA_FAULT_TOLERANCE_NO_PARTITION || 6;
const partition = process.env.REDPANDA_NO_PARTITION || 6;

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

init();