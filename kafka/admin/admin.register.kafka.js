import {kafka} from "./exports/kafka.conf.js";


async function init() {
     const admin = kafka.admin();
     console.log("admin connecting");
     await admin.connect();
     console.log("admin connected sucessfully");
    await admin.createTopics(
        {
            topics:[
                {
                    topic:"registerServicesOTP",
                    numPartitions:6,
                },
                {
                    topic:"registerServicesOTPFaultTolarance",
                    numPartitions:6
                }
            ]
        }
     );

     console.log("topics created");
     await admin.disconnect();
     console.log("admin disconnected");
     
     
};

init()