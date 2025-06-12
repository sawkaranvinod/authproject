import grpc from "@grpc/grpc-js";
import protoLoader from "@grpc/proto-loader";
import {config} from "dotenv";
import {fileURLToPath} from "url";
import path from "path";
config();


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


const grpcConsumerWorkerPort = process.env.GRPC_CONSUMER_WORKER_PORT || 60005;

const packageDefination = protoLoader.loadSync(
    path.join(__dirname,"../../proto/sendInQueue.proto"),{}
);

const proto = grpc.loadPackageDefinition(packageDefination).sendInQueue;

export const SendInQueue = new proto.SendInQueue(`0.0.0.0:${grpcConsumerWorkerPort}`,grpc.credentials.createInsecure());