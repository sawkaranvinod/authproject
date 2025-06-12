import grpc from "@grpc/grpc-js";
import protoLoader from "@grpc/proto-loader";
import {config} from "dotenv";
import {fileURLToPath} from "url";
import path from "path";
import {services} from "../function/services.js"


config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const consumerWorkerPort = process.env.GRPC_CONSUMER_WORKER_PORT || 60005;

const packageDefination = protoLoader.loadSync(
    path.join(__dirname,"../../proto/sendInQueue.proto"),{}
);

const proto = grpc.loadPackageDefinition(packageDefination).sendInQueue;

export function startServer() {
    console.log("server is starting");
    const server = new grpc.Server();
    server.addService(proto.SendInQueue.service,services);
    server.bindAsync(`0.0.0.0:${consumerWorkerPort}`,grpc.ServerCredentials.createInsecure());
    console.log(`server is running at localhost:${consumerWorkerPort}`);
}
