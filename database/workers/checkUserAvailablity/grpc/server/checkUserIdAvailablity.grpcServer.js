import grpc from "@grpc/grpc-js";
import protoLoader from "@grpc/proto-loader";
import path from "path";
import {config} from "dotenv";
import {services} from "../function/checkUserFunction.grpc.js"
import { fileURLToPath } from 'url';

// Fix for __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

config();

const checkUserIdServerPort = process.env.PORT || "40002"

const packageDefinition = protoLoader.loadSync(
    path.join(__dirname, "../../proto/checkUserIdServices.proto"),
    {}
);

const proto = grpc.loadPackageDefinition(packageDefinition).checkUserId;

export function startServer() {
    console.log("Starting gRPC server setup...");
    const server = new grpc.Server();
    // Use the service definition, not the client constructor
    // console.log("proto.CheckUserId:", proto.CheckUserId);
    // console.log("proto.CheckUserId.service:", proto.CheckUserId?.service);
    // console.log("services:", services);
    server.addService(proto.CheckUserId.service, services);
    server.bindAsync(`0.0.0.0:${checkUserIdServerPort}`, grpc.ServerCredentials.createInsecure(), (err, port) => {
        if (err) {
            console.error("Failed to bind server:", err);
            process.exit(1);
        }
        console.log(`server is started at port localhost:${checkUserIdServerPort}`);
        // server.start();
    });
}