import grpc from "@grpc/grpc-js";
import protoLoader from "@grpc/proto-loader";
import {config} from "dotenv";
import path from "path";
import {fileURLToPath} from "url";
import {services} from "../function/services.js"
config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const registerServiceDatabasePort = process.env.GRPC_REGISTER_DATABASE_WORKER_PORT || 75005;

const packageDefination = protoLoader.loadSync(
    path.join(__dirname,"../../proto/registerServices.db.proto"),{}
);

const proto = grpc.loadPackageDefinition(packageDefination).registerUserDatabase;

export function startServer() {
    const server = new grpc.Server();
    server.addService(proto.RegisterServicesDatabase.service,services);
    server.bindAsync(`0.0.0.0:${registerServiceDatabasePort}`,grpc.ServerCredentials.createInsecure());
}