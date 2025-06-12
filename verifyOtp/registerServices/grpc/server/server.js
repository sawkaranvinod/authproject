import grpc from "@grpc/grpc-js";
import protoLoader from "@grpc/proto-loader";
import {config} from "dotenv";
import {fileURLToPath} from "url";
import path from "path";
import {services} from "../function/services.js"

config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


const registerServicesVerifyOTPPort = process.env.GRPC_REGISTER_VERIFY_OTP_PORT || 70005;
const packageDefination = protoLoader.loadSync(
    path.join(__dirname,"../../proto/verifyOTPRegisterServices.proto"),{}
);


const proto = grpc.loadPackageDefinition(packageDefination).verifyOTPRegisterServices;


export function startServer() {
    console.log("starting Server");
    const server = new grpc.Server();
    server.addService(proto.VerifyOTPRegisterServices.service,services);
    server.bindAsync(`0.0.0.0:${registerServicesVerifyOTPPort}`,grpc.ServerCredentials.createInsecure());
}