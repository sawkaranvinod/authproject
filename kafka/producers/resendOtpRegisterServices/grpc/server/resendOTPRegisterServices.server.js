import grpc from "@grpc/grpc-js";
import {config} from "dotenv";
import protoLoader from "@grpc/proto-loader";
import path from "path";
import {fileURLToPath} from "url";

config();


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const resendOTPRegisterServicesPort = process.env.RESEND_OTP_SERVER_PORT || 45001;


const packageDefination = protoLoader.loadSync(
    path.join(__dirname,"../../proto/resendOTPRegisterServices.proto"),{}
);

const proto = grpc.loadPackageDefinition(packageDefination).resendOTPRegisterServices;

export function startServer() {
    console.log("starting server")
    const server = new grpc.Server();
    server.addService(proto.ResendOTPRegisterServicces,services);
    server.bindAsync(`0.0.0.0:${resendOTPRegisterServicesPort}`);
    console.log(`resendOTPRegisterServices grpc server is starting at localhost:${resendOTPRegisterServicesPort}`);
}