import grpc from "@grpc/grpc-js";
import {config} from "dotenv";
import protoLoader from "@grpc/proto-loader";
import path from "path";
import {fileURLToPath} from "url";
import {services} from "../function/services.js"

config();


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const resendOTPRegisterServicesPort = process.env.GRPC_RESEND_OTP_PORT || 45001;


const packageDefination = protoLoader.loadSync(
    path.join(__dirname,"../../proto/resendOTP.proto"),{}
);

const proto = grpc.loadPackageDefinition(packageDefination).resendOTP;

export function startServer() {
    console.log("starting server")
    const server = new grpc.Server();
    server.addService(proto.ResendOTP.service, services); // <-- fix here
    server.bindAsync(`0.0.0.0:${resendOTPRegisterServicesPort}`, grpc.ServerCredentials.createInsecure(), (err, port) => {
        if (err) {
            console.log(err);
            process.exit(-1);
        }
        console.log(`resendOTPRegisterServices grpc server is starting at localhost:${resendOTPRegisterServicesPort}`);
    });
}