import grpc, { loadPackageDefinition } from "@grpc/grpc-js";
import protoLoader from "@grpc/proto-loader";
import path from "path";
import dotenv from "dotenv";
import { fileURLToPath } from 'url';

dotenv.config();

// Fix for __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// const registerUrl = process.env.REGISTER_SERVICES_URL || "localhost:40001";
// const registerPackageDefination = protoLoader.loadSync(
//     path.join(__dirname,"../proto/registerServices.proto"),{}
// );
// const proto = loadPackageDefinition(registerPackageDefination).registerServices;

// export const ClientRegister = new proto.registerServices(registerUrl,grpc.credentials.createInsecure());

const checkUserIdUrl = process.env.CHECKUSERID_AVAILABLITY || "localhost:40002";
const checkUserIdPackageDefination = protoLoader.loadSync(
    path.join(__dirname,"../proto/checkUserIdServices.proto"),{}
);
const proto2 = loadPackageDefinition(checkUserIdPackageDefination).checkUserId;

export const ClientCheckUserIdAvailablity = new proto2.CheckUserId(checkUserIdUrl, grpc.credentials.createInsecure());