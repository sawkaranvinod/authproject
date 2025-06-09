import grpc, { loadPackageDefinition } from "@grpc/grpc-js";
import protoLoader from "@grpc/proto-loader";
import path from "path"
import dotenv from "dotenv";
dotenv.config();

const url = process.env.REGISTER_SERVICES_URL || "localhost:40001";
const packageDefination = protoLoader.loadSync(path.join(__dirname,"../proto/registerServices.proto"),{});
const proto = loadPackageDefinition(packageDefination).registerServices;

export const client = new proto.registerServices("",grpc.credentials.createInsecure());


