import grpc from "@grpc/grpc-js";
import protoLoader from "@grpc/proto-loader";
import { config } from "dotenv";
import path from "path";
import {fileURLToPath} from "url";
import {services} from "../function/producer.kafka.js"

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


config();


const registerServiceProducerPort = process.env.GRPC_REGISTER_SERVER_PORT || 50001;


const packageDefination = protoLoader.loadSync(path.join(__dirname,"../../proto/registerServices.proto"),{});

const proto = grpc.loadPackageDefinition(packageDefination).registerServices;


export function startServer() {
  console.log("starting server");
  const server = new grpc.Server();
  server.addService(proto.RegisterServices.service,services);
  server.bindAsync(`0.0.0.0:${registerServiceProducerPort}`,grpc.ServerCredentials.createInsecure(),(err,port)=>{
    if (err) {
      console.log(err);
      process.exit(-1);
    };
    console.log(`server started at localhost:${registerServiceProducerPort}`);
  });
}
