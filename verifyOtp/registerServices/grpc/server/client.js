import grpc from "@grpc/grpc-js";
import protoLoader from "@grpc/proto-loader";
import {config} from "dotenv";
import path from "path";
import {fileURLToPath} from "url"
config();


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const registerServicesDatabaseWorkerPort = process.env.GRPC_REGISTER_DATABASE_WORKER_PORT || 75005;

const packageDefination = protoLoader.loadSync(
    path.join(__dirname,"../../proto/registerServices.db.proto")
)