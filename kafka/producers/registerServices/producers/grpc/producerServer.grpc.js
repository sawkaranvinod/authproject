import grpc from "@grpc/grpc-js";
import protoLoader from "@grpc/proto-loader";
import { config } from "dotenv";
import path from "path";

config();

const PROTO_PATH = path.resolve("path/to/your.proto"); // Update with your proto file path

// Load proto definition
const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
});
const protoDescriptor = grpc.loadPackageDefinition(packageDefinition);

// Replace 'YourService' and 'yourService' with actual service names from your proto
const yourService = protoDescriptor.YourService;

// Implement your gRPC methods
const serviceImpl = {
  // Example method
  yourMethod: (call, callback) => {
    // Producer logic here
    callback(null, { message: "Produced successfully" });
  },
};

function main() {
  const server = new grpc.Server();
  server.addService(yourService.service, serviceImpl);
  const port = process.env.GRPC_PORT || "50051";
  server.bindAsync(
    `0.0.0.0:${port}`,
    grpc.ServerCredentials.createInsecure(),
    (err, bindPort) => {
      if (err) {
        console.error("Server binding error:", err);
        return;
      }
      server.start();
      console.log(`gRPC producer server running at 0.0.0.0:${bindPort}`);
    }
  );
}

main();
