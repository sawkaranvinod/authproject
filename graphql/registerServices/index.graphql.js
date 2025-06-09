import Fastify from 'fastify';
import mercurius from 'mercurius';
import dotenv from "dotenv";
import { registerServices } from "./registerServicesGraphql/index.js";
import mercuriusTracing from 'mercurius-apollo-tracing'; // <-- use import for ESM

dotenv.config();

const app = Fastify();
const port = process.env.PORT || 4000;

app.register(mercurius, {
  schema: registerServices.typeDefs,
  resolvers: registerServices.resolver,
  graphiql: true,
});

// Register Apollo Tracing plugin
app.register(mercuriusTracing, {
  apiKey: process.env.APOLLO_KEY, // from your .env
  graphRef: process.env.APOLLO_GRAPH_REF, // from your .env
  schema:true,
});

app.listen({ port }, (err, address) => {
  if (err) {
    console.error('❌ Server failed to start:', err);
    process.exit(1);
  }
  console.log('🚀 Mercurius GraphQL ready at', address + '/graphql');
});

process.on('exit', (code) => {
  console.log('Process exiting with code:', code);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection:', reason);
});
