import Fastify from 'fastify';
import mercurius from 'mercurius';
import dotenv from "dotenv";
dotenv.config();


const app = Fastify();

const port = process.env.PORT || 4000;


app.register(mercurius, {
  
  graphiql: true, // or playground: true
});

app.listen({ port }, () => {
  console.log('🚀 Mercurius GraphQL ready at http://localhost:4000/graphql');
});
