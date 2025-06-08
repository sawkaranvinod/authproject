import Fastify from 'fastify';
import mercurius from 'mercurius';
import dotenv from "dotenv";
dotenv.config();


const app = Fastify();

const port = process.env.PORT || 4000;

const schema = `
  type Book {
    title: String
    author: String
  }

  type Query {
    books: [Book]
  }
`;

const resolvers = {
  Query: {
    books: async () => [
      { title: '1984', author: 'George Orwell' },
      { title: 'Sapiens', author: 'Yuval Noah Harari' },
    ],
  },
};

app.register(mercurius, {
  schema,
  resolvers,
  graphiql: true, // or playground: true
});

app.listen({ port }, () => {
  console.log('🚀 Mercurius GraphQL ready at http://localhost:4000/graphql');
});
