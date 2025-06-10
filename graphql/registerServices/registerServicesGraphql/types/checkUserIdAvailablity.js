export const availablity = `#graphql
  type availablity {
    isExist: Boolean!
    userId: String!
    publicKey: String
    salt: String
    iv: String,
    r: Float!,
    p:Float!,
    n:Float!
  }
`