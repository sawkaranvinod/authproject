import {availablity} from "../types/checkUserIdAvailablity.js"
import {registerAcknowledgement} from "../types/register.type.js"


export const typeDefs = `#graphql
    ${availablity}
    ${registerAcknowledgement}
  type Mutation {
        checkUserIdExist(userId: String!):availablity
     register(
            userId:String!
            hashedPassword: String!
            hashedName:String!
            email:String
            hashedFatherName:String
            hashedMotherName:String
            longitude:Number
            latitude:Number
            browser:String!
            deviceName:String!
            method:String!
        ):
        registerAcknowledgement
    }
`;