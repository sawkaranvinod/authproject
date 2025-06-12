import {availablity} from "../types/checkUserIdAvailablity.js";
import {registerAcknowledgement} from "../types/register.type.js";
import {resendOTPAcknowledgement} from "../types/resendOTP.types.js";
import {verifyOTPAcknowledgement} from "../types/verifyOTP.types.js"

export const typeDefs = `#graphql
    ${availablity}
    ${registerAcknowledgement}
    ${resendOTPAcknowledgement}
    ${verifyOTPAcknowledgement}
  type Query {
    _empty: String
  }
  type Mutation {
    checkUserIdAvailablity(userId: String!,method:String!): availablity
    register(
      userId: String!,
      hashedPassword: String!,
      hashedName: String!,
      hashedEmail: String!,
      hashedFatherName: String,
      hashedMotherName: String,
      hashedLongitude: String!,
      hashedLatitude: String!,
      hashedBrowser: String!,
      hashedDeviceName: String!,
      hashedMethod: String!,
      hashedGender: String!,
      hashedTwoFactorAuthentication:String!,
    ): registerAcknowledgement
    resendOTP(userId: String!,context: String!): resendOTPAcknowledgement
    verifyOTP(userId: String!, OTP: Float!): verifyOTPAcknowledgement
  }
`;