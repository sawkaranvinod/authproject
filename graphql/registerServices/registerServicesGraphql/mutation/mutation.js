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
    checkUserIdAvailablity(userId: String!): availablity
    register(
      userId: String!,
      hashedPassword: String!,
      hashedName: String!,
      email: String!,
      hashedFatherName: String,
      hashedMotherName: String,
      longitude: Float,
      latitude: Float,
      browser: String!,
      deviceName: String!,
      method: String!,
      gender: String!,
      twoFactorAuthentication:String!,
      dateOfBirth:String!,
    ): registerAcknowledgement
    resendOTP(userId: String!): resendOTPAcknowledgement
    verifyOTP(userId: String!, OTP: Float!): verifyOTPAcknowledgement
  }
`;