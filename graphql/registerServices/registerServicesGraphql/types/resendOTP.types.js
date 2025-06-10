export const resendOTPAcknowledgement = `#graphql
    type resendOTPAcknowledgement{
        acknowledgement: String!,
        userId:String!,
        context:String!
    }
`