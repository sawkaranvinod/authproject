import grpc, { loadPackageDefinition } from "@grpc/grpc-js";
import protoLoader from "@grpc/proto-loader";
import path from "path";
import dotenv from "dotenv";
import { fileURLToPath } from 'url';

dotenv.config();

// Fix for __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// const registerUrl = process.env.REGISTER_SERVICES_URL || "localhost:50001";
const registerUrl ="localhost:50005"
const registerPackageDefination = protoLoader.loadSync(
    path.join(__dirname,"../proto/registerServices.proto"),{}
);
const proto = loadPackageDefinition(registerPackageDefination).registerServices;

export const ClientRegister = new proto.RegisterServices(registerUrl, grpc.credentials.createInsecure());

// Load checkUserId proto
const checkUserIdPackageDefinition = protoLoader.loadSync(
    path.join(__dirname, "../proto/checkUserIdServices.proto"), {}
);
const proto2 = loadPackageDefinition(checkUserIdPackageDefinition).checkUserId;

// const checkUserIdUrl = process.env.CHECKUSERID_AVAILABLITY || "localhost:40001";
const checkUserIdUrl = "localhost:40005";
export const ClientCheckUserIdAvailablity = new proto2.CheckUserId(checkUserIdUrl, grpc.credentials.createInsecure());


// const resendOtpRegisterServicesUrl = process.env.RESEND_OTP_REGISTER_SERVICES_URL || "localhost:45001";
const resendOtpRegisterServicesUrl = "localhost:45005"
const resendOTPRegistrationServicesPackageDefination = protoLoader.loadSync(
    path.join(__dirname,"../proto/resendOTP.proto"),{}
);

const proto3 = loadPackageDefinition(resendOTPRegistrationServicesPackageDefination).resendOTP;
export const ResendOTPRegisterServices = new proto3.ResendOTP(resendOtpRegisterServicesUrl,grpc.credentials.createInsecure());


const verifyOTPRegisterServicesUrl = process.env.VERIFY_OTP_REGISTER_SERVICES || "localhost:55001";
const verifyOTPRegisterServicesPackageDefination = protoLoader.loadSync(
    path.join(__dirname,"../proto/verifyOTPRegisterServices.proto"),{}
);

const proto4 = loadPackageDefinition(verifyOTPRegisterServicesPackageDefination).verifyOTPRegisterServices;
export const VerifyOTPRegisterServices = new proto4.VerifyOTPRegisterServices(verifyOTPRegisterServicesUrl,grpc.credentials.createInsecure());

