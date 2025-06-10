import {producer} from "../../config/redpanda.config.js";
import {config} from "dotenv";

config();


const topic = process.env.RESEND_OTP_REGISTER_SERVICES_REDPANDA_TOPIC || "resendOTPRegisterServices"