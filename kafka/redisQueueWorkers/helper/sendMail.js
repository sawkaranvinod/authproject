import nodemailer from 'nodemailer';
import {config} from "dotenv";
config()

const pass = process.env.PASS || 'bwvg gigq pklv pqel';
const gmail = process.env.GMAIL || "bs7819679@gmail.com";

// Create a transporter using Gmail and your App Password
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: gmail,         // Replace with your Gmail address
    pass: pass,          // Your App Password
  },
});


export function sendMail(to,subject,text) {
    const from = gmail;
    // Define email details
    const mailOptions = {from,to,subject,text};
    const mail = transporter.sendMail(mailOptions,(error,info)=>{
        if (error) {
            console.log(error);
            return false
        }
        return true
    })

    return mail

}
