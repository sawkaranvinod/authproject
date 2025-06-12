import {User} from "../schema/user.model.js";
import {HashedPersonalDetail} from "../schema/hashedPersonalDetail.js";
import {UserSignUpDetail} from "../schema/userSignUpDetail.model.js";
import {PersonalDetailHashingDetail} from "../schema/personalDetailHasingDetail.js";
import {loginDetail} from "../schema/loginDetail.model.js";


export async function registerUser(
    userId,
    hashedPassword,
    hashedName,
    hashedEmail,
    hashedMotherName,
    hasheFatherName,
    hashedDOB,
    hashedIpAddress,
    hashedLongitude,
    hashedLatitude,
    hashedBrowser,
    hashedDeviceName,
    hashedMethod,
    hashedGender,
    hashedTwoFactorAuthentication,
    publicKey,
    salt,
    privateKey,
    n,
    p,
    r,
    
) {
    
}