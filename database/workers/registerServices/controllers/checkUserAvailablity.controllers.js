import {User} from "../schema/user.model.js";



export async function checkUserIdAvailablity(userId) {
    const available = await User.findOne({userId});
    if (available) {
        return {
            isExist: true,
            iv:"",
            publicKey:"",
            salt:"",
            userId:userId,
        }
    }
    // logic of 
    return {
        isExist:false,
        iv:"sfefwe",
        publicKey:"sdfwqsfd",
        salt:"sdfqefwe",
        userId:userId,
    }
}