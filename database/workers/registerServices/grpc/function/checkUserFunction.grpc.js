import {checkUserIdAvailablity} from "../../controllers/checkUserAvailablity.controllers.js"

export const services = {
    checkUserIdAvailablity: (call, callback) => {
        const userId = call.request.userId; // <-- FIXED
        const result = checkUserIdAvailablity(userId);
        callback(null, result);
    }
};