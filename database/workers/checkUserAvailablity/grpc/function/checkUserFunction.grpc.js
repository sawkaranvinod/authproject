import {checkUserIdAvailablity} from "../../controllers/checkUserAvailablity.controllers.js"

export const services = {
    checkUserIdAvailablity: async (call, callback) => {
        const userId = call.request.userId; // <-- FIXED
        const result = await checkUserIdAvailablity(userId);
        callback(null, result);
    }
};