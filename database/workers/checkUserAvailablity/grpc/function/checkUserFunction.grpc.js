import {checkUserIdAvailablity} from "../../controllers/checkUserAvailablity.controllers.js"

export const services = {
    checkUserIdAvailablity: async (call, callback) => {
        const userId = call.request.userId; // <-- FIXED
        const method = call.request.method || "standard";
        const result = await checkUserIdAvailablity(userId,method);
        callback(null, result);
    }
};