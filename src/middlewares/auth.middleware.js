import { ApiError } from "../utils/ApiErrors.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken"
import { User } from "../models/user.model.js"

// below we are using req,next but the res is remaining empty, so it can also be written as (req, _, next) this syntax is also
export const verifyJWT = asyncHandler(async (req, res, next) => {
    try {
        // we have cookieParse middleware in app.js which helps us to access cookies from req.cookies, since cookies can be accessed by 2 ways: in req -> req.cookies and in res -> res.cookie
        // getting access of accessToken through cookies and req.header is done for "mobiles" because their we dont have direct access to cookies
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "")

        /*
        Previous (incorrect) code:
        if (!token) {
            throw new ApiError(400, "Unauthorized request")
        }
        */
        if (!token) {
            // FIX: Previously returned 400/402 here. Missing or invalid auth
            // should be 401 (Unauthorized). 402 is "Payment Required" and
            // misleading for auth failures, especially in logout.
            // No token provided via cookies or Authorization header
            throw new ApiError(401, "Access token missing")
        }

        // if we get the token then we ask jwt to verify it by providing it the "process.env.ACCESS_TOKEN_SECRET" and store the info in "decodedToken" variable
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)

        // we get access of _id from decodedToken as while writting access token (generateAccessToken) in user.models.js we added it
        const user = await User.findById(decodedToken?._id).select("-password -refreshToken")

        /*
        Previous (incorrect) code:
        if (!user) {
            throw new ApiError(402, "Invalid Access Token")
        }
        */
        if (!user) {
            // FIX: Avoid 402 here; normalize auth failures to 401 to reflect
            // unauthorized access. This removes confusing 402 responses.
            throw new ApiError(401, "Invalid access token (user not found)")
        }

        // we add a new object(property) to req named user which contains all the user info except password and refreshToken as we excluded them while fetching user from DB, now this req.user will be available in all the routes where we want to use it also in the logoutUser controller. Sinse we cant access cookies(user details) in logoutUser controller so we will access req.user instead to get user info
        req.user = user;
        next()
        
    } catch (error) {
        /*
        Previous (incorrect) code:
        } catch (error) {
            throw new ApiError(402, "Invalid access token")
        }
        */
        // FIX: Catch previously re-threw 402 for any JWT error, masking causes.
        // Use 401 and preserve specific error messages for easier debugging
        // (e.g., token missing, expired, malformed).
        // Normalize all JWT-related failures to 401 Unauthorized
        throw new ApiError(401, error?.message || "Invalid access token")
    }
})