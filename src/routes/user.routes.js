import { Router } from "express";
import { loginUser, logoutUser, registerUser, refreshAccessToken, changeCurrentPassword,forgotPassword, getCurrentUser, updateAccountDetails, updateUserAvatar } from "../controllers/user.controllers.js";
import { upload } from "../middlewares/multer.middleware.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router()
//the flow comes here from "userRouter" from app.js and here "/register" is added as a new endpoint and it passes the control to "registerUser", the "registerUser" function is called from the "user.controller.js" and the control is passed to it. 
router.route("/register").post(

    // using the upload Middleware from multer.middleware.js to handle file handling(to accept fields)
    upload.single("avatar"),registerUser
)

router.route("/login").post(loginUser)
router.route("/forgot-password").post(forgotPassword)

// secured routes :: means where user has tot be logged in to continue
router.route("/logout").post(verifyJWT, logoutUser)
router.route("/refresh-token").post(refreshAccessToken)
router.route("/update-user-password").post(verifyJWT, changeCurrentPassword)
router.route("/fetch-current-user-details").get(verifyJWT, getMyProfile)
router.route("/update-account-details").patch(verifyJWT, updateAccountDetails)
router.route("/update-location").patch(verifyJWT, updateLocation)
router.route("/update-avatar").patch(verifyJWT, upload.single("avatar"), updateUserAvatar)

export default router 