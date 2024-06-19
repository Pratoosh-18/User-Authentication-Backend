import { Router } from "express";
import { changeCurrentPassword, getCurrentUser, loginUser, logoutUser, refreshAccessToken, registerUser, sendOtp, updateAccountDetails, verifyOtpAndChangePassword} from "../controllers/user.controller.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router()

router.route("/register").post(
    registerUser
)
router.route("/login").post(
    loginUser
)
router.route("/logout").post(
    verifyJWT, logoutUser
)
router.route("/currentUser").get(
    verifyJWT, getCurrentUser
)
router.route("/changePassword").post(
    verifyJWT, changeCurrentPassword
)
router.route("/updateAccountDetails").post(
    verifyJWT, updateAccountDetails
)
router.route("/refreshAccessToken").post(
    refreshAccessToken
)
router.route("/sendOTP").get(
    sendOtp
)
router.route("/verifyOTPAndChangePassword").post(
    verifyOtpAndChangePassword
)
    
export default router