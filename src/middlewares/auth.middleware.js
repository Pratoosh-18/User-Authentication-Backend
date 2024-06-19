import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";

export const verifyJWT = async (req, res, next) => {
    try {
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "")
        if (!token) {
            throw new Error('Bad request', { statusCode: 404 })
        }
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
        const user = await User.findById(decodedToken?._id).select("-password -refreshToken")
        if (!user) {
            throw new Error('Invalid access token', { statusCode: 404 })
        }
        req.user = user;
        next()
    } catch (error) {
        throw new Error('Jwt verification error', { statusCode: 404 })
    }
}