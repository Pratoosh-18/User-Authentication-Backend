import { User } from "../models/user.model.js"

const getRefereshAndAccessToken = async (userId) => {
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false })

        return { accessToken, refreshToken }


    } catch (error) {
        throw new Error('Token generation went wrong', { statusCode: 404 })
    }
}

const registerUser = async (req, res) => {
    const { username, email, fullname, password } = req.body
    console.log(username, email, fullname, password)

    // Validations
    if (username === undefined) {
        throw new Error('Username is not defined', { statusCode: 404 })
    }
    if (email === undefined) {
        throw new Error('Email is not defined', { statusCode: 404 })
    }
    if (fullname === undefined) {
        throw new Error('Fullname is not defined', { statusCode: 404 })
    }
    if (password === undefined) {
        throw new Error('Password is not defined', { statusCode: 404 })
    }

    const existedUser = await User.findOne({
        $or: [{ username }, { email }]
    })

    if (existedUser) {
        throw new Error('Username or email already exist', { statusCode: 404 })
    }
    //console.log(req.files);

    const user = await User.create({
        fullname,
        email,
        password,
        username: username.toLowerCase()
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refershToken"
    )
    if (!createdUser) {
        throw new Error('Something went wrong registering the user', { statusCode: 500 })
    }
    return res.status(200).json({ createdUser })

}

const loginUser = async (req, res) => {
    const { username, email, password } = req.body
    if (!username && !email) {
        throw new Error('At least one field is required', { statusCode: 404 })
    }
    const user = await User.findOne({
        $or: [{ username }, { email }]
    })
    if (!user) {
        throw new Error('User does not exist', { statusCode: 404 })
    }

    const isPasswordValid = await user.isPasswordCorrect(password)
    if (!isPasswordValid) {
        throw new Error('Incorrect password', { statusCode: 404 })
    }

    const { accessToken, refreshToken } = await getRefereshAndAccessToken(user._id)

    const loggedInUser = await User.findById(user._id)

    const options = {
        httpOnly: true,
        secure: true
    }

    return res.status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(loggedInUser)
}

const logoutUser = async (req, res) => {
    const luser = await User.findByIdAndUpdate(
        req.user._id,
        {
            $unset: {
                refreshToken: 1 // this removes the field from document
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res.status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(luser)
}

export { registerUser, loginUser, logoutUser }     