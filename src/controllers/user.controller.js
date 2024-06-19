import { User } from "../models/user.model.js"

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

export { registerUser }     