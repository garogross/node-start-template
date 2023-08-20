import {catchAsync} from "../utils/catchAsync.js";
import {User} from "../models/userModel.js";
import jwt from "jsonwebtoken"
import {AppError} from "../utils/appError.js";
import {Email} from "../utils/email.js";
import * as crypto from "crypto";
import {HandlerFactory} from "./HandlerFactory.js";
import {uploadImage} from "../utils/multer.js";
import {resizeImage} from "../utils/sharp.js";


export const uploadImageFile = uploadImage.single("photo")

export const resizeUserImage = catchAsync(async (req, res, next) => {
    if (!req.file) return next()

    req.file.filename = `user-${req.user.id}-${Date.now()}.jpeg`
    await resizeImage(req.file.buffer, `public/images/users/${req.file.filename}`)
    next()
})

const handlerFactory = new HandlerFactory(User, 'user')

const signToken = (id) => {
    return jwt.sign({id}, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN
    })
}

const createAndSendToken = (user, res, statusCode = 200) => {
    const token = signToken(user._id)

    const tokenOptions = {
        expires: new Date(
            Date.now() + parseInt(process.env.JWT_EXPIRES_IN) * 24 * 60 * 60 * 1000
        ),
        httponly: true
    }

    if (process.env.NODE_ENV === 'production') tokenOptions.secure = true

    // res.cookie('jwt', token, tokenOptions)

    user.password = undefined

    res.status(statusCode).json({
        status: 'success',
        token
    })
}

const filterUserFields = (obj, allowedFields) => {
    const result = {}
    allowedFields.forEach(item => {
        if (obj[item]) {
            result[item] = obj[item]
        }
    })

    return result;
}

export const checkIfFieldsAreUpdatable = (req, res, next) => {
    if (req.body.password || req.body.passwordConfirm) {
        return next(new AppError('this rout is not for password change', 400))
    }
    const updatableFields = ['name', 'email']
    const filteredUserFields = filterUserFields(req.body, updatableFields)
    if (!Object.keys(filteredUserFields).length) {
        return next(new AppError(`there is no any updatable fields,You can only change this fields: ${updatableFields.join(',')}`))
    }
    req.body = filteredUserFields
    next()
}

//////////////
export const signUp = catchAsync(async (req, res) => {
    const {name, email, password, passwordConfirm, role} = req.body
    const user = await User.create({name, email, password, passwordConfirm, role})

    const token = signToken(user._id)
    const {
        password: pass,
        __v,
        ...userData
        } = {...user.toObject()};


    res.send({
        status: 'success',
        token,
        data: userData
    })
})

export const login = catchAsync(async (req, res, next) => {
    const {email, password} = req.body

    if (!email || !password) {
        return next(new AppError('Please provide email or password', 400))
    }

    const user = await User.findOne({email}).select('+password')

    if (!user) {
        return next(new AppError('incorrect email', 401))
    }

    const isPasswordCorrect = await user.correctPassword(password, user.password)

    if (!isPasswordCorrect) {
        return next(new AppError('incorrect password', 401))
    }

    createAndSendToken(user, res)

})

export const forgotPassword = catchAsync(async (req, res, next) => {
    const user = await User.findOne({email: req.body.email})
    if (!user) {
        return next(new AppError('There is no user with email address', 404))
    }

    const resetToken = user.createPasswordResetToken()
    await user.save({validateBeforeSave: false})

    const resetUrl = `${req.protocol}://${req.get('host')}/api/v1/users/resetPassword/${resetToken}`

    try {
        await new Email(user,resetUrl).sendForgotPass()

        res.status(200).json({
            status: 'success',
            message: 'Token sent to email'
        })
    } catch (err) {
        console.log("ERR",err)
        user.passwordResetToken = undefined
        user.passwordResetExpires = undefined
    }

})

export const resetPassword = catchAsync(async (req, res, next) => {
    const hashedToken = crypto
        .createHash('sha256')
        .update(req.params.token)
        .digest("hex")

    const user = await User.findOne({
        passwordResetToken: hashedToken,
        passwordResetExpires: {$gt: Date.now()}
    })

    if (!user) {
        return next(new AppError('Token is invalid or has expired', 400))
    }
    user.password = req.body.password
    user.passwordConfirm = req.body.passwordConfirm
    user.passwordResetToken = undefined
    user.passwordResetExpires = undefined
    await user.save()

    createAndSendToken(user, res)
})

export const updatePassword = catchAsync(async (req, res, next) => {
    if (!req.body.newPassword || !req.body.currentPassword || !req.body.passwordConfirm) {
        return next(new AppError('Current password, new password and password confirm fields are required', 400))
    }

    const user = await User.findById(req.user._id).select('+password')

    if (!user) {
        return next(new AppError('Your token is wrong', 400))
    }
    const isPasswordCorrect = await user.correctPassword(req.body.currentPassword, user.password)

    if (!isPasswordCorrect) {
        return next(new AppError('Entered current password is wrong,please enter right password', 400))
    }

    if (!req.body.newPassword) {
        return next(new AppError('Please enter new password', 400))
    }

    user.password = req.body.newPassword
    user.passwordConfirm = req.body.passwordConfirm
    await user.save()

    createAndSendToken(user, res)
})


export const deactivateCurrUser = catchAsync(async (req, res, next) => {
    await User.findByIdAndUpdate(req.user.id, {active: false})

    res.status(204).json({
        status: 'success',
        data: null
    })
})

export const getUsers = handlerFactory.getAll()
export const updateUserData = handlerFactory.updateOne()
export const deleteUser = handlerFactory.deleteOne()
export const clearUsers = handlerFactory.deleteAll()
export const getUser = handlerFactory.getOne()
export const getCurrUser = handlerFactory.getMe()