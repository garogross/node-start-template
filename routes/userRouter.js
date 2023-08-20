import express from "express";
import {
    checkIfFieldsAreUpdatable,
    clearUsers, deactivateCurrUser, deleteUser,
    forgotPassword, getCurrUser, getUser,
    getUsers,
    login,
    resetPassword, resizeUserImage,
    signUp,
    updatePassword, updateUserData, uploadImageFile
} from "../controllers/userController.js";
import {protect, restrictTo} from "../controllers/authController.js";

export const userRouter = express.Router()


userRouter.post('/signup', signUp)
userRouter.post('/login', login)
userRouter.post('/forgotPassword', forgotPassword)
userRouter.patch('/resetPassword/:token', resetPassword)
userRouter
    .route('/')
    .get(getUsers)
    .delete(protect, restrictTo("admin"),
    clearUsers
    )

userRouter.use(protect)

userRouter.patch('/updatePassword', updatePassword)
userRouter.get('/me', getCurrUser, getUser)
userRouter.patch(
    '/updateUserData',
    uploadImageFile,
    resizeUserImage,
    checkIfFieldsAreUpdatable,
    updateUserData
)

userRouter.delete('/deleteCurrUser', deactivateCurrUser)

userRouter.delete(
    '/:id',
    restrictTo('admin', 'lead-guide'),
    deleteUser
)