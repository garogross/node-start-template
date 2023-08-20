import multer from "multer";
import {AppError} from "./appError.js";

const multerStorage = multer.memoryStorage()

const multerFilter = (req,file,cb) => {
    if(file.mimetype.startsWith("image")) {
        cb(null,true)
    } else {
        cb(new AppError("Please upload only images",400),false)
    }
}

export const uploadImage = multer({
    storage: multerStorage,
    fileFilter: multerFilter
})