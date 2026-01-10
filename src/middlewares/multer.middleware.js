// where ever file upload will be required, we will inject this Middleware their, like in registration we will do, in login we will not do.

import multer from "multer"

// storing in diskStorage not in memoryStorage.
const storage = multer.diskStorage({

    //destination where to upload
    destination: function (req, file, cb) {
        // by default callback's first argument is error(so we keep it null), second is destination path
        cb(null, "./public/temp")
    },
    filename: function (req, file, cb) {

        // keep the names of the files as the user have given them , dont alter them
        cb(null, file.originalname)
    }
})

export const upload = multer({
    storage,
})

// after running this middleware we fet access to "req.files" and "req.file"