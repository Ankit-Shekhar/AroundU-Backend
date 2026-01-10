// TODO: within registerUser add the AVATAR functionality.
import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { User } from "../models/user.model.js";
import bcrypt from "bcryptjs";

// writing "generateAccessAndRefreshTokens" function to generate them and use below.
// we dont use "asyncHandler" here because this function is not a controller function, its just a utility function to generate tokens that is going to be used in other controllers.
const generateAccessAndRefreshTokens = async (userId) => {
    try {
        //finding the user in DB on the basis of "userId" and generating access and refresh token
        const user = await User.findById(userId)
        // generate tokens (synchronous jwt.sign in model)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        //saving refresh token in Db, when we try to save it in DB using "user" and not mongoose "User" then mongoose user model kicks in(password field) so to stop that we add "{validateBeforeSave: false}" to stop validating anything else.
        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false })

        // after saving to DB return it.
        return { accessToken, refreshToken }
    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating access and refresh token")
    }
}

// 1️⃣ registerUser
const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password, interests, latitude, longitude } = req.body || {};

  // Validate required fields
  const nameValid = typeof name === "string" && name.trim().length > 0;
  const emailValid = typeof email === "string" && email.trim().length > 0;
  const passwordValid = typeof password === "string" && password.trim().length > 0;
  if (!nameValid || !emailValid || !passwordValid) {
    throw new ApiError(400, "Name, email, and password are required");
  }

  // Check email uniqueness
  const existing = await User.findOne({ email: email.trim().toLowerCase() });
  if (existing) {
    throw new ApiError(409, "Email already in use");
  }

  // Hash password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Convert coordinates to GeoJSON Point if provided
  let location;
  if (latitude !== undefined && longitude !== undefined) {
    const lat = parseFloat(latitude);
    const lon = parseFloat(longitude);
    if (!Number.isFinite(lat) || !Number.isFinite(lon)) {
      throw new ApiError(400, "Invalid coordinates");
    }
    location = {
      type: "Point",
      coordinates: [lon, lat],
    };
  }

  // Create user document
  const user = await User.create({
    name: name.trim(),
    email: email.trim().toLowerCase(),
    password: hashedPassword,
    interests,
    location,
  });

  // Remove password before sending response
  const createdUser = await User.findById(user._id).select("-password");
  if (!createdUser) {
    throw new ApiError(500, "User registration failed");
  }

  return res
    .status(201)
    .json(new ApiResponse(201, createdUser, "User registered successfully"));
});

// 2️⃣ loginUser
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body || {};

  const emailValid = typeof email === "string" && email.trim().length > 0;
  const passwordValid = typeof password === "string" && password.trim().length > 0;
  if (!emailValid || !passwordValid) {
    throw new ApiError(400, "Email and password are required");
  }

  const user = await User.findOne({ email: email.trim().toLowerCase() });
  if (!user) {
    throw new ApiError(404, "User not found");
  }

  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) {
    throw new ApiError(401, "Invalid credentials");
  }

  // Generate tokens via model methods if available (preferred style)
  const accessToken = user.generateAccessToken ? user.generateAccessToken() : null;
  const refreshToken = user.generateRefreshToken ? user.generateRefreshToken() : null;

  if (refreshToken) {
    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });
  }

  const sanitizedUser = await User.findById(user._id).select("-password -refreshToken");

  // Cookie options (consistent policy)
  const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
  };

  // Send token(s) + user info
  const payload = refreshToken
    ? { user: sanitizedUser, accessToken, refreshToken }
    : { user: sanitizedUser, token: accessToken };

  const response = res.status(200);
  if (accessToken) {
    response.cookie("accessToken", accessToken, cookieOptions);
  }
  if (refreshToken) {
    response.cookie("refreshToken", refreshToken, cookieOptions);
  }

  return response.json(new ApiResponse(200, payload, "Logged in successfully"));
});

const logoutUser = asyncHandler(async (req, res) => {
    // we cant directly access the User here, because in cases above we were taking "{ email, fullName, username, password } = req.body" all these info from user on basis of what we were finding user in DB, but in "logoutUser" we dont ask user to enter all these details, so currently we dont have access to the user, so here we use Middleware.


    // why can i access "req.user" here because before comming to this functin we are running a "verifyJWT" middleware which is saving all the details of the user using "User" from mongoose to "req.user"

    User.findByIdAndUpdate(
        await req.user._id,
        {
            $set: {
                // deleting refreshToken from Db
                refreshToken: undefined
            }
        },
        {
            // by passing "new: true" we say that when returning , return the new updated value.
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(new ApiResponse(200, {}, "User logged out successfully"))
})

// 3️⃣ getMyProfile
const getMyProfile = asyncHandler(async (req, res) => {
  const userId = await req.user?._id;
  if (!userId) {
    throw new ApiError(401, "Unauthorized");
  }

  const user = await User.findById(userId).select("-password -refreshToken");
  if (!user) {
    throw new ApiError(404, "User not found");
  }

  return res.status(200).json(new ApiResponse(200, user, "Profile fetched"));
});

// 4️⃣ updateLocation
const updateLocation = asyncHandler(async (req, res) => {
  const { latitude, longitude } = req.body || {};

  const lat = parseFloat(latitude);
  const lon = parseFloat(longitude);
  const latValid = Number.isFinite(lat);
  const lonValid = Number.isFinite(lon);
  if (!latValid || !lonValid) {
    throw new ApiError(400, "Valid latitude and longitude are required");
  }

  const userId = await req.user?._id;
  if (!userId) {
    throw new ApiError(401, "Unauthorized");
  }

  const updated = await User.findByIdAndUpdate(
    userId,
    {
      $set: {
        location: {
          type: "Point",
          coordinates: [lon, lat],
        },
      },
    },
    { new: true }
  ).select("-password -refreshToken");

  return res
    .status(200)
    .json(new ApiResponse(200, updated, "Location updated successfully"));
});

// when its used and by whome it is used? : if while using access token in the fronted the user gets "401 unauthorized error"(because if the session expired) then the frontend will call this function to get new access token using refresh token.
const refreshAccessToken = asyncHandler(async (req, res) => {
    // Prefer cookie; allow body fallback for manual testing
    const incomingRefreshToken = req.cookies?.refreshToken || req.body?.refreshToken

    if (!incomingRefreshToken || typeof incomingRefreshToken !== 'string') {
        throw new ApiError(401, "Refresh token missing")
    }

    try {
        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)
        const user = await User.findById(decodedToken?._id)
        if (!user) {
            throw new ApiError(401, "Invalid refresh token (user not found)")
        }
        if (!user.refreshToken) {
            throw new ApiError(401, "No refresh session active")
        }
        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "Refresh token mismatch or reused")
        }

        // Issue new tokens
        const { accessToken, newRefreshToken } = await generateAccessAndRefreshTokens(user._id)

        // Persist new refresh token (rotation) - generateAccessAndRefreshTokens already saved it
        /*
        Previous (incorrect) cookie options:
        const cookieOptions = {
            httpOnly: true,
            secure: true,
            // "secure: process.env.NODE_ENV === 'production'" is given when deploying to production, its says that cookies can be sent over only on HTTPS requests.
            // secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        }
        */
        const cookieOptions = {
            httpOnly: true,
            // FIX: Align refresh cookie security with login cookie. If `secure`
            // is always true locally, Postman on HTTP won't send cookies and
            // token rotation appears brokenR
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        }

        return res
            .status(200)
            .cookie("accessToken", accessToken, cookieOptions)
            .cookie("refreshToken", newRefreshToken, cookieOptions)
            .json(new ApiResponse(200, { accessToken, newRefreshToken }, "Access token refreshed successfully"))
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token")
    }
})

// before running this function we will inject the "verifyJWT" middleware in the route section, so from their we will get the access of all the details of the user.
// this functionality will be used through settings page of user account, where user will provide old password and new password to change his password.
const changeCurrentPassword = asyncHandler(async (req, res) => {
    // accessing old and new password from req.body
    const { oldPassword, newPassword } = req.body

    // getting access to all the details of the user, here we are not excluding password and refreshToken, so we have access to them as well.
    const user = await User.findById(req.user?._id)

    // comapiring oldPassword with password saved in DB
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if (!isPasswordCorrect) {
        throw new ApiError(400, "Invalid old password")
    }

    // updating Db's password field with newPassword.
    user.password = newPassword

    await user.save({ validateBeforeSave: false })

    return res
        .status(200)
        .json(new ApiResponse(200, {}, "Password changed successfully"))

})

// this functionality will be used while logging in , if the user forgets there password the the frontend will create a "forgot password / reset password" button and call this controller through route.
const forgotPassword = asyncHandler(async (req, res) => {
    // accessing old and new password from req.body
    const { username, email, newPassword } = req.body

    // getting access to all the details of the user, here we are not excluding password and refreshToken, so we have access to them as well.
    const user = await User.findOne({
        $or: [{ username }, { email }]
    })

    if (!user) {
        throw new ApiError(404, "User does not exist")
    }

    if (typeof newPassword !== 'string') {
        throw new ApiError(400, "New password must be a string")
    }

    if (user.username !== username || user.email !== email) {
        throw new ApiError(400, "Provided username or email doesn't match, please retry.")
    }

    // updating Db's password field with newPassword.
    user.password = newPassword

    await user.save({ validateBeforeSave: false })


    return res
        .status(200)
        .json(new ApiResponse(200, {}, "Password updated successfully"))

})

// updating files data: here, we have to use 2 middlewares: 
// 1. multer: to accept the files 
// 2. verifyJWT: only those users can modify files who are logged in
// we will inject these 2 middlewares while routing, here just write the controller

const updateUserAvatar = asyncHandler(async (req, res) => {
    // when we will inject multer middleware form their we will get access to files, so here we can use "req.files" and "req.file"
    // we will get the file path and store it in "avatarLocalPath"
    const avatarLocalPath = req.file?.path

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is missing")
    }
    // upload the file on "Cloudinary", after uploading, "Cloudinary" gives its url 
    const avatar = await uploadOnCloudinary(avatarLocalPath)

    if (!avatar.url) {
        throw new ApiError(500, "Error while uploading on Cloudinary")
    }

    // getting users old avatar files url for deleting it after updating it with new one.
    const fetchingUserDetails = await User.findById(req.user?._id);
    const oldAvatarUrlToBeDeleted = fetchingUserDetails?.avatar;

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:
            {
                avatar: avatar.url
            }
        },
        {
            new: true
        }
    ).select("-password")

    // deleting old Avatar file
    if (oldAvatarUrlToBeDeleted) {
        await deleteFromCloudinary(oldAvatarUrlToBeDeleted);
    }


    return res
        .status(200)
        .json(
            new ApiResponse(200, user, "Avatar Image uploaded successfully")
        )
})

export { registerUser, loginUser, getMyProfile, updateLocation };







// import { asyncHandler } from "../utils/asyncHandler.js";
// import { ApiError } from "../utils/ApiErrors.js";
// import { ApiResponse } from "../utils/ApiResponse.js"
// import jwt from "jsonwebtoken"
// import { User } from "../models/user.model.js"
// import { uploadOnCloudinary, deleteFromCloudinary } from "../utils/cloudinary.js"


// writing "generateAccessAndRefreshTokens" function to generate them and use below.
// we dont use "asyncHandler" here because this function is not a controller function, its just a utility function to generate tokens that is going to be used in other controllers.
// const generateAccessAndRefreshTokens = async (userId) => {
//     try {
//         //finding the user in DB on the basis of "userId" and generating access and refresh token
//         const user = await User.findById(userId)
//         // generate tokens (synchronous jwt.sign in model)
//         const accessToken = user.generateAccessToken()
//         const refreshToken = user.generateRefreshToken()

//         //saving refresh token in Db, when we try to save it in DB using "user" and not mongoose "User" then mongoose user model kicks in(password field) so to stop that we add "{validateBeforeSave: false}" to stop validating anything else.
//         user.refreshToken = refreshToken
//         await user.save({ validateBeforeSave: false })

//         // after saving to DB return it.
//         return { accessToken, refreshToken }
//     } catch (error) {
//         throw new ApiError(500, "Something went wrong while generating access and refresh token")
//     }
// }

// const registerUser = asyncHandler(async (req, res) => {

//     // LOGIC :: THAT HAS TO BE EXECUTED.

//     // get user details from Frontend
//     // validation: should not be empty
//     // check if user already exists: via. username, email
//     // check for coverimages, check for avatar because avatar is mandatory to give here.
//     // upload them on cloudinary
//     // create user object - create entry in DB (because mongoDb is a noSql type db so there mostly data is passed in form of objects)
//     // remove password and refresh token field from response (because the returned response will have passwords and refresh tokens as well in it, it actually returns all the data that we pass to it, so we remove the above mentioned fields from it and then show it to the user.)
//     // check for user creation (final check that user was created successfully or not, wheather the response had any value or was null?)
//     // return response

//     // Debug: Check what we're receiving
//     console.log("req.body:", req.body);
//     console.log("req.files:", req.files);
//     console.log("Content-Type:", req.headers['content-type']);


//     // { email, fullName, username, password } these are the data fields that we will recieve from user from the "body" thats why we used "req.body" 
//     const { email, fullName, username, password } = req.body || {};
//     console.log("email: ", email);
//     if (email === "") {
//         throw new ApiError(400, "Email field is Mandatory")
//     }
//     console.log("username: ", username);
//     if (username === "") {
//         throw new ApiError(400, "Username field is Mandatory")
//     }
//     console.log("fullName: ", fullName);
//     if (fullName === "") {
//         throw new ApiError(400, "Full Name field is Mandatory")
//     }
//     console.log("password: ", password);
//     if (password === "") {
//         throw new ApiError(400, "Password field is Mandatory")
//     }

//     const existedUser = await User.findOne({
//         $or: [{ username }, { email }]
//     })
//     if (existedUser) {
//         throw new ApiError(409, "User with this email or username already exists")
//     }

//     // local path of avatar stored in our local storage (server). Here putting '?' because maybe for any reason we may not have access to files and avatar as there are multiple files being uploaded and [0]index of avatar returns an object, so it is possible that for some reason it may not return that object.
//     // const avatarLocalPath = req.files?.avatar[0]?.path;
//     // const coverImageLocalPath = req.files?.coverImage[0]?.path;
//     // both the above cases will create a problem that if we didnt uploaded any one of the required then also the will try to access the data on the [0] index of avatar and coverImage which then will be undefined and then it will throw this error "TypeError: Cannot read properties of undefined (reading '0')" and not our custom error which says that "this file is required". So, better way is to check them using a 'if' condition which is done below.

//     //if we didnt uploaded coverImg and did'nt even check its local path then it can throw an error, so to resolve it we ::

//     let coverImageLocalPath;

//     // here we check 
//     // 1. are we getting files from body or not
//     // 2. the returning array has coverImage or not
//     // 3. the returned coverImage has any properties or not
//     // if all of these are true then its proved that we recieved the "coverImageLocalPath" and we can extract its path from their.
//     // * generally we get all the data in "req.body" but since we are using "multer" middleware to handle files so all the files data will be in "req.files" and text data will be in "req.body"
//     // * we have injected the "multer" middleware in the route section of "user.routes.js" file.
//     // * the data flow: users/register (route) -> multer middleware (to handle files) -> registerUser function (controller)

//     if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
//         coverImageLocalPath = req.files.coverImage[0].path
//     }

//     let avatarLocalPath;
//     if (req.files && Array.isArray(req.files.avatar) && req.files.avatar.length > 0) {
//         avatarLocalPath = req.files.avatar[0].path
//     }
//     if (!avatarLocalPath) {
//         throw new ApiError(400, "Avatar file is required")
//     }

//     // uploaded avater and coverImage to cloudinary
//     const avatar = await uploadOnCloudinary(avatarLocalPath)
//     const coverImage = await uploadOnCloudinary(coverImageLocalPath)

//     // First check if avatar is successfully uploaded or not? if avatar is not successfully uploaded then give a error otherwise it will create an error in DB because avatar is mandatory to upload.
//     if (!avatar) {
//         throw new ApiError(400, "Avatar file is required")
//     }


//     const user = await User.create({
//         fullName,
//         avatar: avatar.url,
//         // creating a check for "coverImage" that if it has been successfully uploaded then upload its url , if not then let it remain empty as its not mandatory to upload "coverImage".
//         coverImage: coverImage?.url || "",
//         email,
//         password,
//         username: username.toLowerCase()
//     })

//     // checking if "user" is successfully created or not, if not then throw an error , if created then remove the password and refresh token from the response and then return the response to user.
//     const createdUser = await User.findById(user._id).select(
//         //by default everythink is selected, so the (-ve) represents what not to select
//         "-password -refreshToken"
//     )


//     if (!createdUser) {
//         throw new ApiError(500, "Something went wrong while registering the user")
//     }

//     // returning the response::
//     return res.status(201).json(
//         // creating an object of "ApiResponse" utility that we made and passing the parameters that we need as response ::
//         // new ApiResponse -> object of ApiResponse class (statusCode, Data, "Message")
//         new ApiResponse(200, createdUser, "User registered Successfuly")
//     )

// })

// const loginUser = asyncHandler(async (req, res) => {

//     // LOGIC :: THAT HAS TO BE EXECUTED.

//     // 1. get data from "req.body"
//     // 2. on base of what we will find the user : username or email -> write a code for that
//     // 3. find the user
//     // 4. password check
//     // 5. if correct password is given then generate "Access Token" & "Refresh Token"
//     // 6. send  "Access Token" & "Refresh Token" to user through "Cookies"
//     // 7. give response (loged in)


//     //get data from frontend
//     const { email, username, password } = req.body

//     // Allow login with EITHER username OR email (at least one required)
//     if ((!username && !email) || !password) {
//         throw new ApiError(400, "username or email and password are required")
//     }

//     //if we successfully got "username" or "email" then check if they already exist in DB
//     const user = await User.findOne({
//         $or: [{ username }, { email }]
//     })

//     if (!user) {
//         throw new ApiError(404, "User does not exist")
//     }

//     // if we found the user then he will give password , so check if provided password is correct or not?
//     //we have already made a method "isPasswordCorrect" using "userSchema.methods" in user.models.js so we will use that
//     // the below provided password is comming from the logging in user form req.body
//     const isPasswordValid = await user.isPasswordCorrect(password) // this will return true / false

//     if (!isPasswordValid) {
//         throw new ApiError(401, "Invalid User Credentials")
//     }

//     // taking "accessToken, refreshToken" from the function "generateAccessAndRefreshTokens" as it returns that 
//     const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id)

//     // once again getting all the data of the user and saving it in "loggedInUser" accept these "-password -refreshToken"
//     const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

//     // sending Cookies: to do so we need to enable some options
//     // byDefault cookies can be modified in frontend, these 2 options make the cookies "readable and modifiable" only by the server and not in the frontend
//     /*
//     Previous (incorrect) cookie options:
//     const options = {
//         httpOnly: true,
//         secure: true
//     }
//     */
//     const options = {
//         httpOnly: true,
//         // FIX: Previously used `secure: true` always, so cookies were NOT
//         // sent over local HTTP (Postman). That made `verifyJWT` see no token
//         // and throw. Make `secure` env-aware so dev/testing works over HTTP.
//         // In local/dev over HTTP, secure cookies won't be sent.
//         // Use secure only in production (HTTPS).
//         secure: process.env.NODE_ENV === 'production',
//         sameSite: 'lax'
//     }

//     // once options are set return response with cookies with options enabled in it.
//     return res.status(200)
//         .cookie("accessToken", accessToken, options)
//         .cookie("refreshToken", refreshToken, options)
//         .json(
//             new ApiResponse(
//                 200,
//                 {
//                     user: loggedInUser, accessToken, refreshToken
//                 },
//                 "User logged In Successfully"
//             )
//         )
// })


// const logoutUser = asyncHandler(async (req, res) => {
//     // we cant directly access the User here, because in cases above we were taking "{ email, fullName, username, password } = req.body" all these info from user on basis of what we were finding user in DB, but in "logoutUser" we dont ask user to enter all these details, so currently we dont have access to the user, so here we use Middleware.


//     // why can i access "req.user" here because before comming to this functin we are running a "verifyJWT" middleware which is saving all the details of the user using "User" from mongoose to "req.user"

//     User.findByIdAndUpdate(
//         await req.user._id,
//         {
//             $set: {
//                 // deleting refreshToken from Db
//                 refreshToken: undefined
//             }
//         },
//         {
//             // by passing "new: true" we say that when returning , return the new updated value.
//             new: true
//         }
//     )

//     const options = {
//         httpOnly: true,
//         secure: true
//     }

//     return res
//         .status(200)
//         .clearCookie("accessToken", options)
//         .clearCookie("refreshToken", options)
//         .json(new ApiResponse(200, {}, "User logged out successfully"))
// })

// // when its used and by whome it is used? : if while using access token in the fronted the user gets "401 unauthorized error"(because if the session expired) then the frontend will call this function to get new access token using refresh token.
// const refreshAccessToken = asyncHandler(async (req, res) => {
//     // Prefer cookie; allow body fallback for manual testing
//     const incomingRefreshToken = req.cookies?.refreshToken || req.body?.refreshToken

//     if (!incomingRefreshToken || typeof incomingRefreshToken !== 'string') {
//         throw new ApiError(401, "Refresh token missing")
//     }

//     try {
//         const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)
//         const user = await User.findById(decodedToken?._id)
//         if (!user) {
//             throw new ApiError(401, "Invalid refresh token (user not found)")
//         }
//         if (!user.refreshToken) {
//             throw new ApiError(401, "No refresh session active")
//         }
//         if (incomingRefreshToken !== user?.refreshToken) {
//             throw new ApiError(401, "Refresh token mismatch or reused")
//         }

//         // Issue new tokens
//         const { accessToken, newRefreshToken } = await generateAccessAndRefreshTokens(user._id)

//         // Persist new refresh token (rotation) - generateAccessAndRefreshTokens already saved it
//         /*
//         Previous (incorrect) cookie options:
//         const cookieOptions = {
//             httpOnly: true,
//             secure: true,
//             // "secure: process.env.NODE_ENV === 'production'" is given when deploying to production, its says that cookies can be sent over only on HTTPS requests.
//             // secure: process.env.NODE_ENV === 'production',
//             sameSite: 'lax'
//         }
//         */
//         const cookieOptions = {
//             httpOnly: true,
//             // FIX: Align refresh cookie security with login cookie. If `secure`
//             // is always true locally, Postman on HTTP won't send cookies and
//             // token rotation appears brokenR
//             secure: process.env.NODE_ENV === 'production',
//             sameSite: 'lax'
//         }

//         return res
//             .status(200)
//             .cookie("accessToken", accessToken, cookieOptions)
//             .cookie("refreshToken", newRefreshToken, cookieOptions)
//             .json(new ApiResponse(200, { accessToken, newRefreshToken }, "Access token refreshed successfully"))
//     } catch (error) {
//         throw new ApiError(401, error?.message || "Invalid refresh token")
//     }
// })


// // before running this function we will inject the "verifyJWT" middleware in the route section, so from their we will get the access of all the details of the user.
// // this functionality will be used through settings page of user account, where user will provide old password and new password to change his password.
// const changeCurrentPassword = asyncHandler(async (req, res) => {
//     // accessing old and new password from req.body
//     const { oldPassword, newPassword } = req.body

//     // getting access to all the details of the user, here we are not excluding password and refreshToken, so we have access to them as well.
//     const user = await User.findById(req.user?._id)

//     // comapiring oldPassword with password saved in DB
//     const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

//     if (!isPasswordCorrect) {
//         throw new ApiError(400, "Invalid old password")
//     }

//     // updating Db's password field with newPassword.
//     user.password = newPassword

//     await user.save({ validateBeforeSave: false })

//     return res
//         .status(200)
//         .json(new ApiResponse(200, {}, "Password changed successfully"))

// })

// // this functionality will be used while logging in , if the user forgets there password the the frontend will create a "forgot password / reset password" button and call this controller through route.
// const forgotPassword = asyncHandler(async (req, res) => {
//     // accessing old and new password from req.body
//     const { username, email, newPassword } = req.body

//     // getting access to all the details of the user, here we are not excluding password and refreshToken, so we have access to them as well.
//     const user = await User.findOne({
//         $or: [{ username }, { email }]
//     })

//     if (!user) {
//         throw new ApiError(404, "User does not exist")
//     }

//     if (typeof newPassword !== 'string') {
//         throw new ApiError(400, "New password must be a string")
//     }

//     if (user.username !== username || user.email !== email) {
//         throw new ApiError(400, "Provided username or email doesn't match, please retry.")
//     }

//     // updating Db's password field with newPassword.
//     user.password = newPassword

//     await user.save({ validateBeforeSave: false })


//     return res
//         .status(200)
//         .json(new ApiResponse(200, {}, "Password updated successfully"))

// })

// fetching (get) current user
// const getCurrentUser = asyncHandler(async (req, res) => {
//     return res
//         .status(200)
//         .json(new ApiResponse(200, req.user, "Current user fetched successfully"))
// })

// // updating text data 
// const updateAccountDetails = asyncHandler(async (req, res) => {
//     // here the developers allow what data must be given access to the user to modify. Here i am allowing "fullName, email"
//     // taking this data from frontend
//     const { fullName, email } = req.body
//     if (!fullName || !email) {
//         throw new ApiError(400, "All fields are required")
//     }

//     const user = await User.findByIdAndUpdate(
//         req.user?._id,
//         {
//             $set:
//             {   // here left side "fullName:" is whats their in Db and right side "fullName" is what we will provide from frontend and same for email.
//                 fullName: fullName,
//                 email: email
//             }
//         },
//         { new: true }
//     ).select("-password")

//     return res
//         .status(200)
//         .json(new ApiResponse(200, user, "Account details updated sucessfully"))
// })

// // updating files data: here, we have to use 2 middlewares: 
// // 1. multer: to accept the files 
// // 2. verifyJWT: only those users can modify files who are logged in
// // we will inject these 2 middlewares while routing, here just write the controller

// const updateUserAvatar = asyncHandler(async (req, res) => {
//     // when we will inject multer middleware form their we will get access to files, so here we can use "req.files" and "req.file"
//     // we will get the file path and store it in "avatarLocalPath"
//     const avatarLocalPath = req.file?.path

//     if (!avatarLocalPath) {
//         throw new ApiError(400, "Avatar file is missing")
//     }
//     // upload the file on "Cloudinary", after uploading, "Cloudinary" gives its url 
//     const avatar = await uploadOnCloudinary(avatarLocalPath)

//     if (!avatar.url) {
//         throw new ApiError(500, "Error while uploading on Cloudinary")
//     }

//     // getting users old avatar files url for deleting it after updating it with new one.
//     const fetchingUserDetails = await User.findById(req.user?._id);
//     const oldAvatarUrlToBeDeleted = fetchingUserDetails?.avatar;

//     const user = await User.findByIdAndUpdate(
//         req.user?._id,
//         {
//             $set:
//             {
//                 avatar: avatar.url
//             }
//         },
//         {
//             new: true
//         }
//     ).select("-password")

//     // deleting old Avatar file
//     if (oldAvatarUrlToBeDeleted) {
//         await deleteFromCloudinary(oldAvatarUrlToBeDeleted);
//     }


//     return res
//         .status(200)
//         .json(
//             new ApiResponse(200, user, "Avatar Image uploaded successfully")
//         )
// })

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    forgotPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar
} 