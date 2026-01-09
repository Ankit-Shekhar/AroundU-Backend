import mongoose, { Schema } from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const userSchema = new Schema(
    {
        username: {
            type: String,
            required: true,
            unique: true,
            trim: true,
            lowercase: true,
            //index: true is done to make any object searchable in the database
            //This is done to make the username searchable in the database
            index: true
        },

        fullName: {
            type: String,
            required: true,
            trim: true,
            index: true
        },

        email: {
            type: String,
            required: true,
            unique: true,
            trim: true,
            lowercase: true,
        },

        avatar: {
            type: String, //cloudinary url
            required: true
        },

        coverImage: {
            type: String, //cloudinary url
        },

        password: {
            type: String,
            required: [true, "Password is required"]
        },

        interests: [
            { type: String }
        ], // sports, fitness, social

        location: {
            type: {
                type: String,
                enum: ["Point"],
                required: true
            },
            coordinates: {
                type: [Number],
                required: true
            } // [lng, lat]
        },

        refreshToken: {
            type: String
        }
    },
    {
        timestamps: true
    }
);

userSchema.index({ location: "2dsphere" });

//mongoose hooks(Middlewares) used: "pre" is used to perform any tasks just before saving the document
//arrow function is not used here because we need to use "this" keyword to access the document being saved and arrow function does not have its own "this" context


//its a middleware so "next" flag is used, After every conditionnext flag is passed to the next Middleware or routeHandler.
userSchema.pre("save", async function (next) {
    // here we have to use a if condition else it will run everytime , irrespective of password was changed or not, so we must check wheather the password was changed or not. Here password is passed as a string.
    if (!this.isModified("password")) return next();
    this.password = await bcrypt.hash(this.password, 10)
    next();
})

//before exporting check the password is correct or not: compares the entered password with its hashed password

userSchema.methods.isPasswordCorrect = async function (password) {
    // here "(password, this.password)" password is the String password entered by the user and this.password is the encrypted password done by bcrypt.
    return await bcrypt.compare(password, this.password)
    //returns true / false
}

userSchema.methods.generateAccessToken = function () {
    // ".sign" method is used to generate tokens
    return jwt.sign(
        {
            //this is the data part: "generateAccessToken" funtion will access it from the database
            _id: this._id,
            email: this.email,
            username: this.username,
            fullName: this.fullName
        },
        process.env.ACCESS_TOKEN_SECRET, // its a private key: its a part of JWT.sign syntax
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY  // expiry time of the token
        }
    )
}
userSchema.methods.generateRefreshToken = function () {
    return jwt.sign(
        {
            _id: this._id,
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRY
        }
    )
}

export const User = mongoose.model("User", userSchema);
