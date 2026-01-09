import mongoose, { Schema } from "mongoose";

const postSchema = new Schema(
    {
        groupId: {
            type: Schema.Types.ObjectId,
            ref: "Group",
            required: true
        },

        userId: {
            type: Schema.Types.ObjectId,
            ref: "User",
            required: true
        },

        caption: {
            type: String,
        },

        mediaUrl: {
            type: String,
        },

        mediaType: {
            type: String,
            enum: ["image", "video"],
            required: true
        },
    },
    {
        timestamps: true
    }
);

export default mongoose.model("Post", postSchema);
