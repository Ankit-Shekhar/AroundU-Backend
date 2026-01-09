import mongoose, { Schema } from "mongoose";

const messageSchema = new Schema(
    {
        groupId: {
            type: Schema.Types.ObjectId,
            ref: "Group",
            required: true
        },

        senderId: {
            type: Schema.Types.ObjectId,
            ref: "User",
            required: true
        },

        text: {
            type: String,
        },

        mediaUrl: {
            type: String,
        },

        mediaType: {
            type: String,
            enum: ["image", "video"]
        },
    },
    {
        timestamps: true
    }
);

export default mongoose.model("Message", messageSchema);
