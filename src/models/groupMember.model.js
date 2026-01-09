import mongoose, { Schema } from "mongoose";

const groupMemberSchema = new Schema(
    {
        userId: {
            type: Schema.Types.ObjectId,
            ref: "User",
            required: true
        },

        groupId: {
            type: Schema.Types.ObjectId,
            ref: "Group",
            required: true
        },
    },
    {
        timestamps: true
    }
);

groupMemberSchema.index({ userId: 1, groupId: 1 }, { unique: true });

export default mongoose.model("GroupMember", groupMemberSchema);
