import mongoose, { Schema } from "mongoose";

const meetingSchema = new Schema(
    {
        groupId: {
            type: Schema.Types.ObjectId,
            ref: "Group",
            required: true
        },

        locationName: {
            type: String,
            required: true
        },

        address: {
            type: String,
            required: true
        },

        location: {
            type: {
                type: String,
                enum: ["Point"],
                required: true
            },
            coordinates: {
                type: [Number],
                required: true
            }
        },

        meetingTime: {
            type: Date,
            required: true
        },
    },
    {
        timestamps: true
    }
);

meetingSchema.index({ location: "2dsphere" });

export default mongoose.model("Meeting", meetingSchema);
