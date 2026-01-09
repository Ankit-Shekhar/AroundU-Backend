import mongoose, { Schema } from "mongoose";

const groupSchema = new Schema(
    {
        name: {
            type: String,
            required: true
        },

        category: {
            type: String,
            enum: ["sports", "fitness", "social"],
            required: true
        },

        description: String,

        createdBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User"
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

        radius: {
            type: Number,
            default: 1000
        }, // meters

        isDefault: {
            type: Boolean,
            default: false
        },
    },
    {
        timestamps: true
    }

);

groupSchema.index({ location: "2dsphere" });

export default mongoose.model("Group", groupSchema);
