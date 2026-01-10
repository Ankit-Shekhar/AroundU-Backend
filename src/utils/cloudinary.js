//uploading files to cloudinary server through "localFilePath" provided to us by Multer

import { v2 as cloudinary } from "cloudinary"
import fs from "fs"

// this config gives permission to user to upload their files by checking their name , key and secret
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});


const uploadOnCloudinary = async (localFilePath) => {
    try {
        if (!localFilePath) return null

        //upload the file on cloudinary
        const response = await cloudinary.uploader.upload(localFilePath, {

            // auto detect which type of file is being uploaded
            resource_type: "auto"
        })
        //file has been added successfully

        console.log("File is uploaded on Cloudinary", response.url);
        //once the file is successfully uploaded it will be unlinked as well
        fs.unlinkSync(localFilePath)
        return response;


    } catch (error) {
        //remove the locally saved temporary file as the upload operation got failed
        fs.unlinkSync(localFilePath)
        return null;
    }
}
// Utility to delete a file from Cloudinary by its URL
const deleteFromCloudinary = async (oldfileLocalPath_url) => {
    try {
        if (!oldfileLocalPath_url) return null;

        // Extract the public ID from the URL
        // Example: https://res.cloudinary.com/<cloud_name>/image/upload/v1234567890/folder/filename.jpg
        // We need: folder/filename (without extension)

        const urlParts = fileUrl.split("/");
        // Remove version part (e.g., v1234567890)
        const versionIndex = urlParts.findIndex(part => /^v\d+$/.test(part));
        const publicIdParts = urlParts.slice(versionIndex + 1);
        let publicId = publicIdParts.join("/");


        // Remove file extension
        publicId = publicId.replace(/\.[^/.]+$/, "");
        // Call Cloudinary destroy
        const result = await cloudinary.uploader.destroy(publicId, { resource_type: "auto" });
        return result;
    } catch (error) {
        console.error("Errorin deleting file from Cloudinary:", error);
        return null;
    }
}

export { uploadOnCloudinary, deleteFromCloudinary }