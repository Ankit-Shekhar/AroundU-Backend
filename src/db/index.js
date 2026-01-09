import mongoose from "mongoose";
import { DB_NAME } from "../constants.js";

const connectDb = async () => {
    try {

        //mongoose actually returns an object which we can store in a variable, here its "connectionInstance"
        const connectionInstance = await mongoose.connect(`${process.env.MONGODB_URL}/${DB_NAME}`);

        console.log(`Database connected successfully! DB HOST: ${connectionInstance.connection.host}`);
    } catch (error) {
        console.log(`Database connection Failed: ${error}`);

        //whatever process is running now this process below is the reference of it through which we can exit that process
        process.exit(1); // Exit the process with failure
    }
}

export default connectDb
