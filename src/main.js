// require('dotenv').config({path: './.env'}); // Load's environment variables from .env file and makes them available everywhere required in the application. :: "As early as possible import the dotenv file and configure it"
//import syntax for dotenv is an experimental feature, so to use that we have to configure it in package.json as ""dev": "nodemon -r dotenv/config --experimental-json-modules src/main.js""

import dotenv from "dotenv";
import http from "http";
import connectDb from "./db/index.js";
import { app } from "./app.js";
import { initSocket } from "./sockets/index.js";

dotenv.config({
    path: './.env'
});

connectDb()
    //application is starting to listen using the Database
    .then(() => {
        const server = http.createServer(app);
        initSocket(server);
        const port = process.env.PORT || 8000;
        server.listen(port, () => {
            console.log(`Server is running on port ${port}`);
        });
    })
    .catch((error) => {
        console.error(`Database connection failed: ${error}`);
    });