import { Server } from "socket.io";
import jwt from "jsonwebtoken";
import { registerGroupHandlers } from "./group.socket.js";
import { registerPostHandlers } from "./post.socket.js";

let ioInstance = null;

function authMiddleware(socket, next) {
	try {
		const token =
			socket.handshake.auth?.token ||
			socket.handshake.headers?.authorization?.replace("Bearer ", "") ||
			socket.handshake.query?.token;

		if (!token) {
			return next(new Error("Unauthorized: token missing"));
		}

		const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
		socket.user = { _id: decoded?._id, username: decoded?.username, email: decoded?.email };
		next();
	} catch (err) {
		next(new Error("Unauthorized: invalid token"));
	}
}

export function initSocket(server) {
	const io = new Server(server, {
		cors: {
			origin: process.env.CORS_ORIGIN || "http://localhost:3000",
			credentials: true,
		},
	});

	io.use(authMiddleware);

	io.on("connection", (socket) => {
		registerGroupHandlers(io, socket);
		registerPostHandlers(io, socket);

		socket.on("disconnect", () => {
			// No-op: can be extended for presence tracking
		});
	});

	ioInstance = io;
	return io;
}

export function getIO() {
	if (!ioInstance) throw new Error("Socket.io not initialized");
	return ioInstance;
}

