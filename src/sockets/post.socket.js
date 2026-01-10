import Post from "../models/post.model.js";
import Like from "../models/like.model.js";
import { Comment } from "../models/comment.model.js";
import GroupMember from "../models/groupMember.model.js";

function roomName(groupId) {
	return `group:${groupId}`;
}

export function registerPostHandlers(io, socket) {
	socket.on("post:new", async (payload, cb) => {
		try {
			const { groupId, postId } = payload || {};
			if (!groupId || !postId) throw new Error("groupId and postId required");

			const isMember = await GroupMember.exists({ userId: socket.user._id, groupId });
			if (!isMember) throw new Error("User is not a member of this group");

			const post = await Post.findById(postId).select("_id groupId userId caption mediaUrl mediaType createdAt");
			if (!post) throw new Error("Post not found");

			io.to(roomName(groupId)).emit("post:broadcast", post);
			cb?.({ ok: true });
		} catch (err) {
			cb?.({ ok: false, error: err.message });
		}
	});

	socket.on("post:like", async ({ groupId, postId }, cb) => {
		try {
			if (!groupId || !postId) throw new Error("groupId and postId required");
			const isMember = await GroupMember.exists({ userId: socket.user._id, groupId });
			if (!isMember) throw new Error("User is not a member of this group");
			const likeCount = await Like.countDocuments({ postId });
			io.to(roomName(groupId)).emit("post:like:update", { postId, likeCount });
			cb?.({ ok: true });
		} catch (err) {
			cb?.({ ok: false, error: err.message });
		}
	});

	socket.on("post:comment", async ({ groupId, postId }, cb) => {
		try {
			if (!groupId || !postId) throw new Error("groupId and postId required");
			const isMember = await GroupMember.exists({ userId: socket.user._id, groupId });
			if (!isMember) throw new Error("User is not a member of this group");
			const commentCount = await Comment.countDocuments({ postId });
			io.to(roomName(groupId)).emit("post:comment:update", { postId, commentCount });
			cb?.({ ok: true });
		} catch (err) {
			cb?.({ ok: false, error: err.message });
		}
	});
}

