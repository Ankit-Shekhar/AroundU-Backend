import GroupMember from "../models/groupMember.model.js";
import Group from "../models/group.model.js";
import { createMessage } from "../controllers/message.controllers.js";

function roomName(groupId) {
	return `group:${groupId}`;
}

export function registerGroupHandlers(io, socket) {
	socket.on("group:join", async ({ groupId }, cb) => {
		try {
			if (!groupId) throw new Error("groupId required");

			const group = await Group.findById(groupId).select("_id");
			if (!group) throw new Error("Group not found");

			const isMember = await GroupMember.exists({ userId: socket.user._id, groupId });
			if (!isMember) throw new Error("User is not a member of this group");

			socket.join(roomName(groupId));
			cb?.({ ok: true });
		} catch (err) {
			cb?.({ ok: false, error: err.message });
		}
	});

	socket.on("group:leave", ({ groupId }, cb) => {
		try {
			if (!groupId) throw new Error("groupId required");
			socket.leave(roomName(groupId));
			cb?.({ ok: true });
		} catch (err) {
			cb?.({ ok: false, error: err.message });
		}
	});

	socket.on("message:send", async (payload, cb) => {
		try {
			const { groupId, text, mediaUrl, mediaType } = payload || {};
			if (!groupId) throw new Error("groupId required");

			const isMember = await GroupMember.exists({ userId: socket.user._id, groupId });
			if (!isMember) throw new Error("User is not a member of this group");

			const message = await createMessage({
				groupId,
				senderId: socket.user._id,
				text,
				mediaUrl,
				mediaType,
			});

			io.to(roomName(groupId)).emit("message:new", {
				_id: message._id,
				groupId: message.groupId,
				senderId: message.senderId,
				text: message.text,
				mediaUrl: message.mediaUrl,
				mediaType: message.mediaType,
				createdAt: message.createdAt,
			});
			cb?.({ ok: true, messageId: message._id });
		} catch (err) {
			cb?.({ ok: false, error: err.message });
		}
	});
}

