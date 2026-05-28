import datetime
import logging
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
import config

logger = logging.getLogger("ghost.mongo")


class MongoLogger:
    """Persistent MongoDB logger for all honeypot interactions."""

    def __init__(self):
        self.client = None
        self.db = None
        self.connected = False
        self._connect()

    def _connect(self):
        import time
        max_retries = 5
        for attempt in range(max_retries):
            try:
                self.client = MongoClient(
                    config.MONGO_URI,
                    serverSelectionTimeoutMS=5000,
                    connectTimeoutMS=5000,
                )
                self.client.admin.command("ping")
                self.db = self.client[config.MONGO_DB]
                self.connected = True
                logger.info("Connected to MongoDB at %s", config.MONGO_URI)

                self.db[config.MONGO_COLLECTION_SESSIONS].create_index("session_id", unique=True)
                self.db[config.MONGO_COLLECTION_SESSIONS].create_index("start_time")
                self.db[config.MONGO_COLLECTION_COMMANDS].create_index("session_id")
                self.db[config.MONGO_COLLECTION_COMMANDS].create_index("timestamp")
                self.db[config.MONGO_COLLECTION_EXPLOITS].create_index("session_id")
                self.db[config.MONGO_COLLECTION_CREDENTIALS].create_index("session_id")
                self.db[config.MONGO_COLLECTION_ANALYSIS].create_index("session_id")
                self.db[config.MONGO_COLLECTION_VFS].create_index([("session_id", 1), ("path", 1)], unique=True)
                return

            except (ConnectionFailure, ServerSelectionTimeoutError, Exception) as e:
                logger.warning("MongoDB connection failed (attempt %d/%d): %s", attempt + 1, max_retries, e)
                if attempt < max_retries - 1:
                    time.sleep(2)
                else:
                    logger.warning("MongoDB not available after %d attempts. Using in-memory fallback.", max_retries)
                    self.connected = False
                    self._init_fallback()

    def _init_fallback(self):
        """In-memory fallback when MongoDB is not available."""
        self._memory = {
            "sessions": [],
            "commands": [],
            "exploits": [],
            "credentials": [],
            "analysis": [],
            "vfs": [],
        }


    def create_session(self, session_id, attacker_ip, attacker_port, username_tried, password_tried):
        doc = {
            "session_id": session_id,
            "attacker_ip": attacker_ip,
            "attacker_port": attacker_port,
            "username_tried": username_tried,
            "password_tried": password_tried,
            "start_time": datetime.datetime.utcnow(),
            "end_time": None,
            "active": True,
            "total_commands": 0,
            "risk_score": 0,
            "tags": [],
            "sentiment_scores": [],
            "sophistication_level": "unknown",
            "frustration_level": 0.0,
        }
        if self.connected:
            self.db[config.MONGO_COLLECTION_SESSIONS].insert_one(doc)
        else:
            self._memory["sessions"].append(doc)
        return doc

    def end_session(self, session_id):
        update = {
            "$set": {
                "end_time": datetime.datetime.utcnow(),
                "active": False,
            }
        }
        if self.connected:
            self.db[config.MONGO_COLLECTION_SESSIONS].update_one(
                {"session_id": session_id}, update
            )
        else:
            for s in self._memory["sessions"]:
                if s["session_id"] == session_id:
                    s["end_time"] = datetime.datetime.utcnow()
                    s["active"] = False

    def update_session_risk(self, session_id, risk_delta, tag=None):
        update = {"$inc": {"risk_score": risk_delta, "total_commands": 0}}
        if tag:
            update["$addToSet"] = {"tags": tag}
        if self.connected:
            self.db[config.MONGO_COLLECTION_SESSIONS].update_one(
                {"session_id": session_id}, update
            )

    def increment_commands(self, session_id):
        if self.connected:
            self.db[config.MONGO_COLLECTION_SESSIONS].update_one(
                {"session_id": session_id},
                {"$inc": {"total_commands": 1}},
            )


    def log_command(self, session_id, command, output, risk_level="low", command_type="normal"):
        doc = {
            "session_id": session_id,
            "timestamp": datetime.datetime.utcnow(),
            "command": command,
            "output": output[:5000] if output else "",
            "risk_level": risk_level,
            "command_type": command_type,
        }
        if self.connected:
            self.db[config.MONGO_COLLECTION_COMMANDS].insert_one(doc)
        else:
            self._memory["commands"].append(doc)
        self.increment_commands(session_id)

        risk_map = {"low": 0, "medium": 5, "high": 15, "critical": 30}
        if risk_level in risk_map and risk_map[risk_level] > 0:
            self.update_session_risk(session_id, risk_map[risk_level], f"{command_type}_{risk_level}")


    def log_exploit_attempt(self, session_id, exploit_name, command, details=""):
        doc = {
            "session_id": session_id,
            "timestamp": datetime.datetime.utcnow(),
            "exploit_name": exploit_name,
            "command": command,
            "details": details,
        }
        if self.connected:
            self.db[config.MONGO_COLLECTION_EXPLOITS].insert_one(doc)
        else:
            self._memory["exploits"].append(doc)
        self.update_session_risk(session_id, 30, "exploit_attempt")


    def log_credential(self, session_id, cred_type, username, password):
        doc = {
            "session_id": session_id,
            "timestamp": datetime.datetime.utcnow(),
            "type": cred_type,
            "username": username,
            "password": password,
        }
        if self.connected:
            self.db[config.MONGO_COLLECTION_CREDENTIALS].insert_one(doc)
        else:
            self._memory["credentials"].append(doc)
        self.update_session_risk(session_id, 15, "credential_harvest")


    def log_analysis(self, session_id, analysis_data):
        doc = {
            "session_id": session_id,
            "timestamp": datetime.datetime.utcnow(),
            **analysis_data,
        }
        if self.connected:
            self.db[config.MONGO_COLLECTION_ANALYSIS].insert_one(doc)
            self.db[config.MONGO_COLLECTION_SESSIONS].update_one(
                {"session_id": session_id},
                {
                    "$set": {
                        "sophistication_level": analysis_data.get("sophistication_level", "unknown"),
                        "frustration_level": analysis_data.get("frustration_score", 0.0),
                    },
                    "$push": {
                        "sentiment_scores": analysis_data.get("sentiment_score", 0.0),
                    },
                },
            )
        else:
            self._memory["analysis"].append(doc)


    def get_session(self, session_id):
        if self.connected:
            return self.db[config.MONGO_COLLECTION_SESSIONS].find_one({"session_id": session_id}, {"_id": 0})
        return next((s for s in self._memory.get("sessions", []) if s["session_id"] == session_id), None)

    def get_all_sessions(self):
        if self.connected:
            return list(self.db[config.MONGO_COLLECTION_SESSIONS].find({}, {"_id": 0}).sort("start_time", -1))
        return self._memory.get("sessions", [])

    def get_active_sessions(self):
        if self.connected:
            return list(self.db[config.MONGO_COLLECTION_SESSIONS].find({"active": True}, {"_id": 0}))
        return [s for s in self._memory.get("sessions", []) if s.get("active")]

    def get_session_commands(self, session_id):
        if self.connected:
            return list(self.db[config.MONGO_COLLECTION_COMMANDS].find(
                {"session_id": session_id}, {"_id": 0}
            ).sort("timestamp", 1))
        return [c for c in self._memory.get("commands", []) if c["session_id"] == session_id]

    def get_session_exploits(self, session_id):
        if self.connected:
            return list(self.db[config.MONGO_COLLECTION_EXPLOITS].find(
                {"session_id": session_id}, {"_id": 0}
            ))
        return [e for e in self._memory.get("exploits", []) if e["session_id"] == session_id]

    def get_session_credentials(self, session_id):
        if self.connected:
            return list(self.db[config.MONGO_COLLECTION_CREDENTIALS].find(
                {"session_id": session_id}, {"_id": 0}
            ))
        return [c for c in self._memory.get("credentials", []) if c["session_id"] == session_id]

    def vfs_add_file(self, session_id, path, content=""):
        if self.connected:
            self.db[config.MONGO_COLLECTION_VFS].update_one(
                {"session_id": session_id, "path": path},
                {"$set": {"content": content, "timestamp": datetime.datetime.utcnow()}},
                upsert=True
            )
        else:
            found = False
            for f in self._memory["vfs"]:
                if f["session_id"] == session_id and f["path"] == path:
                    f["content"] = content
                    found = True
                    break
            if not found:
                self._memory["vfs"].append({"session_id": session_id, "path": path, "content": content})

    def vfs_remove_file(self, session_id, path):
        if self.connected:
            self.db[config.MONGO_COLLECTION_VFS].delete_one({"session_id": session_id, "path": path})
        else:
            self._memory["vfs"] = [f for f in self._memory["vfs"] if not (f["session_id"] == session_id and f["path"] == path)]

    def vfs_get_files(self, session_id):
        if self.connected:
            return list(self.db[config.MONGO_COLLECTION_VFS].find({"session_id": session_id}, {"_id": 0}))
        return [f for f in self._memory.get("vfs", []) if f["session_id"] == session_id]

    def get_stats(self):
        if self.connected:
            sessions = self.db[config.MONGO_COLLECTION_SESSIONS]
            commands = self.db[config.MONGO_COLLECTION_COMMANDS]
            return {
                "total_sessions": sessions.count_documents({}),
                "active_sessions": sessions.count_documents({"active": True}),
                "total_commands": commands.count_documents({}),
                "total_exploits": self.db[config.MONGO_COLLECTION_EXPLOITS].count_documents({}),
                "total_credentials": self.db[config.MONGO_COLLECTION_CREDENTIALS].count_documents({}),
                "high_risk_sessions": sessions.count_documents({"risk_score": {"$gte": 50}}),
            }
        return {
            "total_sessions": len(self._memory.get("sessions", [])),
            "active_sessions": len([s for s in self._memory.get("sessions", []) if s.get("active")]),
            "total_commands": len(self._memory.get("commands", [])),
            "total_exploits": len(self._memory.get("exploits", [])),
            "total_credentials": len(self._memory.get("credentials", [])),
            "high_risk_sessions": 0,
        }

    def close(self):
        if self.client:
            self.client.close()
