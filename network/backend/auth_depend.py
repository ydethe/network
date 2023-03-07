from typing import Tuple
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.requests import Request

from .models import DbUser, con


class ChallengeMiddleware(BaseHTTPMiddleware):
    @staticmethod
    def analyse_header(headers: dict) -> dict:
        key = "challenge"
        if not key in headers.keys():
            key = "Challenge"
        challenge = headers.get(key, None)
        if challenge is None:
            response = {"error": 401, "message": "No challenge provided with the request"}
            return response

        if challenge.count(":") != 2:
            response = {
                "error": 402,
                "message": f"Invalid format for challenge. Shall be <user_id>:<b64_hash>:<b64_sign>. Got {challenge}",
            }
            return response

        user_id, b64_hash, b64_sign = challenge.split(":")

        response = {"user_id": int(user_id), "b64_hash": b64_hash, "b64_sign": b64_sign}

        return response

    async def dispatch(self, request: Request, call_next):
        if not request.url.path.startswith("/person/"):
            response = await call_next(request)
            return response

        response = self.analyse_header(request.headers)
        if "error" in response.keys():
            response = JSONResponse(response)
            return response

        user_id = response["user_id"]
        b64_hash = response["b64_hash"]
        b64_sign = response["b64_sign"]

        with con() as session:
            db_user = session.query(DbUser).filter(DbUser.id == user_id).first()

        if db_user.check_challenge(b64_hash, b64_sign):
            response = await call_next(request)
            return response
        else:
            response = JSONResponse({"error": 403, "message": f"Failed solving the challenge"})
            return response
