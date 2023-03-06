from typing import Tuple
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse
from starlette.requests import Request

from .models import con
from .User import User


class ChallengeMiddleware(BaseHTTPMiddleware):
    @staticmethod
    def analyse_header(headers: dict) -> Tuple[int, str, str]:
        key = "challenge"
        if not key in headers.keys():
            key = "Challenge"
        challenge = headers.get(key, None)
        if challenge is None:
            response = PlainTextResponse("No challenge provided with the request", status_code=401)
            return response

        if challenge.count(":") != 2:
            response = PlainTextResponse(
                f"Invalid format for challenge. Shall be <user_id>:<b64_hash>:<b64_sign>. Got {challenge}",
                status_code=402,
            )
            return response

        user_id, b64_hash, b64_sign = challenge.split(":")

        return int(user_id), b64_hash, b64_sign

    async def dispatch(self, request: Request, call_next):
        user_id, b64_hash, b64_sign = self.analyse_header(request.headers)

        user = User(user_id, file_pref="alice_")
        if user.check_challenge(b64_hash, b64_sign):
            response = await call_next(request)
            return response
        else:
            response = PlainTextResponse(f"Failed solving the challenge", status_code=403)
            return response
