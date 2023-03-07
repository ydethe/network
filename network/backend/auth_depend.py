from fastapi import Request, HTTPException

from .models import DbUser, con


class ChallengeAuthentication(object):
    def __init__(self, challenge_timeout: float):
        self.challenge_timeout = challenge_timeout

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
                "error": 401,
                "message": f"Invalid format for challenge. Shall be <user_id>:<b64_hash>:<b64_sign>. Got {challenge}",
            }
            return response

        user_id, b64_hash, b64_sign = challenge.split(":")

        response = {"user_id": int(user_id), "b64_hash": b64_hash, "b64_sign": b64_sign}

        return response

    async def __call__(self, request: Request) -> int:
        response = self.analyse_header(request.headers)
        if "error" in response.keys():
            raise HTTPException(status_code=response["error"], detail=response["message"])

        user_id = response["user_id"]
        b64_hash = response["b64_hash"]
        b64_sign = response["b64_sign"]

        with con() as session:
            db_user = session.query(DbUser).filter(DbUser.id == user_id).first()

        if db_user.check_challenge(b64_hash, b64_sign, timeout=self.challenge_timeout):
            return user_id
        else:
            raise HTTPException(status_code=401, detail="Failed solving the challenge")


challenge_auth = ChallengeAuthentication(challenge_timeout=5)
