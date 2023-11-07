from fastapi import Request, HTTPException

from .models import DbUser, get_connection


class ChallengeAuthentication(object):
    """This class can be used as a fastapi Depends
    for the endpoints that needs authentication.

    Args:
        challenge_timeout: Timeout for the challenge (s)

    """

    def __init__(self, challenge_timeout: float):
        self.challenge_timeout = challenge_timeout

    @staticmethod
    def analyse_header(headers: dict) -> dict:
        """Analyse headers to find a valid a valid challenge.
        If found, return a dictionary whose keys are:

        * user_id: The id of the authenticating user
        * b64_hash: the challenge's hash as raw string
        * b64_sign: The challenge's signature as raw string

        `network.backend.models.DbUser.check_challenge`
        can use the raw strings to check the challenge

        Args:
            headers: The headers dictionary as contained in fastapi Request objects

        Returns:
            The challenge as a dictionary

        """
        key = "challenge"
        if key not in headers.keys():
            key = "Challenge"
        challenge = headers.get(key, None)
        if challenge is None:
            response = {"status": 401, "message": "No challenge provided with the request"}
            return response

        if challenge.count(":") != 2:
            response = {
                "status": 401,
                "message": (
                    "Invalid format for challenge. Shall be <user_id>:<b64_hash>:<b64_sign>."
                    f" Got {challenge}"
                ),
            }
            return response

        user_id, b64_hash, b64_sign = challenge.split(":")

        response = {"user_id": int(user_id), "b64_hash": b64_hash, "b64_sign": b64_sign}

        return response

    async def __call__(self, request: Request) -> int:
        response = self.analyse_header(request.headers)
        if "status" in response.keys():
            raise HTTPException(status_code=response["status"], detail=response["message"])

        user_id = response["user_id"]
        b64_hash = response["b64_hash"]
        b64_sign = response["b64_sign"]

        con = get_connection()
        with con() as session:
            db_user: DbUser = session.query(DbUser).filter(DbUser.id == user_id).first()
            if db_user is None:
                raise HTTPException(
                    status_code=401, detail="The user making the challenge could not be found"
                )

            challenge_response = db_user.check_challenge(
                session, b64_hash, b64_sign, timeout=self.challenge_timeout
            )

            if challenge_response["status"] != 200:
                raise HTTPException(
                    status_code=challenge_response["status"], detail=challenge_response["message"]
                )

        return user_id


challenge_auth = ChallengeAuthentication(challenge_timeout=5)
