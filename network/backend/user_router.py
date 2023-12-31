from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import schemas
from . import crud
from .models import get_db, get_connection, DbUser
from .auth_depend import challenge_auth


router = APIRouter(prefix="/users", tags=["users"])


@router.post(
    "/",
    response_model=schemas.UserModel,
    description="Creates a user",
)
async def create_user(
    user: schemas.UserModel,
    db: Session = Depends(get_db),
    user_id: int = Depends(challenge_auth),
):
    con = get_connection()
    async with con() as session:
        db_issuer: DbUser = await session.query(DbUser).filter(DbUser.id == user_id).first()

    if not db_issuer.admin:
        raise HTTPException(status_code=403, detail="Only an admin can create a user")

    new_user = crud.create_user(db=db, user=user)

    return new_user
