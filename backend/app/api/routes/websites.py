from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.client import Client
from app.models.website import Website
from app.schemas.website import WebsiteCreate, WebsiteRead
from app.core.security import get_current_admin

router = APIRouter(
    prefix="/websites",
    tags=["Websites"],
    dependencies=[Depends(get_current_admin)],
)


@router.post("", response_model=WebsiteRead, status_code=status.HTTP_201_CREATED)
def create_website(payload: WebsiteCreate, db: Session = Depends(get_db)) -> Website:
    client = db.get(Client, payload.client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    website_data = payload.model_dump(exclude={"url"})
    website = Website(**website_data, url=str(payload.url), authorisation_status="pending")
    db.add(website)
    db.commit()
    db.refresh(website)
    return website


@router.get("", response_model=list[WebsiteRead])
def list_websites(
    client_id: int | None = Query(default=None, gt=0),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> list[Website]:
    statement = select(Website).order_by(Website.id.desc())
    if client_id is not None:
        statement = statement.where(Website.client_id == client_id)
    statement = statement.offset(offset).limit(limit)
    return list(db.scalars(statement).all())


@router.get("/{website_id}", response_model=WebsiteRead)
def get_website(website_id: int, db: Session = Depends(get_db)) -> Website:
    website = db.get(Website, website_id)
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")
    return website
