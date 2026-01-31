from pydantic import BaseModel

class EmailInput(BaseModel):
    sender: str
    subject: str
    body: str

class URLInput(BaseModel):
    url: str

class LogInput(BaseModel):
    timestamp: str
    user: str
    event: str
