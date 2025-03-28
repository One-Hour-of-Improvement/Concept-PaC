from fastapi import FastAPI, Header, HTTPException
import httpx
import json

app = FastAPI()

@app.get("/sensitive-data")
async def get_sensitive_data(x_user_role: str = Header(default=None)):
    # Check authorization with OPA
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://opa:8181/v1/data/authz/allow",
            json={
                "input": {
                    "user_role": x_user_role,
                    "path": "sensitive-data",
                    "method": "GET"
                }
            }
        )
        
        result = response.json()
        if not result.get("result", False):
            raise HTTPException(status_code=403, detail="Unauthorized")
    
    return {"message": "This is sensitive data", "data": "secret-info"}

@app.get("/public-data")
async def get_public_data(x_user_role: str = Header(default=None)):
    # Check authorization with OPA
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://opa:8181/v1/data/authz/allow",
            json={
                "input": {
                    "user_role": x_user_role,
                    "path": "public-data",
                    "method": "GET"
                }
            }
        )
        
        result = response.json()
        if not result.get("result", False):
            raise HTTPException(status_code=403, detail="Unauthorized")
    
    return {"message": "This is public data", "data": "hello world"} 