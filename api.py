from fastapi import FastAPI

app = FastAPI(
    title="ModSecurity Generator API",
    description="API для генерации правил ModSecurity из CVE",
    version="0.1.0",
)


@app.get("/")
def root():
    return {"message": "ModSecurity Generator API работает"}


@app.get("/health")
def health():
    return {"status": "ok"}