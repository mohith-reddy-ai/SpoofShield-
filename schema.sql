from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import dns.resolver
import json

app = FastAPI()

class DNSComparisonRequest(BaseModel):
    domain: str
    record_type: str
    resolvers: list

# Allowed record types
allowed_record_types = ["A", "AAAA", "MX", "TXT"]

# Default DNS resolvers (add more if necessary)
default_resolvers = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]

@app.post("/compare-dns")
async def compare_dns(request: DNSComparisonRequest):
    domain = request.domain
    record_type = request.record_type
    resolvers = request.resolvers or default_resolvers

    results = []

    if record_type not in allowed_record_types:
        raise HTTPException(status_code=400, detail="Invalid record type")

    for resolver in resolvers:
        try:
            answers = dns.resolver.resolve(domain, record_type, nameservers=[resolver], timeout=5)
            results.append({
                "resolver": resolver,
                "answers": [str(r) for r in answers],
                "error": None
            })
        except dns.resolver.NXDOMAIN:
            results.append({
                "resolver": resolver,
                "answers": None,
                "error": "Domain does not exist"
            })
        except dns.resolver.Timeout:
            results.append({
                "resolver": resolver,
                "answers": None,
                "error": "Timeout"
            })
        except dns.resolver.NoAnswer:
            results.append({
                "resolver": resolver,
                "answers": None,
                "error": "No answers"
            })
        except Exception as e:
            results.append({
                "resolver": resolver,
                "answers": None,
                "error": str(e)
            })

    return {
        "status": "success",
        "results": results,
        "comparison": compare_results(results)
    }

@app.get("/health")
async def health():
    return {"status": "healthy"}

def compare_results(results):
    comparison = {}
    for resolver in results:
        r = resolver["resolver"]
        comparison[r] = {}

        if resolver["answers"] is not None:
            for other_resolver in results:
                if other_resolver["resolver"] != r:
                    diff = list(set(resolver["answers"]) ^ set(other_resolver["answers"]))
                    comparison[r][other_resolver["resolver"]] = diff

    return comparison

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8100)