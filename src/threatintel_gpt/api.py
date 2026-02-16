"""
FastAPI REST API for ThreatIntel-GPT

Author: Ayi NEDJIMI
"""

import os
import logging
from typing import Optional, List
from datetime import datetime

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .analyzer import ThreatAnalyzer, ThreatAnalysisResult

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="ThreatIntel-GPT API",
    description="AI-Powered Threat Intelligence Analysis Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize analyzer
analyzer = ThreatAnalyzer(
    api_key=os.getenv("OPENAI_API_KEY"),
    use_cache=True
)


# Request/Response Models
class AnalyzeIOCRequest(BaseModel):
    ioc: str = Field(..., description="Indicator of Compromise to analyze")
    ioc_type: Optional[str] = Field(None, description="Type of IOC (ip, domain, hash, etc.)")
    context: Optional[dict] = Field(None, description="Additional context")


class BatchAnalyzeRequest(BaseModel):
    iocs: List[str] = Field(..., description="List of IOCs to analyze")
    ioc_type: Optional[str] = Field(None, description="Type of IOCs")


class AnalysisResponse(BaseModel):
    ioc: str
    ioc_type: str
    threat_score: float
    severity: str
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    description: str
    recommendations: List[str]
    sources: List[str]
    timestamp: str
    confidence: float
    related_threats: List[dict]


class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: str


# API Endpoints
@app.get("/", response_model=HealthResponse)
async def root():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_ioc(request: AnalyzeIOCRequest):
    """
    Analyze a single Indicator of Compromise
    """
    try:
        logger.info(f"Analyzing IOC: {request.ioc}")
        result = analyzer.analyze_ioc(
            ioc=request.ioc,
            ioc_type=request.ioc_type,
            context=request.context
        )

        return AnalysisResponse(
            ioc=result.ioc,
            ioc_type=result.ioc_type,
            threat_score=result.threat_score,
            severity=result.severity,
            mitre_tactics=result.mitre_tactics,
            mitre_techniques=result.mitre_techniques,
            description=result.description,
            recommendations=result.recommendations,
            sources=result.sources,
            timestamp=result.timestamp,
            confidence=result.confidence,
            related_threats=result.related_threats
        )
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze/batch", response_model=List[AnalysisResponse])
async def batch_analyze(request: BatchAnalyzeRequest):
    """
    Analyze multiple IOCs in batch
    """
    try:
        logger.info(f"Batch analyzing {len(request.iocs)} IOCs")
        results = analyzer.batch_analyze(
            iocs=request.iocs,
            ioc_type=request.ioc_type
        )

        return [
            AnalysisResponse(
                ioc=result.ioc,
                ioc_type=result.ioc_type,
                threat_score=result.threat_score,
                severity=result.severity,
                mitre_tactics=result.mitre_tactics,
                mitre_techniques=result.mitre_techniques,
                description=result.description,
                recommendations=result.recommendations,
                sources=result.sources,
                timestamp=result.timestamp,
                confidence=result.confidence,
                related_threats=result.related_threats
            )
            for result in results
        ]
    except Exception as e:
        logger.error(f"Batch analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/mitre/tactics")
async def get_mitre_tactics():
    """Get list of MITRE ATT&CK tactics"""
    try:
        tactics = analyzer.mitre.get_tactics()
        return {"tactics": tactics}
    except Exception as e:
        logger.error(f"Failed to get tactics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/mitre/techniques")
async def get_mitre_techniques(
    tactic: Optional[str] = Query(None, description="Filter by tactic")
):
    """Get MITRE ATT&CK techniques, optionally filtered by tactic"""
    try:
        if tactic:
            techniques = analyzer.mitre.get_techniques_by_tactic(tactic)
        else:
            techniques = list(analyzer.mitre.TECHNIQUE_KEYWORDS.keys())

        return {"techniques": techniques}
    except Exception as e:
        logger.error(f"Failed to get techniques: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/mitre/search")
async def search_mitre_techniques(
    query: str = Query(..., description="Search query")
):
    """Search MITRE ATT&CK techniques"""
    try:
        results = analyzer.mitre.search_techniques(query)
        return {"results": results}
    except Exception as e:
        logger.error(f"Search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/stats")
async def get_statistics():
    """Get system statistics"""
    try:
        stats = {
            "correlator": analyzer.correlator.get_statistics(),
            "cache": analyzer.cache.get_stats() if analyzer.cache else None
        }
        return stats
    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
