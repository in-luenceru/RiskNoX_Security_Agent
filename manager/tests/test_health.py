"""
Test health check endpoints
"""

import pytest
from fastapi.testclient import TestClient


def test_health_check(client: TestClient):
    """Test basic health check endpoint"""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    
    data = response.json()
    assert data["status"] in ["healthy", "degraded"]
    assert "timestamp" in data
    assert "version" in data
    assert "checks" in data
    
    # Check individual service health
    checks = data["checks"]
    assert "database" in checks
    assert "redis" in checks
    assert "storage" in checks


def test_readiness_check(client: TestClient):
    """Test readiness probe endpoint"""
    response = client.get("/api/v1/ready")
    assert response.status_code == 200
    
    data = response.json()
    assert data["status"] == "ready"
    assert "timestamp" in data


def test_liveness_check(client: TestClient):
    """Test liveness probe endpoint"""
    response = client.get("/api/v1/live")
    assert response.status_code == 200
    
    data = response.json()
    assert data["status"] == "alive"
    assert "timestamp" in data


def test_root_endpoint(client: TestClient):
    """Test root endpoint"""
    response = client.get("/")
    assert response.status_code == 200
    
    data = response.json()
    assert data["service"] == "RiskNoX Security Manager"
    assert data["status"] == "operational"
    assert "version" in data


def test_metrics_endpoint(client: TestClient):
    """Test Prometheus metrics endpoint"""
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    
    # Check for some expected metrics
    content = response.text
    assert "manager_http_requests_total" in content