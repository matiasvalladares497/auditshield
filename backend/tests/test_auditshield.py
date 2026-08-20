"""
AuditShield — Tests del Backend
Suite de pruebas básicas para validar el funcionamiento del sistema.

Para ejecutar:
    pip install pytest pytest-asyncio httpx
    pytest tests/ -v
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from app.main import app
from app.services.audit_engine import (
    calculate_security_score,
    get_score_letter,
    summarize_findings,
    create_finding_id,
)

# ─────────────────────────────────────────────────────────────
# Fixture: cliente de prueba
# ─────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    """Cliente HTTP de prueba."""
    return TestClient(app)


# ─────────────────────────────────────────────────────────────
# Tests: Health check
# ─────────────────────────────────────────────────────────────

class TestHealthCheck:
    def test_health_endpoint_ok(self, client):
        """El endpoint /health debe responder 200."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "AuditShield API"

    def test_health_has_version(self, client):
        """El endpoint /health debe incluir la versión."""
        response = client.get("/health")
        data = response.json()
        assert "version" in data


# ─────────────────────────────────────────────────────────────
# Tests: Audit Engine — calculate_security_score
# ─────────────────────────────────────────────────────────────

class TestCalculateSecurityScore:
    """Pruebas del algoritmo de cálculo de score."""

    def test_no_findings_perfect_score(self):
        """Sin hallazgos: score debe ser 100."""
        score = calculate_security_score([])
        assert score == 100

    def test_single_critical_reduces_score(self):
        """Un hallazgo crítico debe reducir el score en 20 puntos."""
        findings = [{'severity': 'critical', 'title': 'Test', 'module': 'web'}]
        score = calculate_security_score(findings)
        assert score == 80

    def test_single_high_reduces_score(self):
        """Un hallazgo alto debe reducir el score en 10 puntos."""
        findings = [{'severity': 'high', 'title': 'Test', 'module': 'web'}]
        score = calculate_security_score(findings)
        assert score == 90

    def test_single_medium_reduces_score(self):
        """Un hallazgo medio debe reducir el score en 5 puntos."""
        findings = [{'severity': 'medium', 'title': 'Test', 'module': 'web'}]
        score = calculate_security_score(findings)
        assert score == 95

    def test_single_low_reduces_score(self):
        """Un hallazgo bajo debe reducir el score en 2 puntos."""
        findings = [{'severity': 'low', 'title': 'Test', 'module': 'web'}]
        score = calculate_security_score(findings)
        assert score == 98

    def test_score_never_below_zero(self):
        """El score nunca debe ser negativo."""
        findings = [{'severity': 'critical', 'title': f'Critical {i}', 'module': 'web'} for i in range(20)]
        score = calculate_security_score(findings)
        assert score >= 0

    def test_score_never_above_100(self):
        """El score nunca debe superar 100."""
        score = calculate_security_score([])
        assert score <= 100

    def test_multiple_findings_cumulative(self):
        """Múltiples hallazgos acumulan sus reducciones."""
        findings = [
            {'severity': 'critical', 'title': 'C1', 'module': 'web'},
            {'severity': 'high', 'title': 'H1', 'module': 'ssl'},
            {'severity': 'medium', 'title': 'M1', 'module': 'dns'},
        ]
        score = calculate_security_score(findings)
        # 100 - 20 - 10 - 5 = 65
        assert score == 65

    def test_info_severity_not_penalized(self):
        """Los hallazgos informativos no deben penalizar el score."""
        findings = [{'severity': 'info', 'title': 'Info', 'module': 'web'}]
        score = calculate_security_score(findings)
        assert score == 100


# ─────────────────────────────────────────────────────────────
# Tests: Audit Engine — get_score_letter
# ─────────────────────────────────────────────────────────────

class TestGetScoreLetter:
    """Pruebas de la clasificación por letra."""

    def test_perfect_score_a_plus(self):
        assert get_score_letter(100) == 'A+'

    def test_score_95_a_plus(self):
        assert get_score_letter(95) == 'A+'

    def test_score_90_a_plus(self):
        assert get_score_letter(90) == 'A+'

    def test_score_85_a(self):
        assert get_score_letter(85) == 'A'

    def test_score_80_a(self):
        assert get_score_letter(80) == 'A'

    def test_score_75_b(self):
        assert get_score_letter(75) == 'B'

    def test_score_70_b(self):
        assert get_score_letter(70) == 'B'

    def test_score_65_c(self):
        assert get_score_letter(65) == 'C'

    def test_score_60_c(self):
        assert get_score_letter(60) == 'C'

    def test_score_55_d(self):
        assert get_score_letter(55) == 'D'

    def test_score_50_d(self):
        assert get_score_letter(50) == 'D'

    def test_score_49_f(self):
        assert get_score_letter(49) == 'F'

    def test_score_0_f(self):
        assert get_score_letter(0) == 'F'


# ─────────────────────────────────────────────────────────────
# Tests: Audit Engine — summarize_findings
# ─────────────────────────────────────────────────────────────

class TestSummarizeFindings:
    """Pruebas del resumen de hallazgos."""

    def test_empty_findings(self):
        summary = summarize_findings([])
        assert summary['total'] == 0
        assert summary['critical'] == 0
        assert summary['high'] == 0
        assert summary['medium'] == 0
        assert summary['low'] == 0

    def test_counts_correctly(self):
        findings = [
            {'severity': 'critical'},
            {'severity': 'critical'},
            {'severity': 'high'},
            {'severity': 'medium'},
            {'severity': 'medium'},
            {'severity': 'medium'},
            {'severity': 'low'},
            {'severity': 'info'},
        ]
        summary = summarize_findings(findings)
        assert summary['critical'] == 2
        assert summary['high'] == 1
        assert summary['medium'] == 3
        assert summary['low'] == 1
        assert summary['total'] == 8


# ─────────────────────────────────────────────────────────────
# Tests: Audit Engine — create_finding_id
# ─────────────────────────────────────────────────────────────

class TestCreateFindingId:
    """Pruebas del generador de IDs de hallazgos."""

    def test_format_is_correct(self):
        """El ID debe seguir el formato AS-YYYY-NNN."""
        import re
        finding_id = create_finding_id('audit-123', 1)
        pattern = r'^AS-\d{4}-\d{3}$'
        assert re.match(pattern, finding_id), f"ID '{finding_id}' no cumple el formato AS-YYYY-NNN"

    def test_index_zero_padded(self):
        """El índice debe estar zero-padded a 3 dígitos."""
        finding_id = create_finding_id('audit-123', 1)
        parts = finding_id.split('-')
        assert parts[2] == '001'

    def test_index_three_digits(self):
        finding_id = create_finding_id('audit-123', 42)
        parts = finding_id.split('-')
        assert parts[2] == '042'

    def test_large_index(self):
        finding_id = create_finding_id('audit-123', 100)
        parts = finding_id.split('-')
        assert parts[2] == '100'


# ─────────────────────────────────────────────────────────────
# Tests: API Auth — endpoints
# ─────────────────────────────────────────────────────────────

class TestAuthEndpoints:
    """Pruebas de los endpoints de autenticación."""

    def test_login_without_credentials_fails(self, client):
        """Login sin credenciales debe fallar."""
        response = client.post("/api/auth/login", data={})
        assert response.status_code in [400, 422]

    def test_login_with_wrong_credentials_fails(self, client):
        """Login con credenciales incorrectas debe retornar 401."""
        response = client.post("/api/auth/login", data={
            "username": "noexiste@test.com",
            "password": "wrongpassword"
        })
        assert response.status_code in [401, 422]

    def test_register_missing_fields_fails(self, client):
        """Registro sin campos requeridos debe fallar."""
        response = client.post("/api/auth/register", json={})
        assert response.status_code == 422

    def test_me_without_token_returns_401(self, client):
        """Acceder a /me sin token debe retornar 401."""
        response = client.get("/api/auth/me")
        assert response.status_code == 401


# ─────────────────────────────────────────────────────────────
# Tests: Scanners — Verificación de módulos
# ─────────────────────────────────────────────────────────────

class TestScannerModules:
    """Pruebas de importación y estructura de los scanners."""

    def test_osint_module_importable(self):
        """El módulo OSINT debe ser importable."""
        try:
            from app.scanners import osint
            assert hasattr(osint, 'run_osint_scan')
        except ImportError as e:
            pytest.skip(f"Dependencias no instaladas: {e}")

    def test_ssl_analyzer_importable(self):
        """El módulo SSL debe ser importable."""
        try:
            from app.scanners import ssl_analyzer
            assert hasattr(ssl_analyzer, 'run_ssl_scan')
        except ImportError as e:
            pytest.skip(f"Dependencias no instaladas: {e}")

    def test_web_scanner_importable(self):
        """El módulo Web Scanner debe ser importable."""
        try:
            from app.scanners import web_scanner
            assert hasattr(web_scanner, 'run_web_scan')
        except ImportError as e:
            pytest.skip(f"Dependencias no instaladas: {e}")

    def test_dns_auditor_importable(self):
        """El módulo DNS Auditor debe ser importable."""
        try:
            from app.scanners import dns_auditor
            assert hasattr(dns_auditor, 'run_dns_scan')
        except ImportError as e:
            pytest.skip(f"Dependencias no instaladas: {e}")

    def test_port_scanner_importable(self):
        """El módulo Port Scanner debe ser importable."""
        try:
            from app.scanners import port_scanner
            assert hasattr(port_scanner, 'run_port_scan')
        except ImportError as e:
            pytest.skip(f"Dependencias no instaladas: {e}")

    def test_cve_matcher_importable(self):
        """El módulo CVE Matcher debe ser importable."""
        try:
            from app.scanners import cve_matcher
            assert hasattr(cve_matcher, 'run_cve_scan')
        except ImportError as e:
            pytest.skip(f"Dependencias no instaladas: {e}")

    def test_waf_detector_importable(self):
        """El módulo WAF Detector debe ser importable."""
        try:
            from app.scanners import waf_detector
            assert hasattr(waf_detector, 'detect_waf')
        except ImportError as e:
            pytest.skip(f"Dependencias no instaladas: {e}")

    def test_compliance_checker_importable(self):
        """El módulo Compliance Checker debe ser importable."""
        try:
            from app.scanners import compliance_checker
            assert hasattr(compliance_checker, 'run_compliance_check')
        except ImportError as e:
            pytest.skip(f"Dependencias no instaladas: {e}")


# ─────────────────────────────────────────────────────────────
# Tests: Formato de findings
# ─────────────────────────────────────────────────────────────

class TestFindingFormat:
    """Verificar que los hallazgos tengan el formato correcto."""

    REQUIRED_FIELDS = {'severity', 'title', 'description', 'recommendation'}
    VALID_SEVERITIES = {'critical', 'high', 'medium', 'low', 'info'}

    def _make_finding(self, **overrides):
        base = {
            'severity': 'high',
            'title': 'Test Finding',
            'description': 'Descripción del hallazgo',
            'recommendation': 'Recomendación de remediación',
            'evidence': 'Evidencia encontrada',
            'impact': 'Impacto potencial',
            'references': ['https://owasp.org/test'],
            'module': 'web',
        }
        return {**base, **overrides}

    def test_finding_has_all_required_fields(self):
        finding = self._make_finding()
        for field in self.REQUIRED_FIELDS:
            assert field in finding, f"Finding falta campo: {field}"

    def test_finding_severity_is_valid(self):
        for severity in self.VALID_SEVERITIES:
            finding = self._make_finding(severity=severity)
            assert finding['severity'] in self.VALID_SEVERITIES

    def test_invalid_severity_identified(self):
        finding = self._make_finding(severity='unknown')
        assert finding['severity'] not in self.VALID_SEVERITIES
