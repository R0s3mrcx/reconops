from __future__ import annotations
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from app.models.scan import ServiceCategory, RiskLevel


CATEGORY_PORTS: dict[ServiceCategory, set[int]] = {
    ServiceCategory.high_risk: {
        4444, 5555, 6666, 7777, 8888, 9999,
        1337, 31337, 12345, 54321,          
        4899,                                
        5900, 5901,                        
    },
    ServiceCategory.db_exposed: {
        1433, 1521, 3306, 5432,            
        6379, 6380,                          
        27017, 27018,                        
        9200, 9300,                         
        5984,                                
        7474, 7687,                         
        8529,                               
    },
    ServiceCategory.admin_panel: {
        8161,                             
        9000,                               
        15672,                               
        5601,                               
        16686,                               
        9090,                                
        3000,                                
        8080, 8443,                          
    },
    ServiceCategory.dev_exposed: {
        3000, 4000, 4200,                
        5000, 5001,                         
        5173,                                
        8888,                               
        8000, 8001,                          
        9229,                               
    },
    ServiceCategory.legacy: {
        21,   
        23,   
        512, 513, 514,  
        135,  
        139,  
        445,  
        79,   
        111,  
    },
    ServiceCategory.iot: {
        1883, 8883,  
        5683, 5684,  
        502,         
        102,         
        44818,      
    },
}

CATEGORY_RISK: dict[ServiceCategory, int] = {
    ServiceCategory.high_risk:    90,
    ServiceCategory.db_exposed:   80,
    ServiceCategory.legacy:       70,
    ServiceCategory.admin_panel:  65,
    ServiceCategory.iot:          60,
    ServiceCategory.dev_exposed:  55,
    ServiceCategory.standard:     15,
}

SERVICE_DESCRIPTIONS: dict[int, str] = {
    21:    "FTP — plaintext file transfer, credential exposure",
    22:    "SSH — secure shell, ensure key-only auth and rate limiting",
    23:    "Telnet — plaintext protocol, no encryption, replace with SSH",
    25:    "SMTP — mail relay, verify SPF/DKIM/DMARC, restrict relay",
    80:    "HTTP — unencrypted web traffic, redirect to HTTPS",
    443:   "HTTPS — encrypted web, verify TLS version and cipher suite",
    3000:  "Dev server exposed — Node/React/Grafana, should not be public",
    3306:  "MySQL — database port exposed, firewall immediately",
    5432:  "PostgreSQL — database port exposed, restrict to app subnet",
    5601:  "Kibana — log analytics UI, restrict to internal network",
    6379:  "Redis — in-memory store, often no auth by default",
    8080:  "HTTP alternate — common for dev/proxy, verify intended exposure",
    8443:  "HTTPS alternate — often staging/dev, verify TLS configuration",
    8888:  "Jupyter Notebook — RCE risk if exposed, VPN-only access",
    9200:  "Elasticsearch REST API — data exfiltration risk if public",
    9229:  "Node.js debugger — remote code execution if exposed",
    27017: "MongoDB — database port, often no auth in dev deployments",
    4444:  "Non-standard port — common Metasploit/C2 default, investigate",
    1883:  "MQTT broker — IoT telemetry, unencrypted by default",
    9090:  "Prometheus/Cockpit — metrics endpoint, may leak infra details",
    15672: "RabbitMQ management UI — admin panel, restrict access",
    445:   "SMB — file sharing, common ransomware lateral movement vector",
}


def extract_features(port: int, service: str, state: str) -> list[float]:
 
    well_known = {22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995}
    db_ports = {1433, 1521, 3306, 5432, 6379, 27017, 9200, 5984}

    return [
        port / 65535.0,
        1.0 if port < 1024 else 0.0,
        1.0 if port > 49151 else 0.0,
        1.0 if port in well_known else 0.0,
        1.0 if state == "open" else 0.0,
        min(len(service), 20) / 20.0 if service else 0.0,
        1.0 if port in db_ports else 0.0,
        1.0 if (port > 1024 and port not in well_known) else 0.0,
    ]


class AnomalyClassifier:

    def __init__(self) -> None:
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.15,
            random_state=42,
        )
        self.scaler = StandardScaler()
        self._fitted = False

    def fit(self, findings_features: list[list[float]]) -> None:
        if len(findings_features) < 4:
            baseline = [extract_features(p, "known", "open") for p in [22, 80, 443, 53]]
            findings_features = baseline + findings_features

        X = np.array(findings_features)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self._fitted = True

    def score(self, features: list[float]) -> float:
        if not self._fitted:
            return 0.5
        X = np.array([features])
        X_scaled = self.scaler.transform(X)
        raw = self.model.decision_function(X_scaled)[0]
        normalized = float(np.clip(0.5 - raw, 0.0, 1.0))
        return round(normalized, 4)

    def classify(
        self,
        port: int,
        service: str,
        state: str,
    ) -> dict:
        features = extract_features(port, service, state)

        category = ServiceCategory.standard
        for cat, ports in CATEGORY_PORTS.items():
            if port in ports:
                category = cat
                break

        heuristic_risk = CATEGORY_RISK[category]
        anomaly_score = self.score(features)

        composite = int(heuristic_risk * 0.6 + anomaly_score * 100 * 0.4)
        risk_score = max(5, min(100, composite))

        is_shadow = category != ServiceCategory.standard or risk_score >= 55

        if risk_score >= 80:
            risk_level = RiskLevel.critical
        elif risk_score >= 60:
            risk_level = RiskLevel.high
        elif risk_score >= 40:
            risk_level = RiskLevel.medium
        else:
            risk_level = RiskLevel.low

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "category": category,
            "is_shadow": is_shadow,
            "description": SERVICE_DESCRIPTIONS.get(
                port, f"{service or 'unknown'} — review exposure necessity"
            ),
            "anomaly_score": anomaly_score,
            "feature_vector": features,
        }


def new_classifier() -> AnomalyClassifier:
    return AnomalyClassifier()
