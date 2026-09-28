class RecommendationService:
    RECOMMENDATIONS_MAP = {
        "DDoS": [
            "Enable rate limiting and SYN proxy protection on edge firewalls.",
            "Activate Cloud/ISP DDoS mitigation scrubbers.",
            "Isolate target IP range to mitigate upstream bandwidth saturation."
        ],
        "DoS Hulk": [
            "Enforce HTTP keep-alive timeouts and request size limits.",
            "Implement Web Application Firewall (WAF) rate rules for repeated GET requests.",
            "Deploy reverse-proxy caching (Nginx/Varnish) to absorb heavy request volume."
        ],
        "PortScan": [
            "Block originating source IP address at the firewall boundary.",
            "Review exposed port surface and disable unused daemon services.",
            "Enable automated fail2ban / IP shun policies for sequential connection attempts."
        ],
        "Bot": [
            "Isolate infected host workstation/server from the local network segment.",
            "Perform anti-malware and memory forensics on the flagged internal host.",
            "Block command-and-control (C2) domain/IP communication at the DNS sinkhole."
        ],
        "Web Attack - Brute Force": [
            "Enforce multi-factor authentication (MFA) and account lockout policies.",
            "Implement IP-based rate limiting on login/auth endpoints.",
            "Deploy CAPTCHA challenge after 3 failed login attempts."
        ],
        "Web Attack - XSS": [
            "Sanitize and encode all dynamic user inputs before rendering in the DOM.",
            "Configure strict Content Security Policy (CSP) HTTP headers.",
            "Enable WAF rule patterns for script injection payloads."
        ],
        "Web Attack - SQL Injection": [
            "Audit database query handlers to use parameterized statements / prepared queries exclusively.",
            "Restrict database user privileges following the principle of least privilege.",
            "Deploy WAF signatures targeting SQL syntax keywords (UNION, SELECT, OR 1=1)."
        ],
        "FTP-Patator": [
            "Disable root/anonymous FTP access and enforce SSH/SFTP with public key authentication.",
            "Enable fail2ban protection on port 21/22.",
            "Restrict management port access to authorized VPN subnets only."
        ],
        "Infiltration": [
            "Initiate immediate incident response protocol for internal network compromise.",
            "Audit lateral movement paths and active privilege escalation attempts.",
            "Rotate all domain administrative credentials and isolate compromised endpoints."
        ]
    }

    @staticmethod
    def get_recommendations(prediction: str) -> list[str]:
        return RecommendationService.RECOMMENDATIONS_MAP.get(
            prediction,
            [
                "Monitor network traffic for anomalies.",
                "Ensure firewall and IDS signatures are up to date.",
                "Conduct regular vulnerability assessments and log reviews."
            ]
        )
