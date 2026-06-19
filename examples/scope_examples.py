#!/usr/bin/env python3
"""
HexStrike Comprehensive Scope Configuration Examples
====================================================

This file demonstrates how to use the new comprehensive scope system.
"""

import requests
import json

# HexStrike API endpoint
API_URL = "http://127.0.0.1:8888/api/tools/http-framework"


def example_1_bug_bounty_scope():
    """Example 1: Configure scope for a bug bounty program"""
    print("=" * 70)
    print("Example 1: Bug Bounty Program Scope")
    print("=" * 70)
    
    payload = {
        "action": "set_scope",
        "advanced_scope": {
            "targets": {
                "domains": ["hackerone.com", "api.hackerone.com"],
                "include_subdomains": True,
                "subdomain_depth": 3
            },
            "network": {
                "ports": {"tcp": [80, 443, 8080, 8443]},
                "protocols": ["http", "https"]
            },
            "paths": {
                "excluded_paths": ["/logout", "/signout", "/delete"],
                "path_patterns": {
                    "exclude": ["^/auth/logout.*", "^.*/delete/.*"]
                }
            },
            "vulnerability_testing": {
                "categories": {
                    "injection": True,
                    "xss": True,
                    "broken_access_control": True,
                    "ssrf": True,
                    "idor": True
                },
                "safe_mode": True,
                "proof_of_concept_only": True,
                "active_exploitation": False
            },
            "exclusions": {
                "domains": ["support.hackerone.com"],
                "keywords": ["production", "prod"]
            },
            "testing_limits": {
                "max_requests_per_second": 10,
                "max_concurrent_connections": 20
            },
            "compliance": {
                "authorization": {
                    "written_permission": True,
                    "permission_document_id": "H1-BUGBOUNTY-2024"
                },
                "terms_of_service": {
                    "respect_robots_txt": True,
                    "respect_security_txt": True
                }
            }
        }
    }
    
    response = requests.post(API_URL, json=payload)
    print(json.dumps(response.json(), indent=2))


def example_2_load_template():
    """Example 2: Load a pre-built scope template"""
    print("\n" + "=" * 70)
    print("Example 2: Load Pre-Built Template")
    print("=" * 70)
    
    # First, see available templates
    payload = {"action": "get_scope_templates"}
    response = requests.post(API_URL, json=payload)
    templates = response.json()
    
    print("\nAvailable Templates:")
    for name in templates.get("template_names", []):
        print(f"  - {name}")
    
    # Load the bug_bounty_program template
    payload = {
        "action": "load_scope_template",
        "template_name": "bug_bounty_program"
    }
    response = requests.post(API_URL, json=payload)
    print("\nLoaded Template:")
    print(json.dumps(response.json(), indent=2))


def example_3_api_testing_scope():
    """Example 3: Configure scope for API security testing"""
    print("\n" + "=" * 70)
    print("Example 3: API Security Testing Scope")
    print("=" * 70)
    
    payload = {
        "action": "set_scope",
        "advanced_scope": {
            "targets": {
                "domains": ["api.example.com"],
                "include_subdomains": False,
                "url_patterns": ["^https://api\\.example\\.com/v[0-9]+/.*"]
            },
            "network": {
                "ports": {"tcp": [443, 8443]},
                "protocols": ["https"],
                "require_https_only": True
            },
            "paths": {
                "included_paths": ["/api/v1/", "/api/v2/"],
                "file_extensions": {"include": [".json", ".xml"]}
            },
            "authentication": {
                "test_unauthenticated": True,
                "test_authenticated": True,
                "tokens": ["Bearer YOUR_API_TOKEN_HERE"],
                "privilege_levels": ["guest", "user", "admin"]
            },
            "vulnerability_testing": {
                "categories": {
                    "injection": True,
                    "broken_access_control": True,
                    "api_abuse": True,
                    "cors_misconfiguration": True,
                    "idor": True
                },
                "safe_mode": True
            },
            "testing_limits": {
                "max_requests_per_second": 20,
                "request_timeout": 10
            }
        }
    }
    
    response = requests.post(API_URL, json=payload)
    print(json.dumps(response.json(), indent=2))


def example_4_internal_network_scope():
    """Example 4: Configure scope for internal network pentest"""
    print("\n" + "=" * 70)
    print("Example 4: Internal Network Pentest Scope")
    print("=" * 70)
    
    payload = {
        "action": "set_scope",
        "advanced_scope": {
            "targets": {
                "ip_ranges": ["192.168.1.0/24", "10.0.0.0/16"],
                "specific_ips": ["192.168.1.100", "192.168.1.101"],
                "domains": ["internal.company.local"]
            },
            "network": {
                "ports": {
                    "tcp": [],  # Empty = all TCP ports
                    "udp": [53, 161, 389],
                    "excluded_ports": [25, 465, 587]  # Don't touch mail servers
                },
                "protocols": ["http", "https", "ftp", "ssh", "smb", "rdp"]
            },
            "vulnerability_testing": {
                "categories": {
                    "injection": True,
                    "broken_authentication": True,
                    "known_vulnerabilities": True,
                    "ssrf": True,
                    "sensitive_data_exposure": True
                },
                "active_exploitation": True,
                "safe_mode": False
            },
            "testing_limits": {
                "max_requests_per_second": 50,
                "max_concurrent_connections": 100
            },
            "compliance": {
                "authorization": {
                    "written_permission": True,
                    "authorized_by": "CISO",
                    "authorization_date": "2024-06-01",
                    "permission_document_id": "INTERNAL-PENTEST-Q2-2024"
                }
            }
        }
    }
    
    response = requests.post(API_URL, json=payload)
    print(json.dumps(response.json(), indent=2))


def example_5_red_team_operation():
    """Example 5: Configure scope for red team operation (stealth mode)"""
    print("\n" + "=" * 70)
    print("Example 5: Red Team Operation Scope (Stealth)")
    print("=" * 70)
    
    payload = {
        "action": "set_scope",
        "advanced_scope": {
            "targets": {
                "domains": ["target-company.com"],
                "include_subdomains": True,
                "ip_ranges": ["203.0.113.0/24"]
            },
            "testing_limits": {
                "max_requests_per_second": 2,  # Low and slow
                "max_concurrent_connections": 3,
                "throttle_on_error": True,
                "backoff_strategy": "exponential"
            },
            "reconnaissance": {
                "passive_only": True,
                "osint_sources": {
                    "search_engines": True,
                    "social_media": True,
                    "pastebin": True,
                    "github": True,
                    "wayback_machine": True
                },
                "subdomain_enumeration": {
                    "enabled": True,
                    "bruteforce": False
                }
            },
            "advanced": {
                "tor_configuration": {
                    "use_tor": True,
                    "circuit_renewal_minutes": 10
                },
                "evasion_techniques": {
                    "randomize_user_agent": True,
                    "randomize_request_order": True,
                    "time_randomization": True,
                    "header_randomization": True
                }
            },
            "vulnerability_testing": {
                "active_exploitation": True,
                "safe_mode": False
            }
        }
    }
    
    response = requests.post(API_URL, json=payload)
    print(json.dumps(response.json(), indent=2))


def example_6_validate_urls():
    """Example 6: Validate if URLs are in scope"""
    print("\n" + "=" * 70)
    print("Example 6: Validate URLs Against Scope")
    print("=" * 70)
    
    # First, set a simple scope
    set_scope = {
        "action": "set_scope",
        "advanced_scope": {
            "targets": {
                "domains": ["example.com"],
                "include_subdomains": True
            },
            "exclusions": {
                "keywords": ["admin", "delete"],
                "domains": ["mail.example.com"]
            }
        }
    }
    requests.post(API_URL, json=set_scope)
    
    # Test various URLs
    test_urls = [
        "https://example.com/api/users",           # Should be in scope
        "https://api.example.com/v1/data",          # Should be in scope (subdomain)
        "https://mail.example.com/inbox",           # Out of scope (excluded domain)
        "https://example.com/admin/delete",         # Out of scope (excluded keyword)
        "https://otherdomain.com/test"              # Out of scope (different domain)
    ]
    
    for url in test_urls:
        payload = {
            "action": "validate_url",
            "test_url": url
        }
        response = requests.post(API_URL, json=payload)
        result = response.json()
        in_scope = result.get("in_scope", False)
        status = "✅ IN SCOPE" if in_scope else "🚫 OUT OF SCOPE"
        print(f"{status}: {url}")


def example_7_export_import_scope():
    """Example 7: Export and import scope configurations"""
    print("\n" + "=" * 70)
    print("Example 7: Export and Import Scope")
    print("=" * 70)
    
    # Load a template
    load_payload = {
        "action": "load_scope_template",
        "template_name": "web_app_comprehensive"
    }
    requests.post(API_URL, json=load_payload)
    print("✅ Loaded 'web_app_comprehensive' template")
    
    # Export to file
    export_payload = {
        "action": "export_scope",
        "filepath": "my_custom_scope.json"
    }
    response = requests.post(API_URL, json=export_payload)
    print(f"✅ Exported scope: {response.json()}")
    
    # Import from file
    import_payload = {
        "action": "import_scope",
        "filepath": "my_custom_scope.json"
    }
    response = requests.post(API_URL, json=import_payload)
    print(f"✅ Imported scope: {response.json()}")


def example_8_get_scope_summary():
    """Example 8: Get current scope summary"""
    print("\n" + "=" * 70)
    print("Example 8: Get Current Scope Summary")
    print("=" * 70)
    
    payload = {"action": "get_scope"}
    response = requests.post(API_URL, json=payload)
    result = response.json()
    
    if result.get("success"):
        print("\n📊 Current Scope Summary:")
        summary = result.get("summary", {})
        print(json.dumps(summary, indent=2))


def example_9_custom_cloud_scope():
    """Example 9: Configure scope for cloud security audit"""
    print("\n" + "=" * 70)
    print("Example 9: Cloud Security Audit Scope (AWS/Azure/GCP)")
    print("=" * 70)
    
    payload = {
        "action": "set_scope",
        "advanced_scope": {
            "targets": {
                "domains": ["*.amazonaws.com", "*.azure.com"],
                "cloud_identifiers": {
                    "aws": {
                        "account_ids": ["123456789012"],
                        "regions": ["us-east-1", "us-west-2"],
                        "s3_buckets": ["my-public-bucket", "my-data-bucket"],
                        "cloudfront_distributions": ["E1234ABCD5678"]
                    },
                    "azure": {
                        "subscription_ids": ["xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"],
                        "resource_groups": ["production-rg", "staging-rg"]
                    },
                    "gcp": {
                        "project_ids": ["my-gcp-project"],
                        "zones": ["us-central1-a"]
                    }
                }
            },
            "vulnerability_testing": {
                "categories": {
                    "security_misconfiguration": True,
                    "broken_access_control": True,
                    "sensitive_data_exposure": True
                },
                "safe_mode": True
            },
            "testing_limits": {
                "max_requests_per_second": 5,
                "throttle_on_error": True
            },
            "compliance": {
                "standards": {
                    "pci_dss": True,
                    "hipaa": True,
                    "iso_27001": True
                }
            }
        }
    }
    
    response = requests.post(API_URL, json=payload)
    print(json.dumps(response.json(), indent=2))


def example_10_legacy_simple_scope():
    """Example 10: Use legacy simple scope (backward compatible)"""
    print("\n" + "=" * 70)
    print("Example 10: Legacy Simple Scope (Backward Compatible)")
    print("=" * 70)
    
    payload = {
        "action": "set_scope",
        "host": "example.com",
        "include_subdomains": True
    }
    
    response = requests.post(API_URL, json=payload)
    print(json.dumps(response.json(), indent=2))
    print("\n✅ Legacy scope still works for backward compatibility!")


def main():
    """Run all examples"""
    print("\n" + "🔥" * 35)
    print("🔥  HEXSTRIKE COMPREHENSIVE SCOPE EXAMPLES  🔥")
    print("🔥" * 35 + "\n")
    
    try:
        # Check if HexStrike server is running
        response = requests.get("http://127.0.0.1:8888/api/health", timeout=2)
        if response.status_code != 200:
            print("❌ Error: HexStrike server not responding")
            print("Please start the server first: python hexstrike_server.py")
            return
    except requests.exceptions.RequestException:
        print("❌ Error: Cannot connect to HexStrike server")
        print("Please start the server first: python hexstrike_server.py")
        return
    
    examples = [
        ("Bug Bounty Scope", example_1_bug_bounty_scope),
        ("Load Template", example_2_load_template),
        ("API Testing Scope", example_3_api_testing_scope),
        ("Internal Network Scope", example_4_internal_network_scope),
        ("Red Team Operation", example_5_red_team_operation),
        ("Validate URLs", example_6_validate_urls),
        ("Export/Import Scope", example_7_export_import_scope),
        ("Get Scope Summary", example_8_get_scope_summary),
        ("Cloud Security Audit", example_9_custom_cloud_scope),
        ("Legacy Simple Scope", example_10_legacy_simple_scope)
    ]
    
    print("\nAvailable Examples:")
    for i, (name, _) in enumerate(examples, 1):
        print(f"  {i}. {name}")
    
    print("\nSelect an example (1-10) or 'all' to run all examples:")
    choice = input("> ").strip().lower()
    
    if choice == "all":
        for name, func in examples:
            try:
                func()
            except Exception as e:
                print(f"❌ Error in {name}: {e}")
    else:
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(examples):
                name, func = examples[idx]
                func()
            else:
                print("❌ Invalid choice")
        except ValueError:
            print("❌ Invalid input")
    
    print("\n" + "🔥" * 35)
    print("✅ Examples completed!")
    print("🔥" * 35 + "\n")


if __name__ == "__main__":
    main()
