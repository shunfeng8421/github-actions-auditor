"""Discover high-quality repos with GitHub Actions workflows on GitHub."""
import json
import os
import sys
import time
import argparse
import requests
from datetime import datetime

GITHUB_API = "https://api.github.com"

def search_repos(token, min_stars, max_results=100):
    """Search GitHub for active repos likely to have workflows."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    all_repos = []
    seen = set()

    # Broad language search for active repos
    languages = ["TypeScript", "Python", "JavaScript", "Go", "Rust", "Java", "Ruby", "C#", "PHP", "Shell"]
    for lang in languages:
        if len(all_repos) >= max_results:
            break

        query = f"language:{lang} stars:>={min_stars} pushed:>2024-01-01"
        page = 1
        while len(all_repos) < max_results:
            params = {
                "q": query,
                "sort": "stars",
                "order": "desc",
                "per_page": min(20, max_results - len(all_repos)),
                "page": page
            }

            try:
                resp = requests.get(f"{GITHUB_API}/search/repositories",
                                   headers=headers, params=params, timeout=30)
                if resp.status_code == 403:
                    print(f"Rate limited, waiting 60s...")
                    time.sleep(60)
                    continue
                if resp.status_code == 422:
                    break
                resp.raise_for_status()
                data = resp.json()
                items = data.get("items", [])

                if not items:
                    break

                for repo in items:
                    rid = repo["full_name"]
                    if rid not in seen:
                        seen.add(rid)
                        all_repos.append({
                            "full_name": rid,
                            "url": repo["html_url"],
                            "clone_url": repo["clone_url"],
                            "stars": repo["stargazers_count"],
                            "language": repo["language"],
                            "topics": repo.get("topics", []),
                            "description": repo.get("description", ""),
                            "default_branch": repo["default_branch"],
                            "has_workflows": False,
                            "discovered_at": datetime.utcnow().isoformat() + "Z"
                        })

                page += 1
                time.sleep(2)

            except requests.exceptions.RequestException as e:
                print(f"Search error for {lang}: {e}", file=sys.stderr)
                break

    return all_repos[:max_results]

def check_workflows_exist(token, repos):
    """Verify which repos actually have .github/workflows/*.yml files."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    count = 0
    for repo in repos:
        try:
            url = f"{GITHUB_API}/repos/{repo['full_name']}/contents/.github/workflows"
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                contents = resp.json()
                yml_files = [f["name"] for f in contents if f["name"].endswith((".yml", ".yaml"))]
                if yml_files:
                    repo["has_workflows"] = True
                    repo["workflow_files"] = yml_files
                    repo["workflow_count"] = len(yml_files)
                    count += 1
            time.sleep(1)
        except Exception as e:
            print(f"  Error checking {repo['full_name']}: {e}", file=sys.stderr)

    print(f"  Verified {count}/{len(repos)} repos have workflows")
    return repos

def search_workflow_repos_direct(token, min_stars, max_results=100):
    """Directly search for repos with .github/workflows path using code search."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    all_repos = {}
    seen = set()

    # Search for common patterns in workflow files
    patterns = [
        "filename:.github/workflows",
        "uses: actions/checkout path:.github/workflows",
    ]

    for pattern in patterns:
        query = f"{pattern} stars:>={min_stars}"
        page = 1
        while page <= 3 and len(all_repos) < max_results:
            params = {
                "q": query,
                "sort": "stars",
                "order": "desc",
                "per_page": min(30, max_results),
                "page": page
            }

            try:
                resp = requests.get(f"{GITHUB_API}/search/code",
                                   headers=headers, params=params, timeout=30)
                if resp.status_code == 403:
                    print("Code search rate limited, waiting...")
                    time.sleep(60)
                    continue
                if resp.status_code != 200:
                    break
                data = resp.json()

                for item in data.get("items", []):
                    repo_info = item.get("repository", {})
                    full_name = repo_info.get("full_name", "")
                    if full_name and full_name not in seen:
                        seen.add(full_name)
                        all_repos[full_name] = {
                            "full_name": full_name,
                            "url": repo_info.get("html_url", ""),
                            "clone_url": repo_info.get("clone_url", ""),
                            "stars": repo_info.get("stargazers_count", 0),
                            "language": repo_info.get("language", ""),
                            "description": repo_info.get("description", ""),
                            "default_branch": repo_info.get("default_branch", "main"),
                            "has_workflows": True,
                            "workflow_file_sample": item.get("path", ""),
                            "discovered_at": datetime.utcnow().isoformat() + "Z"
                        }

                page += 1
                time.sleep(3)

            except Exception as e:
                print(f"Code search error: {e}", file=sys.stderr)
                break

    return list(all_repos.values())[:max_results]

def main():
    parser = argparse.ArgumentParser(description="Discover repos with GitHub Actions workflows")
    parser.add_argument("--min-stars", type=int, default=50)
    parser.add_argument("--max-repos", type=int, default=100)
    parser.add_argument("--output", default="auditor/logs/discovered_repos.jsonl")
    parser.add_argument("--state", default="auditor/logs/discover_state.json")
    parser.add_argument("--verify", action="store_true", help="Verify workflows exist via API")
    parser.add_argument("--direct", action="store_true", help="Use code search to find workflow repos directly")
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("ERROR: GITHUB_TOKEN not set", file=sys.stderr)
        sys.exit(1)

    # Load previous state
    seen_repos = set()
    if os.path.exists(args.state):
        with open(args.state, "r", encoding="utf-8") as f:
            state = json.load(f)
            seen_repos = set(state.get("seen_repos", []))

    # Search
    if args.direct:
        print("Searching GitHub via code search for workflow files...")
        repos = search_workflow_repos_direct(token, args.min_stars, args.max_repos)
    else:
        print(f"Searching GitHub for active repos (stars >= {args.min_stars})...")
        repos = search_repos(token, args.min_stars, args.max_repos)
        if args.verify:
            print("Verifying workflow existence...")
            repos = check_workflows_exist(token, repos)

    # Filter new
    new_repos = []
    for repo in repos:
        name = repo["full_name"]
        if name not in seen_repos:
            new_repos.append(repo)
            seen_repos.add(name)

    # Write output
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "a", encoding="utf-8") as f:
        for repo in new_repos:
            f.write(json.dumps(repo, ensure_ascii=False) + "\n")

    # Update state
    with open(args.state, "w", encoding="utf-8") as f:
        json.dump({
            "seen_repos": list(seen_repos),
            "last_run": datetime.utcnow().isoformat() + "Z",
            "total_discovered": len(seen_repos)
        }, f)

    workflow_count = sum(1 for r in new_repos if r.get("has_workflows"))
    print(f"Found {len(new_repos)} new repos ({workflow_count} with workflows, total tracked: {len(seen_repos)})")

    # Set output for GitHub Actions
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"new_repos={len(new_repos)}\n")
            f.write(f"workflow_repos={workflow_count}\n")

if __name__ == "__main__":
    main()
