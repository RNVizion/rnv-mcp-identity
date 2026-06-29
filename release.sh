git add -A
git rm -r --cached --ignore-unmatch '__pycache__' '*.egg-info' bootstrap_scaffold.sh
git commit -s -m "Release v0.1.0: verified licenses, ruff + bandit SAST, CHANGELOG + NOTICE"
git tag -a v0.1.0 -m "v0.1.0: L1-L3 identity & authorization for MCP servers"
git push origin main --tags
