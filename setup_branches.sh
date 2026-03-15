#!/bin/bash
# ─────────────────────────────────────────────────────────────────
# setup_branches.sh — One-time setup script
# Run this ONCE after your first push to main.
# It creates all 4 CI branches and pushes them to GitHub.
# ─────────────────────────────────────────────────────────────────

echo "================================================"
echo "  Keyfactor Lab — Branch Setup Script"
echo "================================================"

# Make sure we start from main so all branches stem from the same base
git checkout main

# ── CREATE ci/macos BRANCH ──────────────────────────────────────
echo ""
echo "Creating ci/macos branch..."
# -b creates a new branch named ci/macos from the current position (main)
git checkout -b ci/macos
# Push this branch to GitHub and set it to track the remote branch
git push -u origin ci/macos
echo "  ci/macos created and pushed ✓"

# ── CREATE ci/windows BRANCH ────────────────────────────────────
echo ""
echo "Creating ci/windows branch..."
# Go back to main first so ci/windows also starts from main
git checkout main
git checkout -b ci/windows
git push -u origin ci/windows
echo "  ci/windows created and pushed ✓"

# ── CREATE ci/linux BRANCH ──────────────────────────────────────
echo ""
echo "Creating ci/linux branch..."
git checkout main
git checkout -b ci/linux
git push -u origin ci/linux
echo "  ci/linux created and pushed ✓"

# ── CREATE ci/all-platforms BRANCH ──────────────────────────────
echo ""
echo "Creating ci/all-platforms branch..."
git checkout main
git checkout -b ci/all-platforms
git push -u origin ci/all-platforms
echo "  ci/all-platforms created and pushed ✓"

# ── RETURN TO MAIN ──────────────────────────────────────────────
git checkout main

echo ""
echo "================================================"
echo "  All branches created successfully!"
echo ""
echo "  Branch → Workflow triggered"
echo "  ci/macos        → macos.yml"
echo "  ci/windows      → windows.yml"
echo "  ci/linux        → linux.yml"
echo "  ci/all-platforms → all_platforms.yml"
echo "  main            → all_platforms.yml"
echo "================================================"