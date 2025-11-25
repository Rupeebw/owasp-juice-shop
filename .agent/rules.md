# Custom Rules and Guidance for Antigravity

## Purpose
This file contains custom rules, preferences, and guidance that Antigravity should follow when working in this workspace.

## General Guidelines

### Communication Style
- Be concise and to the point
- Use technical terminology appropriately
- Provide examples when explaining concepts

### Code Practices
- Follow existing code style in the repository
- Add comments for complex logic
- Prefer readability over cleverness

### DevSecOps Focus
- Security is a priority in all implementations
- Document security decisions and trade-offs
- Use industry-standard tools and practices

### Coding standards
- "Always use async/await instead of promises"
-  ALWAYS refer below documents while working on this application
   /docs/AWS_DEPLOYMENT_PLAN.txt
   /docs/AWS_DEPLOYMENT_PLAN_ECS.txt
   /docs/ChangeLog.txt
   /docs/DEVSECOPS_TRAINING_WITH_JUICE_SHOP.txt
   /docs/Deploy-App-2-K8s-Cluster.txt
   /docs/FRONTEND_BACKEND_DATABASE_FLOW.txt
   /docs/GIT_WORKFLOW_SLASH_COMMAND_MANUAL.txt
   /docs/LOCALSTACK_DEPLOYMENT_GUIDE.txt
   /docs/devsecops-practice-summary.txt
   /docs/juice-shop-app.txt
   /docs/security-scan/security-scan-tools.txt
- Don't assume or take change on your own, always ask for permission

### Security policies
- "dont delete any existing file or code"

### Documentation
- ALWAYS write the new document in txt format , follow
  ✓ TXT format
  ✓ TL;DR at the top
  ✓ In /docs directory
  ✓ Skim-able layout
  ✓ LIMITED to 200 lines (max 500-600 based on use-case)
  ✓ MINIMAL decoration, use under the heading "=====" - No heavy borders, just clean headings
- Don't create README.md file until asked by the user
- Once testing is complete , update /docs/ChangeLog.txt

### Tool preferences
- "Use npm instead of yarn"

### Workflow
- "Always create a branch before making changes" but ask before creating a branch

### Git Commit Guidelines

- MUST NOT include code signature and co-author attribution in commit messages for this repository.
- write commit message related to changes made


## Project-Specific Rules

### OWASP Juice Shop Context
- This is an intentionally vulnerable application for training
- Security findings are EXPECTED and should not be "fixed" unless explicitly requested
- Focus on DevSecOps pipeline implementation, not fixing vulnerabilities

### Pipeline Development
- Use warning mode (`continue-on-error: true`) for security scans in training environment
- Document all tools and their purposes
- Maintain the dual-path approach (Kubernetes and AWS ECS)

### Documentation Standards
- Keep documentation up-to-date with code changes
- Use clear, structured formats (like the security-scan-tools.txt format)
- Include examples and use cases
- Maintain changelog for significant updates

## Custom Preferences

### Tool Selection
- Prefer open-source tools when possible
- Use Docker-based tools for portability
- Choose tools with good GitHub Actions integration

### File Organization
- Keep related documentation together
- Use descriptive file names
- Maintain clear directory structure

---

**Note**: You can edit this file at any time to add or modify rules. Antigravity will read these rules at the start of each conversation.
