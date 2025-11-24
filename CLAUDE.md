# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OWASP Juice Shop is an intentionally insecure web application designed for security training, awareness demos, CTFs, and as a test platform for security tools. It contains vulnerabilities from the OWASP Top Ten and other real-world security flaws.

**Important**: This is an intentionally vulnerable application. Do not suggest "fixing" security vulnerabilities unless explicitly requested, as they are features, not bugs. The vulnerabilities are educational tools.

## Documents To Refer

ALWAYS refer below documents while working on this application

1. /docs/AWS_DEPLOYMENT_PLAN.txt
2. /docs/AWS_DEPLOYMENT_PLAN_ECS.txt
3. /docs/DEVSECOPS_TRAINING_WITH_JUICE_SHOP.txt
4. /docs/FRONTEND_BACKEND_DATABASE_FLOW.txt
5. /docs/GIT_WORKFLOW_SLASH_COMMAND_MANUAL.txt
6. /docs/LOCALSTACK_DEPLOYMENT_GUIDE.txt
7. /docs/LocalStack/localStack-Setup.txt
8. /docs/LocalStack/localStack-Slash.txt
9. /docs/devsecops-practice-summary.txt

## Git Commit Guidelines

- Rule: I must NOT include the Claude Code signature and co-author attribution in commit messages for this repository.

## Documentation Guidelines

- ALWAYS write the new document in txt format , follow
  ✓ TXT format
  ✓ TL;DR at the top
  ✓ In /docs directory
  ✓ Skim-able layout
  ✓ LIMITED to 200 lines (max 500-600 based on use-case)
  ✓ MINIMAL decoration, use under the heading "=====" - No heavy borders, just clean headings
- Don't create README.md file until asked by the user

## Create Session Reports Guidelines

1. Recap what was accomplished
2. Provide quick reference (TL;DR at top)
3. Document decisions made
4. Show next steps
5. Give you a shareable artifact

### Individual Session Reports

Location: /docs/Summary/{topicName}-summary.txt

Examples:

- /docs/Summary/{training-update-summary.txt
- /docs/Summary/{simple-pipeline-setup-summary.txt
- /docs/Summary/{devsecops-practice-summary.txt

Structure:

```
================================================================================
TITLE
================================================================================

TL;DR
=====
Brief summary...

KEY SECTIONS
============
Details...

NEXT STEPS
==========
What to do next...

================================================================================
END OF SUMMARY
================================================================================
```

### Consolidated ChangeLog

Location: /docs/ChangeLog.txt

Purpose: Single source of truth for all training preparation work

Structure:

- Quick View Table at top (Done/Pending status for each topic)
- Most recent entries first (reverse chronological)
- Each session report as a section
- Overall progress summary at bottom

The ChangeLog consolidates all individual session reports into one master
document, making it easy to track overall progress and reference past work.

## Technology Stack

### Backend

- **Runtime**: Node.js (versions 20-24 supported)
- **Framework**: Express.js
- **Language**: TypeScript
- **Database**: SQLite (via Sequelize ORM)
- **API**: RESTful endpoints with finale-rest for auto-generated CRUD

### Frontend

- **Framework**: Angular 20
- **Language**: TypeScript
- **UI Library**: Angular Material
- **Build Tool**: Angular CLI with custom webpack config

## Common Commands

### Development

```bash
npm install              # Install all dependencies (backend + frontend)
npm start                # Start production build (port 3000)
npm run serve            # Start backend + frontend in dev mode concurrently
npm run serve:dev        # Start with ts-node-dev for auto-reload
```

### Building

```bash
npm run build:frontend   # Build Angular frontend
npm run build:server     # Compile TypeScript backend to build/
```

### Testing

```bash
npm test                 # Run frontend unit tests + backend server tests
npm run test:server      # Run backend Mocha tests only
npm run test:api         # Run API integration tests (Frisby/Jest)
npm run frisby           # Run API tests with coverage
npm run cypress:open     # Open Cypress for e2e tests
npm run cypress:run      # Run Cypress headless
npm run test:chromium    # Run frontend tests in headless Chromium
```

### Linting

```bash
npm run lint             # Lint backend TypeScript + frontend code
npm run lint:fix         # Auto-fix linting issues
npm run lint:config      # Validate config.schema.yml
```

### Frontend Development

```bash
cd frontend
npm run start            # Serve frontend on port 4200
npm run build            # Production build
npm test                 # Run Karma/Jasmine tests
npm run lint             # Lint TypeScript
npm run lint:scss        # Lint SCSS files
```

## Architecture

### Backend Structure

**Entry Points**:

- `app.ts` - Application bootstrap
- `server.ts` - Main server setup with Express middleware configuration

**Core Directories**:

- `routes/` - 60+ API route handlers (e.g., `routes/login.ts`, `routes/basket.ts`)
- `models/` - Sequelize model definitions (User, Product, Basket, Challenge, etc.)
- `lib/` - Utilities and core logic:
  - `lib/insecurity.ts` - Authentication/crypto utilities (intentionally weak)
  - `lib/utils.ts` - General helper functions
  - `lib/challengeUtils.ts` - Challenge solving/tracking logic
  - `lib/antiCheat.ts` - Anti-cheat detection for CTF mode
  - `lib/startup/` - Application initialization modules
- `data/` - Static data and database initialization:
  - `data/datacreator.ts` - Populates database with initial data
  - `data/static/` - JSON files with products, users, challenges

**Database**:

- SQLite database stored at `data/juiceshop.sqlite`
- Initialized via Sequelize with models in `models/index.ts`
- Uses `sequelize.sync()` during startup

**Configuration**:

- Uses `config` package with YAML files in `config/`
- `config/default.yml` - Base configuration
- `config.schema.yml` - Schema validation
- Customizable via environment-specific configs (e.g., `config/test.yml`)

### Frontend Structure

**Location**: `frontend/src/`

**Key Directories**:

- `frontend/src/app/` - Angular components, services, guards
  - Component-based architecture with lazy loading
  - Services for API communication (e.g., `UserService`, `BasketService`)
  - Guards for authentication and route protection
- `frontend/src/assets/` - Static assets (images, i18n translations)
- `frontend/src/environments/` - Environment-specific configs

**Build Output**: `frontend/dist/frontend/` (served by backend in production)

### API Architecture

**Pattern**: RESTful endpoints mounted on Express router

**Auto-generated REST**:

- Uses `finale-rest` to auto-generate CRUD endpoints for Sequelize models
- Custom routes in `routes/` for business logic

**Authentication**:

- JWT tokens (intentionally using old/vulnerable `jsonwebtoken` 0.4.0)
- Tokens handled via `express-jwt` middleware
- Session management through cookies

**Common Route Patterns**:

- `/rest/user/login` - Authentication
- `/api/Products` - Product catalog
- `/api/BasketItems` - Shopping cart operations
- `/rest/admin/*` - Admin endpoints
- `/api/Challenges` - Challenge tracking

## Testing Strategy

### Backend Tests

- **Server Tests**: `test/server/` - Mocha/Chai unit tests
- **API Tests**: `test/api/` - Frisby integration tests (via Jest)
- **Coverage**: nyc for code coverage reports

### Frontend Tests

- **Unit Tests**: Karma + Jasmine (`*.spec.ts` files alongside components)
- **E2E Tests**: Cypress (`test/cypress/`)

### Running Individual Tests

```bash
# Single API test file
npm run frisby -- test/api/someSpec.ts

# Single server test
npx mocha -r ts-node/register test/server/someTest.ts

# Frontend single spec
cd frontend && ng test --include='**/component.spec.ts'
```

## Key Files

- `server.ts` - Main application server with all middleware setup
- `models/index.ts` - Database initialization and Sequelize setup
- `data/datacreator.ts` - Database seeding logic
- `lib/insecurity.ts` - Core authentication/security functions (intentionally vulnerable)
- `lib/challengeUtils.ts` - Challenge tracking and solving logic
- `package.json` - Root dependencies and npm scripts
- `frontend/package.json` - Frontend dependencies and Angular CLI scripts

## Security Context

This application intentionally contains:

- SQL injection vulnerabilities
- XSS vulnerabilities
- Authentication bypasses
- Broken access control
- Insecure cryptography
- And 100+ other security challenges

**When working on this codebase**: Do not suggest security fixes unless the user explicitly asks to patch a specific vulnerability. The vulnerabilities are the core feature set for training purposes.

## Configuration & Customization

The application supports extensive customization through `config/*.yml`:

- Application name, logo, theme
- Challenge difficulty and hints
- CTF settings and scoring
- Feature flags
- Security headers (intentionally misconfigured)

See `config.schema.yml` for all available options.

## Docker & Deployment

### Docker Image

The application uses a **multi-stage Docker build** that produces a complete, ready-to-run image:

**Stage 1 (installer)**: Node.js 22 base image

- Copies source code
- Runs `npm install --omit=dev` (automatically builds frontend via postinstall hook)
- Compiles TypeScript backend to `build/`
- Cleans up unnecessary files (node_modules, build artifacts)
- Generates SBOM (Software Bill of Materials)

**Stage 2 (final)**: Distroless Node.js 22 image

- Minimal, secure base image
- Copies built application from stage 1
- Runs pre-compiled app at `/juice-shop/build/app.js`
- Exposes port 3000

### Running with Docker

**Option 1: Pull pre-built image (recommended for quick start)**

```bash
docker pull bkimminich/juice-shop
docker run -p 3000:3000 bkimminich/juice-shop
```

The pre-built image contains everything - **no npm commands needed**.

**Option 2: Build locally**

```bash
docker build -t juice-shop .
docker run -p 3000:3000 juice-shop
```

**Option 3: Docker Compose with smoke tests**

```bash
docker-compose -f docker-compose.test.yml up --build --abort-on-container-exit
```

This runs automated smoke tests that verify:

- Main page loads correctly
- API endpoints respond
- Angular bundle is present
- Challenge endpoints work

## Run Juice Shop normally (not just tests):

  Option 1: Using the pre-built image (quick start)
  docker run -p 3000:3000 bkimminich/juice-shop

  Option 2: Using the locally built image
  docker run -p 3000:3000 owasp-juice-shop-app

  Then visit http://localhost:3000 in your browser to access the application!

### Smoke Testing

The `docker-compose.test.yml` sets up a test environment with:

- **app service**: Juice Shop container
- **sut service**: Lightweight Alpine container that runs `test/smoke/smoke-test.sh`

The smoke test performs 4 basic health checks via curl and exits with success/failure status.

### Other Deployment Options

**Packaged distributions** (node binary + app):

```bash
npm run package  # Creates .zip/.tgz for Windows/macOS/Linux
```

**Vagrant**:

```bash
cd vagrant && vagrant up
# Access at http://192.168.56.110
```

## Additional Resources

- Official Documentation: https://pwning.owasp-juice.shop
- GitHub Issues: https://github.com/juice-shop/juice-shop/issues
- CTF Extension: https://github.com/juice-shop/juice-shop-ctf
- add to memory "Documentation Guidelines" ALWAYS write the new document in txt format , follow TL;DR , and write in directory /docs ONLY
