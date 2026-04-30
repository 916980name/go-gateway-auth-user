## ADDED Requirements

### Requirement: Vite React TypeScript project initialization
The project SHALL be initialized in `gateway-UI/` as a Vite + React 18 + TypeScript application with Ant Design 5, react-router-dom v6, axios, and react-i18next as core dependencies.

#### Scenario: Project builds successfully
- **WHEN** `npm run build` is executed in `gateway-UI/`
- **THEN** the build SHALL succeed and produce static assets in `gateway-UI/dist/`

#### Scenario: Dev server starts with HMR
- **WHEN** `npm run dev` is executed in `gateway-UI/`
- **THEN** a Vite dev server SHALL start with hot module replacement enabled

### Requirement: API proxy in development
The Vite dev server SHALL proxy requests matching `/auth/*` and `/admin/*` to the backend server (default `http://localhost:8989`).

#### Scenario: API requests are proxied
- **WHEN** the dev server is running and the browser makes a request to `/auth/login`
- **THEN** the request SHALL be proxied to `http://localhost:8989/auth/login` without CORS errors

#### Scenario: Proxy target is configurable
- **WHEN** the developer sets `VITE_API_BASE` environment variable to `http://localhost:9090`
- **THEN** the proxy SHALL forward API requests to port 9090 instead of the default

### Requirement: Project directory structure
The project SHALL follow a standard directory layout with clear separation of concerns.

#### Scenario: Source structure exists
- **WHEN** the project is initialized
- **THEN** the following directories SHALL exist: `src/api/`, `src/components/`, `src/layouts/`, `src/locales/`, `src/pages/`, `src/store/`, `src/utils/`, `src/types/`

### Requirement: TypeScript strict mode
The project SHALL use TypeScript in strict mode with no implicit any.

#### Scenario: Type errors are caught at build time
- **WHEN** a variable is used without a type annotation and the type cannot be inferred
- **THEN** the TypeScript compiler SHALL report an error

### Requirement: Production build outputs static files
The production build SHALL output static HTML, CSS, and JS files suitable for deployment behind any web server.

#### Scenario: Build output is self-contained
- **WHEN** `npm run build` completes
- **THEN** the `dist/` directory SHALL contain an `index.html` and hashed asset files that can be served statically
