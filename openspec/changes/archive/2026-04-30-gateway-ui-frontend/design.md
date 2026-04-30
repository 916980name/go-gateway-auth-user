## Context

The go-gateway-auth-user backend provides a complete REST admin API for multi-tenant user and RBAC management (tenants, users, credentials, roles, permissions, user-role assignments). It uses JWT cookie-based auth, Casbin RBAC enforcement, UUID-based resource identifiers, and server-side pagination. There is no frontend — the `gateway-UI/` directory is empty.

Two admin roles exist:
- **SuperAdmin** (in the `__system__` tenant): manages tenants and creates tenant administrators
- **TenantAdmin** (per tenant): manages users, roles, permissions, and assignments within their tenant

## Goals / Non-Goals

**Goals:**
- Provide a production-ready admin UI that covers all existing admin API capabilities
- Clear role separation: SuperAdmin and TenantAdmin see different navigation and pages
- i18n from day one (zh-CN + en-US), extensible to more locales
- Standard CRUD patterns: table with pagination/search, modal create/edit, confirmation on delete
- Cookie-based auth with automatic 401 → login redirect

**Non-Goals:**
- Dashboard analytics/charts (blank placeholder only — implemented later)
- Real-time updates (WebSocket, SSE)
- Mobile-responsive design (admin tool, desktop-first)
- User self-service (profile editing, password change) — this is an admin console
- End-to-end testing or Storybook setup in initial delivery
- Custom theming or white-labeling

## Decisions

### 1. Project Tooling: Vite + React 18 + TypeScript

**Choice**: Vite as bundler, React 18 with TypeScript, Ant Design 5 as component library.

**Why**: Vite provides fast HMR for development and optimized production builds. Ant Design 5 has purpose-built admin components (Table with server-side pagination, Form with validation, Modal, Transfer, Steps) that directly map to the CRUD patterns needed. TypeScript ensures API response types match backend contracts.

**Alternatives considered**:
- Vue 3 + Element Plus: equally viable, but user explicitly chose React
- Next.js: SSR unnecessary for an admin panel behind auth

### 2. State Management: React Context (no Redux)

**Choice**: Use React Context for two pieces of global state: (1) auth state (current user, role, tenant list), (2) active tenant selection. All other state is local to pages.

**Why**: The app has minimal cross-cutting state. Each CRUD page is self-contained with its own data fetching. Adding Redux/Zustand would be overhead with no benefit. Auth context is read on every route for guards and layout rendering.

**Alternatives considered**:
- Zustand: lightweight but still an extra dependency for ~2 context values
- Redux Toolkit: too heavy for this scope

### 3. Routing: react-router-dom v6 with Role Guards

**Choice**: Flat route structure with a `<RoleGuard>` wrapper component that checks the user's role and redirects unauthorized access.

```
/login                          (public)
/dashboard                      (both roles)
/tenants                        (SuperAdmin)
/tenants/:id/domains            (SuperAdmin)
/tenant-admins                  (SuperAdmin)
/tenant-admins/create           (SuperAdmin)
/users                          (TenantAdmin)
/users/:id/credentials          (TenantAdmin)
/roles                          (TenantAdmin)
/roles/:id/permissions          (TenantAdmin)
/permissions                    (TenantAdmin)
/user-roles                     (TenantAdmin)
```

**Why**: Flat routes are simple to reason about. The `<RoleGuard>` pattern keeps authorization logic in one place rather than scattered across pages.

### 4. API Client: Axios with Interceptors

**Choice**: Single axios instance configured with `withCredentials: true` (cookies auto-sent), a response interceptor that catches 401 and redirects to `/login`, and typed request/response wrappers.

```typescript
interface PaginatedResponse<T> {
  data: T[];
  pagination: { page: number; pageSize: number; total: number };
}

interface ApiError {
  error: { code: string; message: string };
}
```

**Why**: The backend sends JWT in `Set-Cookie` with `HttpOnly` — the browser handles cookie storage and transmission automatically. Axios interceptors centralize error handling (401 redirect, error message extraction). Typed wrappers ensure frontend/backend contract alignment.

**Alternatives considered**:
- fetch API: works fine, but axios provides interceptors and request cancellation out of the box
- React Query / SWR: could be added later for caching, but simple `useEffect` + `useState` is sufficient for CRUD pages that always fetch fresh data

### 5. Auth Flow: Cookie-Based with `/auth/login`

**Choice**:
1. Login page sends `POST /auth/login` with `{provider: "password", identifier, credential}`
2. Backend responds with `Set-Cookie: Authorization=<JWT>; HttpOnly; Path=/`
3. Frontend stores user info (decoded from a non-HttpOnly info cookie or a `/me` endpoint) in AuthContext
4. Subsequent requests auto-include the cookie
5. Logout calls `POST /auth/logout`, backend clears the cookie
6. 401 response → clear AuthContext → redirect to `/login`

**Why**: Cookie-based auth is simpler for the frontend (no token storage, no `Authorization` header management). The backend already supports `cookieEnabled: true` and sets cookies on login.

**Open detail**: The JWT is HttpOnly so JavaScript can't decode it. We need a way to know the current user's username and role. Options:
- Backend sets a second non-HttpOnly cookie with user info (needs backend support)
- Backend provides a `GET /auth/me` endpoint (needs backend support)
- Login response body includes user info (current: body only has `{message: "login successful"}`)

**Decision**: Add user info (username, roles, tenants) to the login response body. This is a minimal backend change — the handler already has this data from the authentication step.

### 6. Role Detection and Tenant Context

**Choice**: After login, the frontend receives user info including the user's role assignments across tenants. The logic:

```
if user has system_admin role in __system__ tenant:
  → SuperAdmin mode: show tenant selector, SuperAdmin navigation
else:
  → TenantAdmin mode: fix tenant context to user's tenant, show TenantAdmin navigation
```

The active tenant UUID is stored in AuthContext and passed to all API calls as a path parameter.

**Why**: The backend already scopes all RBAC APIs by tenant UUID in the path (`/admin/tenants/:tenantId/...`). The frontend just needs to know which tenant to use.

### 7. i18n: react-i18next with Namespace Files

**Choice**: react-i18next with JSON namespace files per domain:

```
locales/zh-CN/common.json    — shared UI text (buttons, pagination, errors)
locales/zh-CN/menu.json      — sidebar and navigation labels
locales/zh-CN/tenant.json    — tenant management page
locales/zh-CN/user.json      — user management page
locales/zh-CN/role.json      — role management page
locales/zh-CN/permission.json — permission management page
locales/en-US/...            — same structure
```

Language preference stored in `localStorage`, switchable via top-bar toggle.

**Why**: Namespace-per-page keeps translation files small and organized. react-i18next is the standard React i18n library with excellent Ant Design integration.

### 8. Dev Proxy: Vite Proxy to Backend

**Choice**: Vite dev server proxies `/auth/*` and `/admin/*` to the backend at `http://localhost:8989` (configurable).

```typescript
// vite.config.ts
server: {
  proxy: {
    '/auth': 'http://localhost:8989',
    '/admin': 'http://localhost:8989',
  }
}
```

**Why**: Avoids CORS issues in development. In production, the gateway can serve the static files directly or use a reverse proxy.

### 9. CRUD Page Pattern

All CRUD pages follow the same pattern to maintain consistency:

```
┌─ Page Component ──────────────────────────────────┐
│  useTableData(apiCall, pagination) — custom hook  │
│                                                    │
│  ┌─ Toolbar ────────────────────────────────────┐ │
│  │ [Search input]              [+ Create button] │ │
│  └───────────────────────────────────────────────┘ │
│                                                    │
│  ┌─ Ant Design Table ──────────────────────────┐  │
│  │ Columns with sorters                         │  │
│  │ Row actions: Edit | Delete (with Popconfirm) │  │
│  │ Server-side pagination                       │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
│  ┌─ Modal (Create/Edit) ───────────────────────┐  │
│  │ Ant Design Form with validation              │  │
│  │ Reused for both create and edit              │  │
│  └──────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────┘
```

A shared `useTableData` hook handles: fetching, pagination state, search debounce, loading state, and refresh-after-mutation.

## Risks / Trade-offs

**[Risk] Login response doesn't include user info** → Mitigation: Requires a small backend change to include username + role/tenant data in the login response body. This is the only backend change needed. If unacceptable, we can add a `GET /auth/me` endpoint instead.

**[Risk] SuperAdmin role detection depends on knowing `__system__` tenant code** → Mitigation: The `__system__` tenant code is a well-known constant defined in the backend seed. Hardcoding it in the frontend config is acceptable since it never changes.

**[Risk] No automated tests in initial delivery** → Mitigation: The CRUD page pattern is repetitive and well-understood. Manual testing against the running backend is the primary verification method. Test infrastructure can be added in a follow-up change.

**[Trade-off] No data caching (React Query)** → Accepted: Each page fetches fresh data on mount. For an admin tool with low traffic, this is fine. Caching can be added later if needed.

**[Trade-off] Ant Design bundle size** → Accepted: Vite tree-shakes Ant Design 5 effectively. Admin tools are not performance-critical for initial load.
