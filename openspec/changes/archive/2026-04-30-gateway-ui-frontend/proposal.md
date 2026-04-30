## Why

The go-gateway-auth-user backend exposes a complete admin API for tenant, user, and RBAC management, but there is no frontend to operate it. Administrators currently must use raw HTTP requests or scripts to manage tenants, users, roles, and permissions. A dedicated management UI will make the system usable for non-technical administrators and provide a clear operational interface for the two-tier admin model (SuperAdmin and TenantAdmin).

## What Changes

- Create a new frontend project in `gateway-UI/` from scratch using React + Vite + Ant Design 5
- Implement cookie-based JWT authentication (login/logout) against the existing backend auth endpoints
- Build a role-aware admin layout with two distinct experiences:
  - **SuperAdmin**: system-wide dashboard, tenant CRUD with domain management, dedicated tenant admin creation wizard
  - **TenantAdmin**: tenant-scoped dashboard, user CRUD with credential management, role CRUD with permission assignment, permission CRUD (resource/action paths), user-role assignment
- Global tenant selector in top bar for SuperAdmin; fixed tenant context for TenantAdmin
- Full i18n support with zh-CN and en-US locales using react-i18next
- Dashboard pages are blank placeholders (to be implemented later)
- All CRUD pages use Ant Design ProTable with server-side pagination, search, and modal-based create/edit forms

## Capabilities

### New Capabilities
- `ui-project-scaffold`: Vite + React + Ant Design project setup, routing, build configuration, and dev proxy to backend
- `ui-auth`: Login page, cookie-based JWT auth flow, logout, 401 redirect, auth context/state management
- `ui-layout`: Role-aware admin layout with sidebar navigation, top bar with tenant selector (SuperAdmin) or fixed tenant label (TenantAdmin), language switcher, user menu
- `ui-i18n`: Internationalization infrastructure with zh-CN and en-US locale files, language switching
- `ui-tenant-management`: SuperAdmin tenant list, create/edit/disable tenants, domain management sub-panel
- `ui-tenant-admin-wizard`: SuperAdmin dedicated flow to create a tenant admin account (select tenant → create user → assign tenant_admin role)
- `ui-user-management`: TenantAdmin user list with search, create/edit/disable users, credential management drawer
- `ui-role-management`: TenantAdmin role list, create/edit/delete roles, permission assignment via transfer component
- `ui-permission-management`: TenantAdmin permission list, create/edit/delete permissions with resource path and HTTP action fields
- `ui-user-role-assignment`: TenantAdmin page to view and assign roles to users within the tenant

### Modified Capabilities
(none — this is a new project, no existing backend specs are modified)

## Impact

- **New project**: `gateway-UI/` directory, entirely new codebase
- **Backend dependency**: Consumes existing admin API at `/admin/*` and auth endpoints at `/auth/*` — no backend changes required
- **Dev workflow**: Vite dev server will proxy API requests to the backend (configurable target)
- **Deployment**: Produces static files (`dist/`) that can be served by any web server or the gateway itself
- **Dependencies**: React 18+, Ant Design 5, react-router-dom 6, react-i18next, axios
