## 1. Project Scaffold

- [x] 1.1 Initialize Vite + React 18 + TypeScript project in `gateway-UI/` with `npm create vite@latest`
- [x] 1.2 Install core dependencies: antd, @ant-design/icons, react-router-dom, axios, react-i18next, i18next
- [x] 1.3 Configure TypeScript strict mode in `tsconfig.json`
- [x] 1.4 Configure Vite dev proxy for `/auth/*` and `/admin/*` to `http://localhost:8989` in `vite.config.ts`
- [x] 1.5 Create directory structure: `src/api/`, `src/components/`, `src/layouts/`, `src/locales/`, `src/pages/`, `src/store/`, `src/utils/`, `src/types/`
- [x] 1.6 Verify `npm run dev` and `npm run build` both succeed

## 2. i18n Infrastructure

- [x] 2.1 Configure react-i18next with namespace-based JSON files and `zh-CN` as default language
- [x] 2.2 Create locale file structure: `src/locales/zh-CN/{common,menu,tenant,user,role,permission}.json` and `src/locales/en-US/` with same structure
- [x] 2.3 Write zh-CN and en-US translations for `common.json` (buttons: create, edit, delete, save, cancel, confirm, search; pagination; error messages; status labels)
- [x] 2.4 Write zh-CN and en-US translations for `menu.json` (sidebar items: dashboard, tenant management, tenant admin, user management, role management, permission management, user-role assignment)
- [x] 2.5 Configure Ant Design ConfigProvider locale integration (zhCN / enUS) synced with i18next language

## 3. API Client and Types

- [x] 3.1 Create TypeScript type definitions in `src/types/`: User, Tenant, TenantDomain, Role, Permission, UserRole, UserCredential, PaginatedResponse, ApiError, LoginRequest, LoginResponse
- [x] 3.2 Create axios instance in `src/api/client.ts` with `withCredentials: true` and 401 response interceptor that redirects to `/login`
- [x] 3.3 Create API modules: `src/api/auth.ts` (login, logout), `src/api/tenant.ts` (CRUD + domains), `src/api/user.ts` (CRUD + credentials), `src/api/role.ts` (CRUD + permission assignment), `src/api/permission.ts` (CRUD), `src/api/userRole.ts` (get/set roles)

## 4. Auth and Store

- [x] 4.1 Create AuthContext in `src/store/AuthContext.tsx` with state: currentUser, isSuperAdmin, tenantList, activeTenantId, login/logout actions
- [x] 4.2 Implement login flow: call `POST /auth/login`, parse response for user info (username, roles, tenants), determine SuperAdmin vs TenantAdmin, store in context
- [x] 4.3 Implement logout flow: call `POST /auth/logout`, clear context, redirect to `/login`
- [x] 4.4 Create `<AuthGuard>` component that redirects unauthenticated users to `/login`
- [x] 4.5 Create `<RoleGuard role="superadmin|tenantadmin">` component that redirects unauthorized role access to `/dashboard`

## 5. Layout and Routing

- [x] 5.1 Create `<AdminLayout>` in `src/layouts/AdminLayout.tsx` with Ant Design Layout (Sider + Header + Content)
- [x] 5.2 Implement collapsible sidebar with role-based menu items (SuperAdmin: dashboard, tenants, tenant-admins; TenantAdmin: dashboard, users, roles, permissions, user-roles)
- [x] 5.3 Implement top bar: tenant selector dropdown (SuperAdmin) or fixed tenant label (TenantAdmin), language switcher (zh-CN/en-US toggle), user menu dropdown (username + logout)
- [x] 5.4 Create `<AuthLayout>` in `src/layouts/AuthLayout.tsx` for the login page (centered card layout)
- [x] 5.5 Set up react-router-dom routes in `src/App.tsx` with AuthGuard and RoleGuard wrappers for all pages
- [x] 5.6 Create blank `<Dashboard>` placeholder page at `/dashboard`

## 6. Login Page

- [x] 6.1 Create login page at `src/pages/login/index.tsx` with Ant Design Form (username, password, submit button)
- [x] 6.2 Add form validation (required fields), error display on failed login, loading state on submit
- [x] 6.3 Write zh-CN and en-US translations for login page text
- [x] 6.4 Add language switcher to login page (top-right corner)

## 7. Tenant Management (SuperAdmin)

- [x] 7.1 Create tenant list page at `src/pages/tenants/index.tsx` with Ant Design Table, server-side pagination, columns: Name, Code, Status, Created At, Actions
- [x] 7.2 Implement create tenant modal with form: code (required), name (required)
- [x] 7.3 Implement edit tenant modal with pre-filled form
- [x] 7.4 Implement disable tenant with Popconfirm confirmation
- [x] 7.5 Create tenant domain drawer at `src/pages/tenants/DomainDrawer.tsx`: list domains, add domain input, delete domain with confirmation
- [x] 7.6 Write zh-CN and en-US translations for `tenant.json`

## 8. Tenant Admin Wizard (SuperAdmin)

- [x] 8.1 Create tenant admin list page at `src/pages/tenant-admins/index.tsx` with table showing tenant admin accounts
- [x] 8.2 Create wizard page at `src/pages/tenant-admins/Create.tsx` using Ant Design Steps component (3 steps)
- [x] 8.3 Implement Step 1: tenant selector dropdown populated from `GET /admin/tenants`
- [x] 8.4 Implement Step 2: account creation form (username, password, display name, email, phone)
- [x] 8.5 Implement Step 3: execute `POST /admin/users` then `PUT /admin/tenants/:tenantId/users/:userId/roles` with tenant_admin role, show success/error result
- [x] 8.6 Write zh-CN and en-US translations for tenant admin wizard text

## 9. User Management (TenantAdmin)

- [x] 9.1 Create user list page at `src/pages/users/index.tsx` with table, pagination, search input, columns: Username, Display Name, Email, Phone, Status, Created At, Actions
- [x] 9.2 Implement create user modal with form: username, password, display name, email, phone
- [x] 9.3 Implement edit user modal (no password field) with pre-filled form
- [x] 9.4 Implement disable user with Popconfirm confirmation
- [x] 9.5 Create credential drawer at `src/pages/users/CredentialDrawer.tsx`: list credentials, add credential form (provider type, credential), delete credential with confirmation
- [x] 9.6 Write zh-CN and en-US translations for `user.json`

## 10. Role Management (TenantAdmin)

- [x] 10.1 Create role list page at `src/pages/roles/index.tsx` with table, pagination, columns: Name, Code, Description, Created At, Actions
- [x] 10.2 Implement create role modal with form: code, name, description
- [x] 10.3 Implement edit role modal with pre-filled form
- [x] 10.4 Implement delete role with Popconfirm and warning about cascading removal
- [x] 10.5 Create permission assignment page at `src/pages/roles/Permissions.tsx` with Ant Design Transfer component showing available vs assigned permissions (display: name, resource, action)
- [x] 10.6 Write zh-CN and en-US translations for `role.json`

## 11. Permission Management (TenantAdmin)

- [x] 11.1 Create permission list page at `src/pages/permissions/index.tsx` with table, pagination, columns: Name, Code, Resource, Action, Description, Created At, Actions
- [x] 11.2 Implement create permission modal with form: code, name, resource (with path pattern placeholder), action (select: GET/POST/PUT/DELETE/PATCH), description
- [x] 11.3 Implement edit permission modal with pre-filled form
- [x] 11.4 Implement delete permission with Popconfirm and warning about cascading removal
- [x] 11.5 Write zh-CN and en-US translations for `permission.json`

## 12. User-Role Assignment (TenantAdmin)

- [x] 12.1 Create user-role page at `src/pages/user-roles/index.tsx` with table showing users and their current roles
- [x] 12.2 Implement "Manage Roles" action that opens a modal/drawer with Transfer component (available roles vs assigned roles)
- [x] 12.3 Implement save that calls `PUT /admin/tenants/:tenantId/users/:userId/roles` with selected role UUIDs (full replace)
- [x] 12.4 Write zh-CN and en-US translations for user-role assignment text

## 13. Shared Components and Hooks

- [x] 13.1 Create `useTableData` custom hook: handles fetch with pagination params, loading state, search debounce, refresh-after-mutation callback
- [x] 13.2 Create shared `<PageHeader>` component with title and create button
- [x] 13.3 Create shared `<StatusTag>` component (active/disabled badge)
