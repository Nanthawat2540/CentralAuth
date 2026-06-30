-- ============================================================
--  CentralAuth v2 — Database Migration
--  Run on: login_pastechs
--  Adds: refresh_tokens, permissions, role_permissions,
--        api_keys, audit_logs, mfa columns on users
-- ============================================================

USE login_pastechs;
GO

-- ── 1. Add MFA columns to users (idempotent) ─────────────────────────────
IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('users') AND name = 'mfa_enabled')
    ALTER TABLE users ADD mfa_enabled BIT NOT NULL DEFAULT 0;
GO
IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('users') AND name = 'mfa_secret')
    ALTER TABLE users ADD mfa_secret NVARCHAR(64) NULL;
GO

PRINT 'users MFA columns OK';

-- ── 2. refresh_tokens ────────────────────────────────────────────────────
IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'refresh_tokens')
BEGIN
    CREATE TABLE refresh_tokens (
        id          BIGINT         IDENTITY(1,1) PRIMARY KEY,
        user_id     INT            NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token       NVARCHAR(200)  NOT NULL,
        expires_at  DATETIME2(7)   NOT NULL,
        revoked_at  DATETIME2(7)   NULL,
        replaced_by NVARCHAR(200)  NULL,
        ip_address  NVARCHAR(50)   NULL,
        user_agent  NVARCHAR(500)  NULL,
        created_at  DATETIME2(7)   NOT NULL DEFAULT GETUTCDATE()
    );

    CREATE UNIQUE INDEX UX_refresh_tokens_token ON refresh_tokens(token);
    CREATE        INDEX IX_refresh_tokens_user   ON refresh_tokens(user_id);
    CREATE        INDEX IX_refresh_tokens_exp    ON refresh_tokens(expires_at) WHERE revoked_at IS NULL;

    PRINT 'refresh_tokens created';
END
ELSE
    PRINT 'refresh_tokens already exists';
GO

-- ── 3. permissions ───────────────────────────────────────────────────────
IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'permissions')
BEGIN
    CREATE TABLE permissions (
        id          INT            IDENTITY(1,1) PRIMARY KEY,
        name        NVARCHAR(100)  NOT NULL,
        module      NVARCHAR(50)   NOT NULL,
        action      NVARCHAR(50)   NOT NULL,
        description NVARCHAR(200)  NULL,
        CONSTRAINT UQ_permissions_name UNIQUE (name)
    );

    -- Seed default permissions
    INSERT INTO permissions (name, module, action, description) VALUES
        ('users.read',        'users',   'read',   'View users list'),
        ('users.create',      'users',   'create', 'Create new users'),
        ('users.update',      'users',   'update', 'Update users'),
        ('users.delete',      'users',   'delete', 'Delete / deactivate users'),
        ('roles.read',        'roles',   'read',   'View roles'),
        ('roles.manage',      'roles',   'manage', 'Create / update / delete roles'),
        ('apikeys.read',      'apikeys', 'read',   'View API keys'),
        ('apikeys.create',    'apikeys', 'create', 'Create API keys'),
        ('apikeys.delete',    'apikeys', 'delete', 'Revoke API keys'),
        ('auditlogs.read',    'audit',   'read',   'View audit logs'),
        ('auth.impersonate',  'auth',    'impersonate', 'Login as another user');

    PRINT 'permissions created + seeded';
END
ELSE
    PRINT 'permissions already exists';
GO

-- ── 4. role_permissions ──────────────────────────────────────────────────
IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'role_permissions')
BEGIN
    CREATE TABLE role_permissions (
        role_name     NVARCHAR(50) NOT NULL,
        permission_id INT          NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
        CONSTRAINT PK_role_permissions PRIMARY KEY (role_name, permission_id)
    );

    -- Seed: admin gets all permissions
    INSERT INTO role_permissions (role_name, permission_id)
    SELECT 'admin', id FROM permissions;

    PRINT 'role_permissions created + seeded';
END
ELSE
    PRINT 'role_permissions already exists';
GO

-- ── 5. api_keys ──────────────────────────────────────────────────────────
IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'api_keys')
BEGIN
    CREATE TABLE api_keys (
        id          INT           IDENTITY(1,1) PRIMARY KEY,
        key_hash    NVARCHAR(100) NOT NULL,
        name        NVARCHAR(100) NOT NULL,
        user_id     INT           NULL REFERENCES users(id) ON DELETE SET NULL,
        app_id      NVARCHAR(50)  NULL,
        permissions NVARCHAR(MAX) NULL,       -- JSON array of permission names
        expires_at  DATETIME2(7)  NULL,
        last_used   DATETIME2(7)  NULL,
        is_active   BIT           NOT NULL DEFAULT 1,
        created_at  DATETIME2(7)  NOT NULL DEFAULT GETUTCDATE(),
        CONSTRAINT UQ_api_keys_hash UNIQUE (key_hash)
    );

    CREATE INDEX IX_api_keys_user    ON api_keys(user_id);
    CREATE INDEX IX_api_keys_active  ON api_keys(is_active) WHERE is_active = 1;

    PRINT 'api_keys created';
END
ELSE
    PRINT 'api_keys already exists';
GO

-- ── 6. audit_logs ────────────────────────────────────────────────────────
IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'audit_logs')
BEGIN
    CREATE TABLE audit_logs (
        id          BIGINT         IDENTITY(1,1) PRIMARY KEY,
        user_id     INT            NULL,
        action      NVARCHAR(100)  NOT NULL,
        resource    NVARCHAR(200)  NULL,
        details     NVARCHAR(MAX)  NULL,         -- JSON
        ip_address  NVARCHAR(50)   NULL,
        user_agent  NVARCHAR(500)  NULL,
        created_at  DATETIME2(7)   NOT NULL DEFAULT GETUTCDATE()
    );

    CREATE INDEX IX_audit_logs_user    ON audit_logs(user_id);
    CREATE INDEX IX_audit_logs_action  ON audit_logs(action);
    CREATE INDEX IX_audit_logs_time    ON audit_logs(created_at DESC);

    PRINT 'audit_logs created';
END
ELSE
    PRINT 'audit_logs already exists';
GO

-- ── 7. Cleanup job (optional) — auto-purge expired tokens > 7 days ───────
-- Run via SQL Agent or scheduled job
-- DELETE FROM refresh_tokens WHERE expires_at < DATEADD(DAY, -7, GETUTCDATE());

PRINT '=== CentralAuth v2 migration complete ===';
GO
