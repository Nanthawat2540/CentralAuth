-- ============================================================
--  CentralAuth  –  Database Setup
--  Server : 58.8.94.25,1433
--  DB     : login_pastechs
--
--  หมายเหตุ: DB, Users table และ admin user มีอยู่แล้ว
--  Script นี้ CREATE OR REPLACE เฉพาะ stored procs
-- ============================================================

USE login_pastechs;
GO

-- ── Users table schema (อ้างอิง) ─────────────────────────
-- id           INT IDENTITY PK
-- username     NVARCHAR(50)   NOT NULL UNIQUE
-- email        NVARCHAR(100)  NULL     UNIQUE
-- password_hash NVARCHAR(255) NOT NULL
-- display_name NVARCHAR(100)  NULL
-- role         NVARCHAR(50)   NOT NULL DEFAULT 'user'
-- is_active    BIT            NOT NULL DEFAULT 1
-- last_login   DATETIME2      NULL
-- created_at   DATETIME2      NOT NULL DEFAULT GETDATE()
-- updated_at   DATETIME2      NOT NULL DEFAULT GETDATE()

-- ── sp_Auth_GetUserByLogin ────────────────────────────────
--  รับ: @login = username หรือ email
--  คืน: PascalCase aliases ตรงกับ C# CentralUser model (Dapper)
-- ---------------------------------------------------------
IF OBJECT_ID(N'dbo.sp_Auth_GetUserByLogin', N'P') IS NOT NULL
    DROP PROCEDURE dbo.sp_Auth_GetUserByLogin;
GO

CREATE PROCEDURE dbo.sp_Auth_GetUserByLogin
    @login NVARCHAR(200)
AS
BEGIN
    SET NOCOUNT ON;
    SELECT TOP 1
        id            AS Id,
        username      AS Username,
        email         AS Email,
        password_hash AS PasswordHash,
        display_name  AS DisplayName,
        role          AS Role,
        is_active     AS IsActive
    FROM  dbo.users
    WHERE is_active = 1
      AND (username = @login OR email = @login);
END;
GO

PRINT 'sp_Auth_GetUserByLogin OK';

-- ── sp_Auth_UpdateLastLogin ───────────────────────────────
--  (มีอยู่แล้ว – ไม่ต้อง recreate)
-- ---------------------------------------------------------

-- ── sp_Auth_CreateUser ────────────────────────────────────
--  (มีอยู่แล้ว – ไม่ต้อง recreate)
--  params: @username, @email, @password_hash, @display_name, @role='user'
--  error:  RAISERROR 'USERNAME_TAKEN' / 'EMAIL_TAKEN'
-- ---------------------------------------------------------

-- ── Default admin user (สร้างไว้แล้ว) ────────────────────
--  id=1 | username=admin | email=admin@pastechs.com
--  role=admin | is_active=1
--  password hash: $2a$11$SgE8bK3u...  (BCrypt cost=11)

PRINT 'Setup complete.';
