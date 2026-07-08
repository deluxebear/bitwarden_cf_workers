ALTER TABLE auth_requests ADD COLUMN organization_id text REFERENCES organizations(id) ON DELETE cascade;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_auth_requests_organization_id` ON `auth_requests` (`organization_id`);
