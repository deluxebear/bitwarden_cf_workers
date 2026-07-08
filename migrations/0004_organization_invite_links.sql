ALTER TABLE organizations ADD COLUMN use_invite_links INTEGER DEFAULT 0;
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `organization_invite_links` (
    `id` text PRIMARY KEY NOT NULL,
    `code` text NOT NULL,
    `organization_id` text NOT NULL,
    `allowed_domains` text NOT NULL,
    `invite` text NOT NULL,
    `supports_confirmation` integer DEFAULT false NOT NULL,
    `creation_date` text NOT NULL,
    `revision_date` text NOT NULL,
    FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `idx_org_invite_links_code` ON `organization_invite_links` (`code`);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `idx_org_invite_links_org_id` ON `organization_invite_links` (`organization_id`);
