CREATE TABLE IF NOT EXISTS `organization_domains` (
    `id` text PRIMARY KEY NOT NULL,
    `organization_id` text NOT NULL,
    `txt` text NOT NULL,
    `domain_name` text NOT NULL,
    `creation_date` text NOT NULL,
    `next_run_date` text NOT NULL,
    `job_run_count` integer DEFAULT 0 NOT NULL,
    `verified_date` text,
    `last_checked_date` text,
    FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_org_domains_org_id` ON `organization_domains` (`organization_id`);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `idx_org_domains_org_domain` ON `organization_domains` (`organization_id`, `domain_name`);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `sso_configs` (
    `id` text PRIMARY KEY NOT NULL,
    `organization_id` text NOT NULL,
    `enabled` integer DEFAULT false NOT NULL,
    `data` text NOT NULL,
    `creation_date` text NOT NULL,
    `revision_date` text NOT NULL,
    FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `idx_sso_configs_org_id` ON `sso_configs` (`organization_id`);
