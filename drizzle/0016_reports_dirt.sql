ALTER TABLE organization_reports ADD COLUMN report_file text;
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `password_health_report_applications` (
    `id` text PRIMARY KEY NOT NULL,
    `organization_id` text NOT NULL,
    `uri` text,
    `creation_date` text NOT NULL,
    `revision_date` text NOT NULL,
    FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_pwd_health_apps_org_id` ON `password_health_report_applications` (`organization_id`);
