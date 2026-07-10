ALTER TABLE `sso_configs` ADD COLUMN `issuer` text;
--> statement-breakpoint
ALTER TABLE `sso_configs` ADD COLUMN `client_id` text;
--> statement-breakpoint
ALTER TABLE `sso_configs` ADD COLUMN `client_secret_env` text;
--> statement-breakpoint
ALTER TABLE `sso_configs` ADD COLUMN `redirect_uri` text;
--> statement-breakpoint
ALTER TABLE `sso_configs` ADD COLUMN `claim_mapping` text;
--> statement-breakpoint
UPDATE `sso_configs`
SET
    `issuer` = COALESCE(NULLIF(json_extract(`data`, '$.issuer'), ''), NULLIF(json_extract(`data`, '$.authority'), '')),
    `client_id` = NULLIF(json_extract(`data`, '$.clientId'), '')
WHERE json_valid(`data`);
--> statement-breakpoint
UPDATE `sso_configs`
SET `enabled` = 0
WHERE json_valid(`data`)
  AND (NULLIF(json_extract(`data`, '$.clientSecret'), '') IS NOT NULL
       OR NULLIF(json_extract(`data`, '$.ClientSecret'), '') IS NOT NULL)
  AND `client_secret_env` IS NULL;
--> statement-breakpoint
UPDATE `sso_configs`
SET `data` = json_remove(`data`, '$.clientSecret', '$.ClientSecret')
WHERE json_valid(`data`);
