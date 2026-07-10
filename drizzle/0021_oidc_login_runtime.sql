UPDATE `sso_configs`
SET `enabled` = 0
WHERE `organization_id` IN (
    SELECT `id` FROM `organizations`
    WHERE `identifier` IS NOT NULL AND trim(`identifier`) <> ''
      AND lower(trim(`identifier`)) IN (
          SELECT lower(trim(`identifier`)) FROM `organizations`
          WHERE `identifier` IS NOT NULL AND trim(`identifier`) <> ''
          GROUP BY lower(trim(`identifier`)) HAVING count(*) > 1
      )
);
--> statement-breakpoint
UPDATE `organizations`
SET `identifier` = NULL
WHERE `identifier` IS NULL OR trim(`identifier`) = '';
--> statement-breakpoint
UPDATE `organizations`
SET `identifier` = NULL
WHERE `identifier` IS NOT NULL
  AND rowid NOT IN (
      SELECT min(rowid) FROM `organizations`
      WHERE `identifier` IS NOT NULL
      GROUP BY lower(trim(`identifier`))
  );
--> statement-breakpoint
UPDATE `organizations`
SET `identifier` = lower(trim(`identifier`))
WHERE `identifier` IS NOT NULL;
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_organizations_identifier_lower`
ON `organizations` (lower(`identifier`)) WHERE `identifier` IS NOT NULL;
--> statement-breakpoint
CREATE TABLE `oidc_login_states` (
    `state_hash` text PRIMARY KEY NOT NULL,
    `organization_id` text NOT NULL REFERENCES `organizations`(`id`) ON DELETE cascade,
    `nonce` text NOT NULL,
    `provider_pkce_verifier` text NOT NULL,
    `client_id` text NOT NULL,
    `client_redirect_uri` text NOT NULL,
    `client_state` text,
    `client_code_challenge` text NOT NULL,
    `creation_date` text NOT NULL,
    `expiration_date` text NOT NULL,
    `consumed_date` text
);
--> statement-breakpoint
CREATE INDEX `idx_oidc_login_states_expiration` ON `oidc_login_states` (`expiration_date`);
--> statement-breakpoint
CREATE TABLE `oidc_authorization_codes` (
    `code_hash` text PRIMARY KEY NOT NULL,
    `organization_id` text NOT NULL REFERENCES `organizations`(`id`) ON DELETE cascade,
    `user_id` text NOT NULL REFERENCES `users`(`id`) ON DELETE cascade,
    `client_id` text NOT NULL,
    `redirect_uri` text NOT NULL,
    `code_challenge` text NOT NULL,
    `creation_date` text NOT NULL,
    `expiration_date` text NOT NULL,
    `consumed_date` text
);
--> statement-breakpoint
CREATE INDEX `idx_oidc_authorization_codes_expiration` ON `oidc_authorization_codes` (`expiration_date`);
--> statement-breakpoint
CREATE TABLE `oidc_identities` (
    `organization_id` text NOT NULL REFERENCES `organizations`(`id`) ON DELETE cascade,
    `issuer` text NOT NULL,
    `subject` text NOT NULL,
    `user_id` text NOT NULL REFERENCES `users`(`id`) ON DELETE cascade,
    `email` text NOT NULL,
    `creation_date` text NOT NULL,
    `revision_date` text NOT NULL,
    PRIMARY KEY (`organization_id`, `issuer`, `subject`)
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_oidc_identities_org_user` ON `oidc_identities` (`organization_id`, `user_id`);
