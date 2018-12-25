Roundcube plugin: user\_check
=============================

This plugin is useful for multi-domain setups (https://github.com/roundcube/roundcubemail/wiki/Configuration:-Multi-Domain-Setup) where specific users need to be whitelisted or blacklisted from specific domains. This gives more control and flexibility than Roundcube built-in settings 'username\_domain' and 'username\_domain\_forced'. I recommend placing user\_check plugin configuration (see example configuration in config.inc.dist) in host-specific configuration files through Roundcube built-in setting 'include\_host\_config' to enable per-host user whitelists or blacklists. Filters will be matched against Roundcube usernames, which may or may not contain a domain part.
