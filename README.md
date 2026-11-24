# mo2f-ga-secret-bridge

Fix for Google Authenticator logins broken by the WordPress plugin
**"Two-Factor Authentication (2FA) – Passkey & Google Authenticator"** (miniOrange) **6.7.0**.

## Symptom
After the (auto-)update to 6.7.0, users who set up Google Authenticator on an older version can no
longer log in: the password is accepted, the 6-digit code from the phone is always rejected, the
field just clears, and after a few tries the plugin says *"Too many incorrect attempts"*. Other
login-limit plugins (Limit Login Attempts Reloaded, Melapress Login Security, …) may then lock the
account or IP as well.

## Cause
- Up to 6.6.x the on-premise Google Authenticator secret is stored in user meta `mo2f_gauth_key`,
  AES-128-CBC encrypted with the per-user key in `mo2f_get_auth_rnd_string`.
- 6.7.0 reads the secret **only** from `mo2f_secret_ga` (and encrypts it there as `enc:…`).
  Its built-in migration handles a plaintext `mo2f_secret_ga`, but nothing ever reads `mo2f_gauth_key`.
- So for these users 6.7.0 verifies the code against an **empty secret** and returns FAILURE for every code.

Check whether you are affected (read-only):
```sql
SELECT user_id, meta_key, LENGTH(meta_value) FROM wp_usermeta
WHERE meta_key IN ('mo2f_gauth_key','mo2f_get_auth_rnd_string','mo2f_secret_ga');
```
Affected users have `mo2f_gauth_key` + `mo2f_get_auth_rnd_string` but **no** `mo2f_secret_ga`.

## Fix
The script decrypts the old secret with the plugin's own algorithm and stores it as `mo2f_secret_ga`.
The existing entry in the phone app keeps working, no new QR code needed. The old meta keys are not
changed. The secret is never printed.

```bash
php mo2f-ga-secret-bridge.php /path/to/wordpress 1            # dry run, changes nothing
php mo2f-ga-secret-bridge.php /path/to/wordpress 1 --write    # fix user 1
php mo2f-ga-secret-bridge.php /path/to/wordpress --all        # dry run for every affected user
php mo2f-ga-secret-bridge.php /path/to/wordpress --all --write
php mo2f-ga-secret-bridge.php /path/to/wordpress 1 --undo     # way back: delete mo2f_secret_ga again
```
It loads WordPress (`wp-load.php`) and uses the site's own DB credentials; run it as a user that can read `wp-config.php`.
Take a database backup first.

**Locked out right now?** Add `define( 'MO2F_DISABLE_2FA_ENFORCEMENT', true );` to `wp-config.php`
(the 6.7.0 emergency switch), log in, run the script, then remove the line again.
Alternative without the script: log in with the switch and set up Google Authenticator again (new QR code).

## Tested
- Real site: WordPress + plugin 6.7.0, PHP 8.5, one affected admin user, with a site-specific earlier version of this
  script (same decrypt/write logic, fixed path and single user): dry run, write, login with the old phone code OK.
- Offline unit tests (`test/selftest.php`, WordPress meta stubbed): decrypt matches the 6.6.0 encrypt, wrong key → nothing
  written, existing `mo2f_secret_ga` never overwritten, `--undo` deletes only `mo2f_secret_ga`.
- Not tested on a real site: `--all` with several users, multisite.

## License
MIT — Danail Vankov <danail.vankov@gmail.com>. Not affiliated with miniOrange.
