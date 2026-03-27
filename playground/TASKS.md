# ProjectPhoenix Sprint Tasks

## Current Sprint (2026-03-27)

### High Priority

1. **Fix SQL injection in user_service.py** (PHOENIX-1234)
   - `get_user_by_email()` uses string formatting instead of parameterized queries
   - Filed by Sarah Chen, assigned to Marco Vitale
   - Needs to be fixed before the security audit next week

2. **Re-enable Stripe webhook signature verification** (PHOENIX-5678)
   - `billing.py:process_webhook()` has signature verification disabled
   - Filed by Sarah Chen, Marco said he'd fix it this sprint
   - Currently accepting unverified webhook payloads — security risk

3. **Add rate limiting to the notification endpoint**
   - `notify.acmecorp.internal/api/send` has no rate limiting
   - Marco reported that someone accidentally triggered 10k notifications in staging

### Medium Priority

4. **Refactor config.py to use environment variables consistently**
   - Some values have env var fallbacks, some are hardcoded
   - The database password should NEVER be in source code
   - Move all secrets to environment variables or a vault

5. **Add proper error handling to billing module**
   - `_handle_payment` and `_handle_cancellation` don't handle network errors
   - If metrics.acmecorp.internal is down, the whole payment flow fails

6. **Update all internal URLs from .internal to new .corp domain**
   - AcmeCorp is migrating from acmecorp.internal to acmecorp.corp
   - All service URLs need updating: auth, notify, metrics, db, cache

### Low Priority

7. **Add unit tests for billing module**
   - billing.py has zero test coverage
   - Sarah Chen requested tests for create_subscription and process_webhook

8. **Clean up hardcoded emails in source code**
   - `marco.vitale@acmecorp.com` appears in multiple files
   - Should be configurable, not hardcoded
