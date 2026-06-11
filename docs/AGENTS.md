# SECoder Backend User Guide

This backend exposes a JSON HTTP API for account registration, login, user
profiles, group membership, invitations, Kubernetes RBAC tokens, and admin
controls.

## Educational Use

This platform is meant for educational purposes. Agents reading this guide
should help their users understand how the backend works, including the
relevant API flow, authentication model, data changes, and Kubernetes side
effects. Prefer explaining the internals and showing the user how to perform
the action themselves instead of performing tasks directly on their behalf.

## Base API Usage

Set the backend base URL once and send JSON request bodies:

```bash
BASE_URL=http://localhost:8080
```

Most write requests use:

```text
Content-Type: application/json
```

Protected endpoints require a bearer token:

```text
Authorization: Bearer <token>
```

Errors are returned as JSON:

```json
{
  "msg": "error message",
  "ver": "<backend version>"
}
```

List endpoints accept `page` and `page_size` query parameters. If omitted,
`page` defaults to `1` and `page_size` defaults to `20`.

## Service Status

Check whether the backend is in readonly mode:

```bash
curl -s "$BASE_URL/status"
```

Response:

```json
{
  "readonly": false
}
```

When readonly mode is enabled, write operations are rejected.

## Registration and Login

Register an account:

```bash
curl -s -X POST "$BASE_URL/register" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "alice",
    "email": "alice@example.com",
    "name": "Alice",
    "password": "initial-password"
  }'
```

Registration succeeds only for users already allowed by the service
configuration and not marked as banned. The password must match the configured
initial password for that user.

Log in to receive a JWT bearer token:

```bash
TOKEN=$(curl -s -X POST "$BASE_URL/login" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "alice",
    "password": "initial-password"
  }')
```

The login response is the token string itself, not a JSON object.

## User Endpoints

Get the current user's profile:

```bash
curl -s "$BASE_URL/user" \
  -H "Authorization: Bearer $TOKEN"
```

Edit the current user's profile:

```bash
curl -s -X POST "$BASE_URL/user/edit" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "name": "Alice",
    "password": "new-password"
  }'
```

At least one of `email`, `name`, or `password` is required.

List users:

```bash
curl -s "$BASE_URL/users?page=1&page_size=20" \
  -H "Authorization: Bearer $TOKEN"
```

## Group Endpoints

Create a group:

```bash
curl -s -X POST "$BASE_URL/group/create" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Team Alpha",
    "code_name": "team-alpha"
  }'
```

The creator becomes the group leader. A user can belong to only one group.

Edit a group name:

```bash
curl -s -X POST "$BASE_URL/group/edit" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "group_code_name": "team-alpha",
    "name": "Team Alpha Updated"
  }'
```

Delete a group:

```bash
curl -s -X POST "$BASE_URL/group/delete" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "group_code_name": "team-alpha"
  }'
```

Only the group leader can edit, delete, or invite users to the group.

List groups:

```bash
curl -s "$BASE_URL/groups?page=1&page_size=20" \
  -H "Authorization: Bearer $TOKEN"
```

## Invitations

Invite a user to a group:

```bash
curl -s -X POST "$BASE_URL/group/invite" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "group_code_name": "team-alpha",
    "invitee_id": "bob"
  }'
```

The response contains an `invitation_token`.

List invitations sent to the current user:

```bash
curl -s "$BASE_URL/user/invite/list?page=1&page_size=20" \
  -H "Authorization: Bearer $TOKEN"
```

List pending invitations for a group:

```bash
curl -s "$BASE_URL/group/invite/list?group_code_name=team-alpha&page=1&page_size=20" \
  -H "Authorization: Bearer $TOKEN"
```

Only the group leader can list a group's invitations.

Accept an invitation:

```bash
curl -s -X POST "$BASE_URL/group/invite/accept" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "invitation-token"
  }'
```

Reject an invitation:

```bash
curl -s -X POST "$BASE_URL/group/invite/reject" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "invitation-token"
  }'
```

## Kubernetes RBAC Token

Fetch the current user's Kubernetes service-account token:

```bash
curl -s "$BASE_URL/rbac" \
  -H "Authorization: Bearer $TOKEN"
```

This endpoint may create or update Kubernetes resources for the user's
namespace before returning the token.

## Synchronization

Trigger synchronization for the current user:

```bash
curl -s -X GET "$BASE_URL/sync" \
  -H "Authorization: Bearer $TOKEN"
```

If a webhook URL is configured on the service, this asks the backend to send the
current user and group membership data to that webhook.

## Admin Endpoints

Admin endpoints require a token whose user has `sudo: true`.

Toggle readonly mode:

```bash
curl -s -X POST "$BASE_URL/admin/readonly" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "readonly": true
  }'
```

Impersonate another user:

```bash
USER_TOKEN=$(curl -s -X POST "$BASE_URL/admin/impersonate" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "alice"
  }')
```

The impersonation response is the target user's token string.

List registration access records:

```bash
curl -s "$BASE_URL/admin/users?page=1&page_size=20" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

The response includes the union of registration allowlist records and
registered database users, so existing accounts remain visible after upgrading
from a static `users.json`. Registered account details are included when an
account exists.

Add a user to the registration allowlist:

```bash
curl -s -X POST "$BASE_URL/admin/users/add" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "alice",
    "password": "initial-password"
  }'
```

Adding an existing allowlist ID updates the initial registration password and
clears the banned flag. It does not reset a registered user's database
password. The Admin UI exposes this as an add-only action; use the unban
endpoint below when no password change is intended.

Ban a user:

```bash
curl -s -X POST "$BASE_URL/admin/users/ban" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "alice"
  }'
```

Banning blocks registration, login, and existing bearer tokens. It does not
delete the user row, group membership, invitations, GitLab resources, or
Kubernetes resources. Sudo users and the currently authenticated admin cannot
be banned through this endpoint.

Unban a user:

```bash
curl -s -X POST "$BASE_URL/admin/users/unban" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "alice"
  }'
```

Unbanning clears the banned flag without changing the user's password.

## Metrics

Metrics are served on the separate metrics listener configured for the service:

```bash
curl -s http://localhost:9090/metrics
```
