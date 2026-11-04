# 05: Access groups and the service functions

Status: open
Labels: ready-for-agent
Blocked by: 01

Spec: [../spec.md](../spec.md)

**What to build:** An App declares its Access groups in settings, says whether they add up or are exclusive, and names the lowest access group and the App admin group. App code manages Accounts through the package's service functions, which enforce the rules and send signals.

- [ ] Declared Access groups are created or updated after migrations
- [ ] The system check refuses an undeclared lowest access group or App admin group
- [ ] Service functions: invite an Account with Access groups, set Access groups, block, unblock, and check whether an Account holds a group
- [ ] Refused with stable error codes: undeclared groups, two exclusive groups, removing the App admin group from the last App admin
- [ ] In exclusive mode, setting a group replaces the old one
- [ ] Signals for Access groups changed, Account blocked and Account unblocked, carrying the Account and the acting Account
- [ ] No Access group code changes Django admin access (staff and superuser flags); App admin functions take and return no password data
- [ ] Tested at the service-function seam, as an App's own code would call them
