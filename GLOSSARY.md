# Staff sign-in

How an organisation's staff get into its internal Django apps, and who decides what they can do in each one.

## Language

**App**:
One internal web application that uses this package.
_Avoid_: Project, service, portal

**User**:
One person's record in one App, identified by email. A person who uses three Apps has three Users.
_Avoid_: Account, profile, login (allauth's own names, such as its account adapters and `SocialAccount`, keep "account")

**Microsoft sign-in**:
Signing in to an App with the person's work account in the organisation's Microsoft Entra tenant.
_Avoid_: SSO, Entra login, Azure login, social login

**Password sign-in**:
Signing in to an App with an email and a password the App stores. It is for people without a work Microsoft account, and for local development where Microsoft sign-in is not set up. A User with a Microsoft link cannot use it.
_Avoid_: Local login, username login

**Microsoft link**:
The tie between a User and one Microsoft person, made at that person's first Microsoft sign-in by matching their work email, and used alone after that.
_Avoid_: Entra identity, social account

**Sign-up rule**:
What an App does when someone with no User completes Microsoft sign-in: refuse them (**Invite only**, the default) or make them a User with only the App's Lowest access (**Open to staff**).
_Avoid_: Auto-provisioning, registration

**Second step**:
The extra proof, after the password, that a Password sign-in needs before it opens the User: a code from an authenticator app, a passkey, or a one-time recovery code. A passkey is only ever a Second step, never a way to sign in on its own. Microsoft sign-in has no Second step in the App because Microsoft already asks for one.
_Avoid_: 2FA, OTP (when meaning the whole step)

**Temporary password**:
A password set on a User by IT, or given by an App admin to someone who has never signed in. The person must replace it at their next Password sign-in, and it stops working after a set time.
_Avoid_: Default password, initial password

**Password reset**:
A person choosing a new password through an emailed link. Only a User that already has a password can use it, and the Second step is still needed afterwards.
_Avoid_: Forgot password (in code and docs; fine as on-screen wording)

## Access

**Access group**:
A named group an App declares to say what a User may do there. An App's Access groups either add up (a person can hold several) or are exclusive (a person holds exactly one).
_Avoid_: Role (as a separate thing), permission, workspace

**Lowest access**:
The one Access group an App names as the least it grants, given to every User that Open to staff makes.
_Avoid_: Default group, base role

**App admin**:
An Access group whose members manage people and data inside the App's own screens. App admins never see a password in use; they can only give a Temporary password to someone who has never signed in.
_Avoid_: Administrator, superuser, staff

**Django admin access**:
Permission to use the App's built-in Django admin screens, held only by developers and IT, never granted by being an App admin.
_Avoid_: Admin, staff, portal admin
