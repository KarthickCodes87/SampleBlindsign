# SampleBlindsign
Simple Blind sign flow demonstration

# SAML
SAML (Security Assertion Markup Language) is an XML-based standard for single sign-on (SSO) that lets an organization’s identity system log users into other applications without those apps handling passwords directly.

How it works (high level)

Identity Provider (IdP): Your company’s login system (e.g., Okta, Azure AD, ADFS) that authenticates you.
Service Provider (SP): The app you’re trying to access (e.g., GitHub, Salesforce).
When you try to open the SP, it redirects you to the IdP (or sends a request).
You sign in at the IdP.
The IdP sends the SP a signed SAML assertion (a statement like “this user is authenticated” plus optional attributes such as email, username, groups).
The SP validates the signature and logs you in.

Key terms

Assertion: The package of authentication/identity claims.
Metadata: XML configuration exchanged between IdP and SP (certificates, endpoints, entity IDs).
SP-initiated vs IdP-initiated login: Whether the login starts at the app (SP) or from the IdP portal.
Attributes/claims: Extra user info provided to the SP (often used for role/group mapping).
Single Logout (SLO): Optional part of SAML to log out across systems (not always implemented).
