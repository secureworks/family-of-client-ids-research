import msal
import jwt
import pandas as pd
import random

from typing import Any, List, Dict, Union


def acquire_token_by_refresh_token(
    *, refresh_token: str, client_id: str, scopes: List[str], tenant_id: str
) -> Dict[str, str]:
    """Convenience function to instantiate a public client
    and attempt to acquire new tokens using a provided refresh token.
    """
    app = msal.PublicClientApplication(
        client_id=client_id, authority=f"https://login.microsoftonline.com/{tenant_id}"
    )

    return app.acquire_token_by_refresh_token(refresh_token, scopes=scopes)


def decode_jwt(base64_blob: str) -> Dict[str, Any]:
    """Decodes base64 encoded JWT blob"""
    return jwt.decode(
        base64_blob, options={"verify_signature": False, "verify_aud": False}
    )


def get_tokens_for_foci_clients(
    bearer_tokens: Dict[str, Union[List, str]],
    chain: bool = False,
    demo: bool = True,
) -> pd.DataFrame:
    """Redeem family refresh token for new bearer tokens
    for family"""

    family_tokens = []  # List[Dict]

    tenant_id = bearer_tokens["id_token_claims"]["tid"]
    family_refresh_token = bearer_tokens["refresh_token"]
    starting_access_token = decode_jwt(bearer_tokens["access_token"])
    current_client = starting_access_token["appid"]
    current_resource = starting_access_token["aud"]
    current_scopes = f"{current_resource}/.default"

    # Mapping of know FOCI client app IDs to the
    # resources that were pre-consented for those
    # clients. We will request the `.default` scope
    # for every combination of client ID and resource
    # in this large dictionary.

    FOCI_CLIENT_VALID_RESOURCE_MAP = {
        "00b41c95-dab0-4487-9791-b9d2c32c80f2": [
            "https://graph.windows.net",
            "https://substrate.office.com",
            "https://outlook.office.com",
            "https://graph.microsoft.com",
            "https://management.core.windows.net",
            "https://outlook.office365.com",
            "https://api.spaces.skype.com",
            "https://manage.office.com",
            "https://msmamservice.api.application",
            "https://officeapps.live.com",
            "https://api.diagnostics.office.com",
            f"https://{tenant_id}-my.sharepoint.com",
            f"https://{tenant_id}.sharepoint.com",
            "https://webshell.suite.office.com",
            "https://batch.core.windows.net",
            "https://management.azure.com/",
            f"https://{tenant_id}-admin.sharepoint.com",
            "https://analysis.windows.net/powerbi/api",
            "https://quantum.microsoft.com",
            "https://database.windows.net",
            "https://storage.azure.com",
            "https://compliance.microsoft.com",
            "https://iothubs.azure.net",
            "https://dev.azuresynapse.net",
            "https://rest.media.azure.net",
            "https://api.loganalytics.io",
            "https://datalake.azure.net",
            "https://vault.azure.net",
            "https://www.yammer.com",
            "https://digitaltwins.azure.net",
        ],
        "04b07795-8ddb-461a-bbee-02f9e1bf7b46": [
            "https://outlook.office.com",
            "https://substrate.office.com",
            "https://msmamservice.api.application",
            "https://management.core.windows.net",
            f"https://{tenant_id}-admin.sharepoint.com",
            "https://manage.office.com",
            "https://api.spaces.skype.com",
            "https://api.diagnostics.office.com",
            "https://graph.microsoft.com",
            "https://officeapps.live.com",
            "https://management.azure.com/",
            "https://outlook.office365.com",
            f"https://{tenant_id}-my.sharepoint.com",
            "https://graph.windows.net",
            "https://webshell.suite.office.com",
            "https://vault.azure.net",
            "https://datalake.azure.net",
            "https://batch.core.windows.net",
            "https://analysis.windows.net/powerbi/api",
            "https://www.yammer.com",
            "https://storage.azure.com",
            "https://api.loganalytics.io",
            "https://rest.media.azure.net",
            "https://digitaltwins.azure.net",
            "https://dev.azuresynapse.net",
            "https://iothubs.azure.net",
            "https://quantum.microsoft.com",
            "https://compliance.microsoft.com",
            "https://database.windows.net",
            "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
            f"https://{tenant_id}.sharepoint.com",
        ],
        "1950a258-227b-4e31-a9cf-717495945fc2": [
            "https://graph.microsoft.com",
            "https://outlook.office.com",
            "https://graph.windows.net",
            "https://management.core.windows.net",
            "https://outlook.office365.com",
            "https://substrate.office.com",
            "https://manage.office.com",
            "https://webshell.suite.office.com",
            "https://officeapps.live.com",
            "https://msmamservice.api.application",
            f"https://{tenant_id}-my.sharepoint.com",
            "https://api.spaces.skype.com",
            "https://api.diagnostics.office.com",
            f"https://{tenant_id}.sharepoint.com",
            "https://datalake.azure.net",
            "https://management.azure.com/",
            "https://batch.core.windows.net",
            "https://analysis.windows.net/powerbi/api",
            f"https://{tenant_id}-admin.sharepoint.com",
            "https://api.loganalytics.io",
            "https://vault.azure.net",
            "https://rest.media.azure.net",
            "https://storage.azure.com",
            "https://www.yammer.com",
            "1950a258-227b-4e31-a9cf-717495945fc2",
            "https://database.windows.net",
            "https://dev.azuresynapse.net",
            "https://iothubs.azure.net",
            "https://quantum.microsoft.com",
            "https://compliance.microsoft.com",
            "https://digitaltwins.azure.net",
        ],
        "1fec8e78-bce4-4aaf-ab1b-5451cc387264": [
            "https://graph.microsoft.com",
            "https://substrate.office.com",
            "https://graph.windows.net",
            "https://management.core.windows.net",
            "https://api.diagnostics.office.com",
            "https://manage.office.com",
            "https://outlook.office.com",
            "https://outlook.office365.com",
            "https://api.spaces.skype.com",
            "https://webshell.suite.office.com",
            "https://datalake.azure.net",
            f"https://{tenant_id}-my.sharepoint.com",
            "https://msmamservice.api.application",
            f"https://{tenant_id}.sharepoint.com",
            "https://analysis.windows.net/powerbi/api",
            "https://vault.azure.net",
            "https://management.azure.com/",
            "https://batch.core.windows.net",
            "https://storage.azure.com",
            "https://rest.media.azure.net",
            "https://www.yammer.com",
            "https://officeapps.live.com",
            "https://api.loganalytics.io",
            "https://database.windows.net",
            "https://digitaltwins.azure.net",
            "https://dev.azuresynapse.net",
            "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
            "https://quantum.microsoft.com",
            "https://iothubs.azure.net",
            "https://compliance.microsoft.com",
            f"https://{tenant_id}-admin.sharepoint.com",
        ],
        "26a7ee05-5602-4d76-a7ba-eae8b7b67941": [
            "https://graph.microsoft.com",
            "https://management.core.windows.net",
            "https://outlook.office.com",
            "https://outlook.office365.com",
            "https://graph.windows.net",
            "https://substrate.office.com",
            "https://api.diagnostics.office.com",
            "https://manage.office.com",
            "https://msmamservice.api.application",
            "https://officeapps.live.com",
            "https://webshell.suite.office.com",
            "https://api.spaces.skype.com",
            f"https://{tenant_id}-my.sharepoint.com",
            f"https://{tenant_id}-admin.sharepoint.com",
            "https://analysis.windows.net/powerbi/api",
            "https://datalake.azure.net",
            f"https://{tenant_id}.sharepoint.com",
            "https://storage.azure.com",
            "https://vault.azure.net",
            "https://management.azure.com/",
            "https://batch.core.windows.net",
            "https://rest.media.azure.net",
            "https://api.loganalytics.io",
            "https://database.windows.net",
            "https://digitaltwins.azure.net",
            "https://www.yammer.com",
            "https://dev.azuresynapse.net",
            "https://iothubs.azure.net",
            "https://quantum.microsoft.com",
            "https://compliance.microsoft.com",
        ],
        "27922004-5251-4030-b22d-91ecd9a37ea4": [
            "https://management.core.windows.net",
            "https://graph.microsoft.com",
            "https://outlook.office.com",
            "https://graph.windows.net",
            "https://api.spaces.skype.com",
            "https://substrate.office.com",
            "https://outlook.office365.com",
            "https://manage.office.com",
            "https://api.diagnostics.office.com",
            f"https://{tenant_id}.sharepoint.com",
            "https://msmamservice.api.application",
            f"https://{tenant_id}-admin.sharepoint.com",
            "https://officeapps.live.com",
            "https://webshell.suite.office.com",
            f"https://{tenant_id}-my.sharepoint.com",
            "https://vault.azure.net",
            "https://management.azure.com/",
            "https://datalake.azure.net",
            "https://rest.media.azure.net",
            "https://batch.core.windows.net",
            "https://analysis.windows.net/powerbi/api",
            "https://storage.azure.com",
            "https://digitaltwins.azure.net",
            "https://api.loganalytics.io",
            "https://www.yammer.com",
            "https://dev.azuresynapse.net",
            "https://database.windows.net",
            "https://compliance.microsoft.com",
            "https://iothubs.azure.net",
            "https://quantum.microsoft.com",
            "27922004-5251-4030-b22d-91ecd9a37ea4",
        ],
        "2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8": ["https://graph.windows.net"],
        "4813382a-8fa7-425e-ab75-3b753aab3abb": [
            "https://graph.microsoft.com",
            "https://graph.windows.net",
            "https://management.core.windows.net",
            "https://outlook.office.com",
            "https://api.diagnostics.office.com",
            "https://substrate.office.com",
            "https://outlook.office365.com",
            "https://api.spaces.skype.com",
            "https://officeapps.live.com",
            f"https://{tenant_id}.sharepoint.com",
            f"https://{tenant_id}-my.sharepoint.com",
            f"https://{tenant_id}-admin.sharepoint.com",
            "https://manage.office.com",
            "https://management.azure.com/",
            "https://msmamservice.api.application",
            "https://vault.azure.net",
            "https://datalake.azure.net",
            "https://storage.azure.com",
            "https://analysis.windows.net/powerbi/api",
            "https://batch.core.windows.net",
            "https://rest.media.azure.net",
            "https://api.loganalytics.io",
            "https://digitaltwins.azure.net",
            "https://www.yammer.com",
            "https://database.windows.net",
            "https://quantum.microsoft.com",
            "https://compliance.microsoft.com",
            "https://dev.azuresynapse.net",
            "https://iothubs.azure.net",
            "4813382a-8fa7-425e-ab75-3b753aab3abb",
            "https://webshell.suite.office.com",
        ],
        "844cca35-0656-46ce-b636-13f48b0eecbd": [
            "https://graph.windows.net",
            "https://msmamservice.api.application",
            "https://www.yammer.com",
        ],
        "872cd9fa-d31f-45e0-9eab-6e460a02d1f1": [
            "https://graph.microsoft.com",
            "https://substrate.office.com",
            "https://graph.windows.net",
            "https://management.core.windows.net",
            "https://outlook.office365.com",
            "https://outlook.office.com",
            "https://api.diagnostics.office.com",
            "https://manage.office.com",
            "https://msmamservice.api.application",
            "https://api.spaces.skype.com",
            "https://webshell.suite.office.com",
            f"https://{tenant_id}-my.sharepoint.com",
            f"https://{tenant_id}.sharepoint.com",
            "https://officeapps.live.com",
            f"https://{tenant_id}-admin.sharepoint.com",
            "https://vault.azure.net",
            "https://management.azure.com/",
            "https://batch.core.windows.net",
            "https://datalake.azure.net",
            "https://analysis.windows.net/powerbi/api",
            "https://api.loganalytics.io",
            "https://rest.media.azure.net",
            "https://storage.azure.com",
            "https://digitaltwins.azure.net",
            "https://www.yammer.com",
            "https://database.windows.net",
            "https://dev.azuresynapse.net",
            "https://compliance.microsoft.com",
            "https://iothubs.azure.net",
            "https://quantum.microsoft.com",
            "872cd9fa-d31f-45e0-9eab-6e460a02d1f1",
        ],
        "87749df4-7ccf-48f8-aa87-704bad0e0e16": [
            "https://graph.windows.net",
            "https://api.spaces.skype.com",
        ],
        "ab9b8c07-8f02-4f72-87fa-80105867a763": [
            "https://graph.microsoft.com",
            "https://outlook.office365.com",
            "https://graph.windows.net",
            "https://outlook.office.com",
            "https://management.core.windows.net",
            "https://api.spaces.skype.com",
            "https://api.diagnostics.office.com",
            "https://substrate.office.com",
            "https://webshell.suite.office.com",
            "https://msmamservice.api.application",
            "https://manage.office.com",
            f"https://{tenant_id}-my.sharepoint.com",
            f"https://{tenant_id}.sharepoint.com",
            "https://officeapps.live.com",
            f"https://{tenant_id}-admin.sharepoint.com",
            "https://management.azure.com/",
            "https://vault.azure.net",
            "https://batch.core.windows.net",
            "https://datalake.azure.net",
            "https://rest.media.azure.net",
            "https://storage.azure.com",
            "https://analysis.windows.net/powerbi/api",
            "https://api.loganalytics.io",
            "https://www.yammer.com",
            "https://digitaltwins.azure.net",
            "https://dev.azuresynapse.net",
            "https://database.windows.net",
            "https://iothubs.azure.net",
            "https://quantum.microsoft.com",
            "https://compliance.microsoft.com",
            "ab9b8c07-8f02-4f72-87fa-80105867a763",
        ],
        "af124e86-4e96-495a-b70a-90f90ab96707": [
            "https://graph.windows.net",
            "https://graph.microsoft.com",
            "https://manage.office.com",
            "https://api.diagnostics.office.com",
            "https://webshell.suite.office.com",
            "https://officeapps.live.com",
            f"https://{tenant_id}.sharepoint.com",
            "https://substrate.office.com",
            "https://management.core.windows.net",
            "https://outlook.office.com",
            f"https://{tenant_id}-my.sharepoint.com",
            "https://outlook.office365.com",
            f"https://{tenant_id}-admin.sharepoint.com",
            "https://management.azure.com/",
            "https://vault.azure.net",
            "https://analysis.windows.net/powerbi/api",
            "https://datalake.azure.net",
            "https://api.loganalytics.io",
            "https://digitaltwins.azure.net",
            "af124e86-4e96-495a-b70a-90f90ab96707",
            "https://iothubs.azure.net",
            "https://database.windows.net",
            "https://dev.azuresynapse.net",
            "https://api.spaces.skype.com",
            "https://www.yammer.com",
            "https://storage.azure.com",
            "https://rest.media.azure.net",
            "https://batch.core.windows.net",
            "https://quantum.microsoft.com",
            "https://compliance.microsoft.com",
            "https://msmamservice.api.application",
        ],
        "cf36b471-5b44-428c-9ce7-313bf84528de": ["https://graph.windows.net"],
        "d3590ed6-52b3-4102-aeff-aad2292ab01c": [
            "https://graph.windows.net",
            "https://graph.microsoft.com",
            "https://management.core.windows.net",
            "https://manage.office.com",
            "https://api.diagnostics.office.com",
            "https://officeapps.live.com",
            f"https://{tenant_id}.sharepoint.com",
            "https://api.spaces.skype.com",
            "https://vault.azure.net",
            "https://management.azure.com/",
            f"https://{tenant_id}-my.sharepoint.com",
            "https://msmamservice.api.application",
            "https://outlook.office365.com",
            "https://outlook.office.com",
            "https://substrate.office.com",
            "https://webshell.suite.office.com",
            "https://api.loganalytics.io",
            "https://analysis.windows.net/powerbi/api",
            "https://batch.core.windows.net",
            "https://datalake.azure.net",
            "https://storage.azure.com",
            "https://rest.media.azure.net",
            "https://digitaltwins.azure.net",
            "https://compliance.microsoft.com",
            "https://database.windows.net",
            "https://quantum.microsoft.com",
            "https://iothubs.azure.net",
            "https://dev.azuresynapse.net",
            "d3590ed6-52b3-4102-aeff-aad2292ab01c",
            f"https://{tenant_id}-admin.sharepoint.com",
            "https://www.yammer.com",
        ],
    }

    client_resource_pairs = list(
        set(
            [
                (client, resource)
                for client, valid_resources in FOCI_CLIENT_VALID_RESOURCE_MAP.items()
                for resource in valid_resources
            ]
        )
    )

    total_requests = len(client_resource_pairs)

    if demo:
        max_requests = 100
    else:
        max_requests = total_requests

    for num_iterations, (new_client, resource) in enumerate(
        random.sample(client_resource_pairs, max_requests)
    ):
        new_scopes = f"{resource}/.default"

        if new_client == current_client and new_scopes == current_scopes:
            continue

        new_tokens = acquire_token_by_refresh_token(
            refresh_token=family_refresh_token,
            client_id=new_client,
            scopes=[new_scopes],
            tenant_id=tenant_id,
        )

        try:
            decoded_new_access_token = decode_jwt(new_tokens["access_token"])
            new_tokens = {**decoded_new_access_token, **new_tokens}
        except Exception as exc:
            print(f"[{num_iterations + 1} / {total_requests}] " + ("#" * 88))
            print(f"Old Token: {current_client} -> {current_scopes}")
            print(f"New Token: {new_client} -> {new_scopes}\n")

        formatted_new_scopes = "\n".join(
            [f"- {scope}" for scope in new_tokens["scope"].split()]
        )

        print(f"[{num_iterations + 1} / {total_requests}] " + ("#" * 88))
        print(f"Old Token: {current_client} -> {current_scopes}")
        print(f"New Token: {new_client} -> {new_scopes}")
        print(f"\nScopes in New Access Token:\n{formatted_new_scopes}\n")

        if chain:
            family_refresh_token = new_tokens["refresh_token"]

        current_client = new_client
        current_scopes = new_scopes

        family_tokens.append(new_tokens)

    return pd.json_normalize(family_tokens)
