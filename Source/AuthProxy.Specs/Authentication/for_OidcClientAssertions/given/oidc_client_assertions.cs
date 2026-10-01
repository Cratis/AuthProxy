// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Identity.Abstractions;
using Microsoft.Identity.Web;

namespace Cratis.AuthProxy.Authentication.for_OidcClientAssertions.given;

/// <summary>
/// Provides <see cref="OidcClientAssertions"/> over the real Microsoft.Identity.Web credential loader and a scratch
/// directory for credential files.
/// </summary>
public class oidc_client_assertions : Specification
{
    protected const string Scheme = "workforce";
    protected const string TokenEndpoint = "https://login.example.com/tenant/oauth2/v2.0/token";

    protected string _directory;
    protected ICredentialsLoader _loader;
    protected C.OidcProvider _provider;
    protected OidcClientAssertions _assertions;

    void Establish()
    {
        _directory = Directory.CreateTempSubdirectory("authproxy-client-credential-").FullName;
        _loader = new DefaultCredentialsLoader(NullLogger<DefaultCredentialsLoader>.Instance);
        _provider = new()
        {
            Name = "Workforce",
            Authority = "https://login.example.com/tenant/v2.0",
            ClientId = "client-id",
            ClientCredential = new()
        };
        _assertions = new(_loader, TimeProvider.System, NullLogger<OidcClientAssertions>.Instance);
    }

    void Destroy() => Directory.Delete(_directory, recursive: true);
}
