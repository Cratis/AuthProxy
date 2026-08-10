// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_CanonicalIdentityResolver.given;

public class a_canonical_identity_resolver : Specification
{
    protected const string ProviderKey = "entra-workforce";
    protected const string Scheme = "microsoft-entra";
    protected const string Issuer = "https://login.microsoftonline.com/tenant-id/v2.0";

    protected C.AuthProxy _configuration;
    protected CanonicalIdentityResolver _resolver;

    protected virtual C.AuthProxy CreateConfiguration() => new()
    {
        Authentication = new C.Authentication
        {
            OidcProviders =
            [
                new C.OidcProvider
                {
                    Name = "Microsoft Entra",
                    CanonicalIdentity = new C.CanonicalIdentity
                    {
                        ProviderKey = ProviderKey,
                        SubjectClaimType = "oid"
                    }
                }
            ]
        }
    };

    void Establish()
    {
        _configuration = CreateConfiguration();
        var options = Substitute.For<IOptionsMonitor<C.Authentication>>();
        options.CurrentValue.Returns(_configuration.Authentication);
        _resolver = new CanonicalIdentityResolver(options);
    }

    protected static ClaimsPrincipal Principal(params Claim[] claims) =>
        new(new ClaimsIdentity(claims, Scheme));
}
