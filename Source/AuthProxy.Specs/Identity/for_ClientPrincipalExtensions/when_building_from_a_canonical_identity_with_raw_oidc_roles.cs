// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Identity.for_ClientPrincipalExtensions;

/// <summary>
/// Specifies that provider-native OIDC role claims survive canonical principal forwarding without widening the accepted claim names.
/// </summary>
public class when_building_from_a_canonical_identity_with_raw_oidc_roles : Specification
{
    ClientPrincipal? _result;

    void Establish()
    {
        var configuration = new C.Authentication
        {
            OidcProviders =
            [
                new C.OidcProvider
                {
                    Name = "Microsoft Entra",
                    CanonicalIdentity = new C.CanonicalIdentity
                    {
                        ProviderKey = "workforce",
                        SubjectClaimType = "oid"
                    }
                }
            ]
        };
        var options = Substitute.For<IOptionsMonitor<C.Authentication>>();
        options.CurrentValue.Returns(configuration);
        var resolver = CreateResolver(options, configuration);
        var enriched = resolver.Resolve(
            new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("oid", "subject-42"),
                new Claim("role", "raw-role"),
                new Claim("roles", "raw-roles"),
                new Claim(ClaimTypes.Role, "mapped-role"),
                new Claim("Role", "case-varied-role"),
                new Claim("unrelated_role", "unrelated-role")
            ],
            "microsoft-entra")),
            "microsoft-entra",
            "https://identity.example.com/tenant",
            isFreshAuthentication: true);
        var services = new ServiceCollection()
            .AddSingleton<ICanonicalIdentityResolver>(resolver)
            .BuildServiceProvider();
        var context = new DefaultHttpContext
        {
            RequestServices = services,
            User = enriched.Principal!
        };

        _result = context.BuildClientPrincipal();
    }

    [Fact] void should_preserve_only_the_exact_supported_role_claim_types() =>
        _result!.UserRoles.ShouldContainOnly("raw-role", "raw-roles", "mapped-role", "anonymous", "authenticated");

    static CanonicalIdentityResolver CreateResolver(IOptionsMonitor<C.Authentication> options, C.Authentication authentication)
    {
        var constructor = typeof(CanonicalIdentityResolver).GetConstructor([typeof(IOptionsMonitor<C.Authentication>)]);
        if (constructor is not null)
        {
            return (CanonicalIdentityResolver)constructor.Invoke([options]);
        }

        var rootOptions = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        rootOptions.CurrentValue.Returns(new C.AuthProxy { Authentication = authentication });
        return (CanonicalIdentityResolver)typeof(CanonicalIdentityResolver)
            .GetConstructor([typeof(IOptionsMonitor<C.AuthProxy>)])!
            .Invoke([rootOptions]);
    }
}
