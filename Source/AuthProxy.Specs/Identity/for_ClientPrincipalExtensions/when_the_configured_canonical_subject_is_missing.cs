// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Identity.for_ClientPrincipalExtensions;

public class when_the_configured_canonical_subject_is_missing : Specification
{
    DefaultHttpContext _context;
    ClientPrincipal? _result;

    void Establish()
    {
        var configuration = new C.AuthProxy
        {
            Authentication = new C.Authentication
            {
                OAuthProviders =
                [
                    new C.OAuthProvider
                    {
                        Name = "GitHub",
                        CanonicalIdentity = new C.CanonicalIdentity
                        {
                            ProviderKey = "workforce",
                            SubjectClaimType = "oid",
                            Issuer = "https://identity.example.com"
                        }
                    }
                ]
            }
        };
        var options = Substitute.For<IOptionsMonitor<C.Authentication>>();
        options.CurrentValue.Returns(configuration.Authentication);
        var services = new ServiceCollection()
            .AddSingleton<ICanonicalIdentityResolver>(new CanonicalIdentityResolver(options))
            .BuildServiceProvider();
        _context = new DefaultHttpContext
        {
            RequestServices = services,
            User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("sub", "old-sub"),
                new Claim("email", "person@example.com")
            ],
            "github"))
        };
    }

    void Because() => _result = _context.BuildClientPrincipal();

    [Fact] void should_fail_closed() => _result.ShouldBeNull();
    [Fact] void should_not_create_a_principal_id_header() => _context.Request.Headers.ContainsKey(Headers.PrincipalId).ShouldBeFalse();
}
