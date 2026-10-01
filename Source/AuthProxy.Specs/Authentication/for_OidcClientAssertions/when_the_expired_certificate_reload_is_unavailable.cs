// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.given;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Identity.Abstractions;

namespace Cratis.AuthProxy.Authentication.for_OidcClientAssertions;

public class when_the_expired_certificate_reload_is_unavailable : Specification
{
    readonly List<Exception> _failures = [];
    readonly List<int> _loadCounts = [];
    readonly List<string> _recoveredAssertions = [];

    async Task Because()
    {
        foreach (var reloadThrows in new[] { false, true })
        {
            var clock = new AdjustableTimeProvider(DateTimeOffset.UtcNow);
            using var expired = ClientCertificates.Rsa(clock.Now.AddDays(-30), clock.Now.AddDays(-1));
            using var replacement = ClientCertificates.Rsa(clock.Now.AddDays(-1), clock.Now.AddDays(30));
            var loads = 0;
            var loader = Substitute.For<ICredentialsLoader>();
            loader.LoadCredentialsIfNeededAsync(Arg.Any<CredentialDescription>(), Arg.Any<CredentialSourceLoaderParameters?>())
                .Returns(call =>
                {
                    loads++;
                    var description = call.Arg<CredentialDescription>();
                    if (loads == 1 || loads == 4)
                    {
                        description.Certificate = loads == 1 ? expired : replacement;
                        description.CachedValue = description.Certificate;
                        return Task.CompletedTask;
                    }

                    return reloadThrows
                        ? Task.FromException(new OidcClientCredentialUnavailable("The certificate store is unavailable."))
                        : Task.CompletedTask;
                });
            loader.When(_ => _.ResetCredentials(Arg.Any<IEnumerable<CredentialDescription>>()))
                .Do(call =>
                {
                    var description = call.Arg<IEnumerable<CredentialDescription>>().Single();
                    description.Certificate = null;
                    description.CachedValue = null;
                });
            var provider = new C.OidcProvider
            {
                Name = "Workforce",
                ClientId = "client-id",
                Authority = "https://login.example.com/tenant",
                ClientCredential = new() { Source = C.OidcClientCredentialSource.CertificateStore }
            };
            var assertions = new OidcClientAssertions(loader, clock, NullLogger<OidcClientAssertions>.Instance);

            _failures.Add(await Catch.Exception(() => assertions.Create("workforce", provider, provider.Authority, CancellationToken.None)));
            _loadCounts.Add(loads);
            clock.Now = clock.Now.AddSeconds(59);
            _failures.Add(await Catch.Exception(() => assertions.Create("workforce", provider, provider.Authority, CancellationToken.None)));
            _loadCounts.Add(loads);
            clock.Now = clock.Now.AddSeconds(1);
            _failures.Add(await Catch.Exception(() => assertions.Create("workforce", provider, provider.Authority, CancellationToken.None)));
            _loadCounts.Add(loads);
            clock.Now = clock.Now.AddSeconds(59);
            _failures.Add(await Catch.Exception(() => assertions.Create("workforce", provider, provider.Authority, CancellationToken.None)));
            _loadCounts.Add(loads);
            clock.Now = clock.Now.AddSeconds(1);
            _recoveredAssertions.Add(await assertions.Create("workforce", provider, provider.Authority, CancellationToken.None));
            _loadCounts.Add(loads);
        }
    }

    [Fact] void should_fail_closed_for_null_and_failed_reloads() => _failures.TrueForAll(_ => _ is OidcClientCredentialUnavailable).ShouldBeTrue();
    [Fact] void should_load_only_once_per_minute_after_the_expiry_reset() => _loadCounts.ShouldEqual(new[] { 2, 2, 3, 3, 4, 2, 2, 3, 3, 4 });
    [Fact] void should_resume_signing_when_a_later_reload_succeeds() => _recoveredAssertions.TrueForAll(_ => !string.IsNullOrWhiteSpace(_)).ShouldBeTrue();

    sealed class AdjustableTimeProvider(DateTimeOffset now) : TimeProvider
    {
        internal DateTimeOffset Now { get; set; } = now;

        public override DateTimeOffset GetUtcNow() => Now;
    }
}
