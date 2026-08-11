// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier.when_logging_a_sign_in;

/// <summary>
/// The sign-in notification line is written at information level on every legacy-mode sign-in, so it is the
/// highest-volume disclosure of a provider subject the proxy could make — one line per person per sign-in.
/// </summary>
public class with_a_legacy_subject : given.a_sign_in_notifier
{
    const string SensitiveSubject = "sensitive-provider-subject";

    readonly RecordingLogger<SignInNotifier> _logger = new();

    protected override ClaimsPrincipal CreatePrincipal() => new(new ClaimsIdentity(
    [
        new Claim("sub", SensitiveSubject),
        new Claim("iss", "https://github.com"),
    ],
    "github"));

    protected override SignInNotifier CreateNotifier(
        C.AuthProxy configuration,
        IOptionsMonitor<C.AuthProxy> optionsMonitor,
        IHttpClientFactory httpClientFactory) =>
        new(optionsMonitor, new ClientLocationResolver(), httpClientFactory, _logger);

    async Task Because() => await _notifier.Notify(_httpContext, _principal);

    [Fact] void should_not_disclose_the_provider_subject() => _logger.Text.ShouldNotContain(SensitiveSubject);
    [Fact] void should_still_record_the_bounded_reason() => _logger.Text.ShouldContain("Sign-in notified");
}
