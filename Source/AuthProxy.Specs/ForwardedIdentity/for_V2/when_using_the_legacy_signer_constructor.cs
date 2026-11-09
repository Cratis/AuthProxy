// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_V2;

public class when_using_the_legacy_signer_constructor : Specification
{
    [Fact]
    public void should_preserve_the_three_parameter_binary_signature()
    {
        Assert.NotNull(typeof(ForwardedIdentitySigner).GetConstructor(
            [typeof(IOptionsMonitor<C.AuthProxy>), typeof(TimeProvider), typeof(ILogger<ForwardedIdentitySigner>)]));
    }

    [Fact]
    public void should_warn_once_on_first_v2_use_without_an_http_context_accessor()
    {
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(new C.AuthProxy { Services = new Dictionary<string, C.Service> { ["app"] = new() { ForwardedIdentity = when_signing_with_explicit_trusted_context.Settings() } } });
        var logger = new RecordingLogger<ForwardedIdentitySigner>();
        using var signer = new ForwardedIdentitySigner(monitor, TimeProvider.System, logger);
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.example/private");
        Assert.Equal(ForwardedIdentitySigningOutcome.Refused, signer.Sign(request, when_signing_with_explicit_trusted_context.Target()));
        Assert.Equal(ForwardedIdentitySigningOutcome.Refused, signer.Sign(request, when_signing_with_explicit_trusted_context.Target()));
        var warning = Assert.Single(logger.Messages, message => message.Contains("IHttpContextAccessor", StringComparison.Ordinal));
        Assert.Equal(LogLevel.Warning, logger.Levels[logger.Messages.ToList().IndexOf(warning)]);
    }
}
