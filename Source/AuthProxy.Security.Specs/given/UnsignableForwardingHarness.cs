// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using NSubstitute;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// The deployment of <see cref="SecurityHarness"/>, configured to sign what it forwards with a signer that fails.
/// </summary>
/// <remarks>
/// A configuration that would fail to sign is refused at startup, so a signer that fails at run time is the only way
/// to show what happens to a request that cannot be signed: it must never reach the origin unsigned.
/// </remarks>
public class UnsignableForwardingHarness : SecurityHarness
{
    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);

        var signer = Substitute.For<IForwardedIdentitySigner>();
        signer.IsEnabled.Returns(true);
        signer.AudienceFor(Arg.Any<string>()).Returns(callInfo => callInfo.Arg<string>());
        signer.Sign(Arg.Any<HttpRequestMessage>(), Arg.Any<string>()).Returns(ForwardedIdentitySigningStatus.Failed);

        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IForwardedIdentitySigner>();
            services.AddSingleton(signer);
        });
    }
}
