// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;

namespace Cratis.AuthProxy.Security.for_FreshAuthentication;

/// <summary>Method-scoped freshness cannot start without an explicit per-service backend contract.</summary>
public class when_method_scoping_is_not_attested
{
    [Theory]
    [InlineData(null)]
    [InlineData(false)]
    public void should_refuse_startup_when_the_attestation_is_missing_or_false(bool? attested)
    {
        using var harness = new FreshAuthenticationHarness { MethodOverrideUnsupported = attested };
        var error = Assert.Throws<OptionsValidationException>(() => harness.CreateBearerClient().Dispose());
        Assert.Contains(nameof(C.Service.FreshAuthenticationMethodOverrideUnsupported), error.Message, StringComparison.Ordinal);
        Assert.Contains("backend does not support method overrides", error.Message, StringComparison.Ordinal);
        Assert.Empty(harness.Origin.Received);
    }
}
