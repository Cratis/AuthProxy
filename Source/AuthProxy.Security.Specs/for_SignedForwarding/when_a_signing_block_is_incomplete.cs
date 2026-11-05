// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;

namespace Cratis.AuthProxy.Security.for_SignedForwarding;

/// <summary>A partial signing block is rejected before the deployment can serve requests.</summary>
public class when_a_signing_block_is_incomplete
{
    [Fact]
    public async Task should_fail_startup_with_a_redacted_configuration_path()
    {
        await using var harness = new InvalidForwardedIdentityHarness();
        var error = Assert.Throws<OptionsValidationException>(harness.CreateSecurityClient);
        Assert.Contains("Services:app:ForwardedIdentity:SecretBase64", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(Convert.ToBase64String(harness.ApplicationOrigin.Secret.Span), error.Message, StringComparison.Ordinal);
    }
}
