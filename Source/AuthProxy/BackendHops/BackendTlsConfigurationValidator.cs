// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BackendHops;

/// <summary>
/// Validates mounted material and the transport required for signed identity-bearing hops.
/// </summary>
/// <param name="timeProvider">The validity clock.</param>
internal sealed class BackendTlsConfigurationValidator(TimeProvider timeProvider) : IValidateOptions<C.AuthProxy>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        var failures = new List<string>();
        if (!Enum.IsDefined(options.Profile)) failures.Add($"{C.AuthProxy.SectionKey}:Profile must be Default or LocalDevelopment.");
        if (options.BackendTls.ReloadInterval < C.BackendTls.MinimumReloadInterval)
        {
            failures.Add($"{C.AuthProxy.SectionKey}:BackendTls:ReloadInterval must be at least five seconds.");
        }

        if (!BackendTlsMaterial.TryLoad(options.BackendTls, timeProvider.GetUtcNow(), out var material, out var problem))
        {
            failures.Add(problem!);
        }
        else
        {
            material!.ClientCertificate?.Dispose();
            foreach (var anchor in material.TrustAnchors) anchor.Dispose();
        }

        if (options.Profile != C.DeploymentProfile.LocalDevelopment)
        {
            foreach (var hop in BackendHopHosts.SignedHops(options))
            {
                if (!Uri.TryCreate(hop.Address, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
                {
                    failures.Add($"{hop.Key} must use HTTPS for a signed identity-bearing hop.");
                }
                if (options.BackendTls.ClientCertificate is null)
                {
                    failures.Add($"{C.AuthProxy.SectionKey}:BackendTls:ClientCertificate is required for {hop.Key}.");
                }
            }
        }

        failures.AddRange(IdentityBackChannelFailures(options));

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    static IEnumerable<string> IdentityBackChannelFailures(C.AuthProxy options) => options.BackendTls.RequireTlsOnIdentityHops
        ? BackendHopHosts.IdentityBearingHops(options)
            .DistinctBy(channel => channel.Key)
            .Where(channel => !BackendHopHosts.AllowsIdentityBackChannel(options, channel.Address))
            .Select(channel => $"{channel.Key} must use HTTPS for an identity-bearing hop; HTTP is allowed only for loopback targets in LocalDevelopment.")
        : BackendHopHosts.RequiresHttps(options)
            ? BackendHopHosts.IdentityBackChannels(options)
                .Where(channel => !BackendHopHosts.IsHttps(channel.Address))
                .Select(channel => $"{channel.Key} must use HTTPS while forwarded-identity signing is configured.")
            : [];
}
