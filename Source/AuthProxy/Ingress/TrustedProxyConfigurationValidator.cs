// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Ingress;

/// <summary>
/// Refuses a configuration naming a trusted proxy that is not an address or a CIDR range.
/// </summary>
/// <remarks>
/// Dropping the entry is the one thing that must not happen. The remaining entries would still form a
/// boundary, so the proxy would start and quietly refuse the forwarded headers of the very ingress the
/// operator meant to trust — every sign-in address recorded as the inner load balancer, every geo header
/// discarded, and nothing anywhere saying why. Failing at startup names the offending value instead, at the
/// one moment somebody is watching.
/// <para>
/// A typo in the other direction is worse still: an entry meant to narrow the boundary that instead parses as
/// nothing leaves a deployment believing it is protected while the mistyped range protects nothing.
/// </para>
/// </remarks>
public class TrustedProxyConfigurationValidator : IValidateOptions<C.Ingress>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.Ingress options)
    {
        var failures = options.TrustedProxies
            .Select((entry, index) => (Entry: entry, Index: index))
            .Where(_ => TrustedProxyAddress.Resolve(_.Entry) is null)
            .Select(_ => $"{C.Ingress.SectionKey}:TrustedProxies:{_.Index} is '{_.Entry}', which is not an IP address or a CIDR range. Write a peer as '10.0.0.7' or '2001:db8::1', and a range as '10.0.0.0/8' or '2001:db8::/32'.")
            .ToList();

        return failures.Count > 0
            ? ValidateOptionsResult.Fail(failures)
            : ValidateOptionsResult.Success;
    }
}
