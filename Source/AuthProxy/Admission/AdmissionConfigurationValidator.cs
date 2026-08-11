// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Admission;

/// <summary>
/// Refuses a configuration that closes the door without saying who holds the key.
/// </summary>
/// <remarks>
/// Every failure here is one that would otherwise start cleanly and then refuse every caller alive, with a
/// <c>404</c> that says nothing about why. Naming it at startup names it at the one moment somebody is
/// watching.
/// </remarks>
public class AdmissionConfigurationValidator : IValidateOptions<C.AuthProxy>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        // Asked before anything else, because every question below is asked of a mode that was understood. A
        // name the binder cannot parse already refuses to start; a number outside the enum binds silently, and
        // would otherwise walk straight past the early return into a deployment gated by nothing.
        if (!Enum.IsDefined(options.Admission.Mode))
        {
            return ValidateOptionsResult.Fail(
                $"{C.Admission.SectionKey}:{nameof(C.Admission.Mode)} is set to '{(int)options.Admission.Mode}', which is not a mode this AuthProxy has. " +
                $"A mode it cannot recognize is treated as closed rather than as public, so the value has to name one of: {string.Join(", ", Enum.GetNames<C.AdmissionMode>())}.");
        }

        if (options.Admission.Mode != C.AdmissionMode.CapabilityOnly)
        {
            return ValidateOptionsResult.Success;
        }

        var failures = new List<string>();

        AddCapabilityFailures(options.Admission.Capability, failures);

        if (options.Admission.EntryLifetime <= TimeSpan.Zero)
        {
            failures.Add($"{C.Admission.SectionKey}:{nameof(C.Admission.EntryLifetime)} must be greater than zero. An entry that has expired before it is issued admits nobody.");
        }

        if (options.Invite is not null)
        {
            failures.Add(
                $"{C.Admission.SectionKey}:{nameof(C.Admission.Mode)} cannot be {nameof(C.AdmissionMode.CapabilityOnly)} while {C.AuthProxy.SectionKey}:Invite is configured. " +
                "Two capability mechanisms in one deployment is a misconfiguration: an invitation is a capability with its own issuance, its own browser state and its own refusals, and it would be reached only through a door admission has already closed. " +
                "Refusing the combination rather than silently ordering the two keeps the door open to unifying them later — an invitation becoming one kind of admission capability — instead of freezing whichever precedence happened to ship.");
        }

        return failures.Count > 0
            ? ValidateOptionsResult.Fail(failures)
            : ValidateOptionsResult.Success;
    }

    static void AddCapabilityFailures(C.AdmissionCapability? capability, List<string> failures)
    {
        const string verifierUrlKey = $"{C.Admission.SectionKey}:Capability:{nameof(C.AdmissionCapability.VerifierUrl)}";

        if (capability is null || string.IsNullOrWhiteSpace(capability.VerifierUrl))
        {
            failures.Add($"{verifierUrlKey} must name the endpoint that decides whether a presented capability admits. Without one nothing can ever be admitted and the deployment refuses every caller.");
            return;
        }

        // The scheme has to be named, not merely parsed: an absolute file-system path parses as an absolute
        // URI on Unix, so a relative-looking value would otherwise be accepted and then never reach anything.
        if (!Uri.TryCreate(capability.VerifierUrl, UriKind.Absolute, out var verifier)
            || (verifier.Scheme != Uri.UriSchemeHttp && verifier.Scheme != Uri.UriSchemeHttps))
        {
            failures.Add($"{verifierUrlKey} must be an absolute http or https URL.");
        }

        if (string.IsNullOrWhiteSpace(capability.Path) || !capability.Path.StartsWith('/'))
        {
            failures.Add($"{C.Admission.SectionKey}:Capability:{nameof(C.AdmissionCapability.Path)} must be an absolute request path beginning with '/'.");
        }

        if (capability.MaximumLength <= 0)
        {
            failures.Add($"{C.Admission.SectionKey}:Capability:{nameof(C.AdmissionCapability.MaximumLength)} must be greater than zero. A bound of nothing refuses every capability.");
        }
    }
}
