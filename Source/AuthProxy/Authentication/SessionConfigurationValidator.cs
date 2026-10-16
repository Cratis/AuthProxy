// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ReverseProxy;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Validates the session cookie name and domain at startup.
/// </summary>
/// <remarks>
/// A shared cookie domain turns a per-host session into one that every host under the domain honors, so a
/// declaration that cannot be honored safely stops the host with a message naming the problem rather than
/// surfacing later as a session that quietly does not travel, or travels further than intended.
/// </remarks>
public class SessionConfigurationValidator : IValidateOptions<C.AuthProxy>
{
    const string HostOnlyPrefix = "__Host-";
    const string TokenSeparators = "()<>@,;:\\\"/[]?={} \t";

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        var failures = new List<string>();
        var domain = SessionCookie.DomainOf(options.Session);

        ValidateCookieName(options.Session, domain, failures);

        if (domain is not null)
        {
            ValidateDomain(options, domain, failures);
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    static void ValidateCookieName(C.Session session, string? domain, List<string> failures)
    {
        var key = $"{C.Session.SectionKey}:{nameof(C.Session.CookieName)}";

        if (string.IsNullOrWhiteSpace(session.CookieName))
        {
            failures.Add($"{key} is blank. Leave it unset to use '{C.Session.DefaultCookieName}', or name the session cookie.");
            return;
        }

        var cookieName = session.CookieName.Trim();
        var illegal = cookieName.FirstOrDefault(_ => _ <= ' ' || _ >= '\u007f' || TokenSeparators.Contains(_));
        if (illegal != default)
        {
            failures.Add($"{key} '{cookieName}' is not a valid cookie name: it contains '{illegal}', and a cookie name may only use RFC 6265 token characters (letters, digits and !#$%&'*+-.^_`|~).");
        }

        if (domain is not null && cookieName.StartsWith(HostOnlyPrefix, StringComparison.OrdinalIgnoreCase))
        {
            failures.Add($"{key} '{cookieName}' uses the {HostOnlyPrefix} prefix, which browsers only accept on a cookie without a Domain, and {C.Session.SectionKey}:{nameof(C.Session.CookieDomain)} is set. Choose another name, or leave the domain unset.");
        }
    }

    static void ValidateDomain(C.AuthProxy options, string domain, List<string> failures)
    {
        var key = $"{C.Session.SectionKey}:{nameof(C.Session.CookieDomain)}";
        var rejection = CookieDomainScope.Evaluate(domain, out var normalized);
        if (rejection != CookieDomainRejection.None)
        {
            failures.Add($"{key} '{domain}' cannot be used: {Explain(rejection)}");
            return;
        }

        foreach (var (serviceName, service) in options.Services)
        {
            foreach (var host in ServiceRoutes.HostsOf(service).Where(_ => !CookieDomainScope.Covers(normalized, _.Host)))
            {
                failures.Add($"Service '{serviceName}' declares host '{host.Host}', which is outside {key} '{domain}'. A browser would not send the session cookie there, so the host would never be signed in; move the host under the domain or widen the domain.");
            }
        }

        if (options.TenantResolutions.Any(_ => _.Strategy == C.TenantSourceIdentifierResolverType.SubHost))
        {
            failures.Add($"{key} is set while a tenant resolution uses the SubHost strategy. One session would then span every tenant host, and the tenant check only confirms that a tenant exists, not that the person belongs to it — today the host-only session cookie is what keeps a session for one tenant off the next tenant's host. Remove the domain, or resolve tenants another way.");
        }
    }

    static string Explain(CookieDomainRejection rejection) => rejection switch
    {
        CookieDomainRejection.NotAHost => "it is not a host name, such as .example.com. Wildcards, schemes and paths are not allowed.",
        CookieDomainRejection.HasPort => "it names a port, and a cookie domain is a host name only.",
        CookieDomainRejection.IpAddress => "it is an IP address, which cannot be shared with other hosts.",
        CookieDomainRejection.SingleLabel => "it has no dot, so it is a top-level domain or a single-label host that browsers refuse as a cookie domain. Use a registrable domain, such as .example.com.",
        CookieDomainRejection.NotAscii => "it is not ASCII. Write an internationalized domain in its punycode (xn--) form.",
        _ => "it is not usable."
    };
}
