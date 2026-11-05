// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Reports signed and legacy flows without retaining any secret material.</summary>
public static class ForwardedIdentitySigningReport
{
    /// <summary>Lists every applicable outbound flow in the deployment.</summary>
    /// <param name="config">The gateway configuration.</param>
    /// <returns>The redacted diagnostic rows.</returns>
    public static IReadOnlyList<ForwardedIdentityFlowStatus> For(C.AuthProxy config)
    {
        var rows = new List<ForwardedIdentityFlowStatus>();
        foreach (var (name, service) in config.Services)
        {
            if (service.Backend is not null || service.Frontend is not null) rows.Add(Row(ForwardedIdentityFlow.ProxiedRequest, name, service.ForwardedIdentity, service.Backend?.BaseUrl ?? service.Frontend?.BaseUrl, config));
            if (service.BearerRoutes.Count > 0) rows.Add(Row(ForwardedIdentityFlow.BearerRoute, name, service.ForwardedIdentity, service.Backend?.BaseUrl, config));
            if (service.ParticipatesInIdentityResolution) rows.Add(Row(ForwardedIdentityFlow.IdentityDetails, name, service.ForwardedIdentity, service.Backend?.BaseUrl, config));
        }
        if (TenantSelectionMiddleware.TryGetSelectionOptions(config, out var selection)) rows.Add(Row(ForwardedIdentityFlow.TenantList, null, selection.ForwardedIdentity, selection.TenantsEndpoint, config));
        return rows;
    }

    static ForwardedIdentityFlowStatus Row(ForwardedIdentityFlow flow, string? service, C.ForwardedIdentitySigning? settings, string? address, C.AuthProxy config) =>
        new(flow, service, settings is not null, settings?.KeyId, settings?.Audience)
        {
            Transport = Uri.TryCreate(address, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps
                ? config.BackendTls.ClientCertificate is null ? BackendHops.BackendHopTransport.Tls : BackendHops.BackendHopTransport.MutualTls
                : BackendHops.BackendHopTransport.PlainHttp
        };
}
