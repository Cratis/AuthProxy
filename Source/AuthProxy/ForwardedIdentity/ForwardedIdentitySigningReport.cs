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
            if (service.Backend is not null || service.Frontend is not null) rows.Add(Row(ForwardedIdentityFlow.ProxiedRequest, name, service.ForwardedIdentity));
            if (service.BearerRoutes.Count > 0) rows.Add(Row(ForwardedIdentityFlow.BearerRoute, name, service.ForwardedIdentity));
            if (service.ParticipatesInIdentityResolution) rows.Add(Row(ForwardedIdentityFlow.IdentityDetails, name, service.ForwardedIdentity));
        }
        if (TenantSelectionMiddleware.TryGetSelectionOptions(config, out var selection)) rows.Add(Row(ForwardedIdentityFlow.TenantList, null, selection.ForwardedIdentity));
        return rows;
    }

    static ForwardedIdentityFlowStatus Row(ForwardedIdentityFlow flow, string? service, C.ForwardedIdentitySigning? settings) => new(flow, service, settings is not null, settings?.KeyId, settings?.Audience);
}
