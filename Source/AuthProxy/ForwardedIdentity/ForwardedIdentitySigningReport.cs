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
        List<ForwardedIdentityFlowStatus> rows = [];
        foreach (var (name, service) in config.Services)
        {
            if (service.Backend is not null || service.Frontend is not null) rows.Add(Row(ForwardedIdentityFlow.ProxiedRequest, name, service.ForwardedIdentity, service.Backend?.BaseUrl ?? service.Frontend?.BaseUrl, config));
            if (service.BearerRoutes.Count > 0) rows.Add(Row(ForwardedIdentityFlow.BearerRoute, name, service.ForwardedIdentity, service.Backend?.BaseUrl, config));
            if (service.ParticipatesInIdentityResolution) rows.Add(Row(ForwardedIdentityFlow.IdentityDetails, name, service.ForwardedIdentity, service.Backend?.BaseUrl, config));
        }
        if (TenantSelectionMiddleware.TryGetSelectionOptions(config, out var selection)) rows.Add(Row(ForwardedIdentityFlow.TenantList, null, selection.ForwardedIdentity, selection.TenantsEndpoint, config));
        rows.AddRange(Callbacks(config));
        rows.AddRange(OnBehalf(config));
        rows.AddRange(BodyFlows(config));
        return rows;
    }

    static IEnumerable<ForwardedIdentityFlowStatus> Callbacks(C.AuthProxy config) => config.Services
        .Where(pair => pair.Value.SignInCallback is not null && pair.Value.Backend is not null)
        .Select(pair => Row(ForwardedIdentityFlow.SignInCallback, pair.Key, pair.Value.ForwardedIdentity, pair.Value.Backend!.BaseUrl, config));

    static IEnumerable<ForwardedIdentityFlowStatus> OnBehalf(C.AuthProxy config)
    {
        if (config.OnBehalf is not { } onBehalf) yield break;
        if (!config.Services.TryGetValue(onBehalf.Service, out var application)) yield break;
        if (application.Backend is { } backend) yield return Row(ForwardedIdentityFlow.OnBehalf, onBehalf.Service, null, backend.BaseUrl, config) with { IsAttested = true };
    }

    static IEnumerable<ForwardedIdentityFlowStatus> BodyFlows(C.AuthProxy config)
    {
        var flows = new (ForwardedIdentityFlow Flow, string? Address)[]
        {
            (ForwardedIdentityFlow.InvitationStage, config.Invite?.StageUrl),
            (ForwardedIdentityFlow.InvitationExchange, config.Invite?.ExchangeUrl),
            (ForwardedIdentityFlow.LinkExchange, config.Link?.ExchangeUrl),
            (ForwardedIdentityFlow.SignInNotification, config.SignIn?.NotifyUrl)
        };
        foreach (var (flow, address) in flows.Where(flow => !string.IsNullOrWhiteSpace(flow.Address)))
        {
            var row = Row(flow, null, null, address, config);
            if (row.Transport == BackendHops.BackendHopTransport.MutualTls && !BackendHops.BackendHopHosts.For(config).Contains(new Uri(address!, UriKind.Absolute).IdnHost))
            {
                row = row with { Transport = BackendHops.BackendHopTransport.Tls };
            }
            yield return row;
        }
    }

    static ForwardedIdentityFlowStatus Row(ForwardedIdentityFlow flow, string? service, C.ForwardedIdentitySigning? settings, string? address, C.AuthProxy config) =>
        new(flow, service, settings is not null, settings?.KeyId, settings?.Audience)
        {
            Version = settings?.Version,
            Transport = Uri.TryCreate(address, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps
                ? config.BackendTls.ClientCertificate is null ? BackendHops.BackendHopTransport.Tls : BackendHops.BackendHopTransport.MutualTls
                : BackendHops.BackendHopTransport.PlainHttp
        };
}
