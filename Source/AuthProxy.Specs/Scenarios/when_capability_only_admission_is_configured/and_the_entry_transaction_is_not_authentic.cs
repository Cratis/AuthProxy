// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;

namespace Cratis.AuthProxy.Scenarios.when_capability_only_admission_is_configured;

/// <summary>
/// An entry transaction the deployment did not seal is not an entry transaction. Altered, truncated,
/// invented and sealed-by-somebody-else all answer exactly as an absent one does, so probing the cookie
/// teaches an attacker nothing about what a real one looks like.
/// </summary>
/// <param name="factory">The closed proxy under test.</param>
public class and_the_entry_transaction_is_not_authentic(AuthProxyFactory factory) : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    readonly Dictionary<string, string> _shapes = new(StringComparer.Ordinal);

    string _presentingNothing = string.Empty;

    public async Task InitializeAsync()
    {
        using var client = factory.CreateProbingClient();

        _presentingNothing = (await ObservedAnswer.Capture(client, "/", HttpMethod.Get)).Shape;

        var authentic = await AuthenticEntryTransaction(client);

        _shapes["altered"] = await Present(client, $"{authentic[..^1]}{(authentic[^1] == 'A' ? 'B' : 'A')}");
        _shapes["truncated"] = await Present(client, authentic[..(authentic.Length / 2)]);
        _shapes["invented"] = await Present(client, "CfDJ8not-a-real-protected-value");
        _shapes["empty"] = await Present(client, string.Empty);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_answer_every_unauthentic_transaction_the_way_an_absent_one_is_answered() =>
        Assert.Empty(_shapes
            .Where(shape => !string.Equals(shape.Value, _presentingNothing, StringComparison.Ordinal))
            .Select(shape => shape.Key));

    static async Task<string> AuthenticEntryTransaction(HttpClient client)
    {
        using var presentation = new HttpRequestMessage(HttpMethod.Post, AuthProxyFactory.AdmissionPath)
        {
            Content = new StringContent(AuthProxyFactory.MintCapability(), Encoding.UTF8, "text/plain"),
        };
        using var admission = await client.SendAsync(presentation);

        var setCookie = admission.Headers.GetValues("Set-Cookie").First();
        var value = setCookie[(setCookie.IndexOf('=', StringComparison.Ordinal) + 1)..];

        return value[..value.IndexOf(';', StringComparison.Ordinal)];
    }

    static async Task<string> Present(HttpClient client, string entryTransaction)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/");
        request.Headers.TryAddWithoutValidation("Cookie", $"{Cookies.EntryTransaction}={entryTransaction}");

        using var response = await client.SendAsync(request);

        var headers = response.Headers
            .Concat(response.Content.Headers)
            .Where(header => !string.Equals(header.Key, "Date", StringComparison.OrdinalIgnoreCase))
            .Select(header => $"{header.Key}: {string.Join(',', header.Value)}")
            .Order(StringComparer.Ordinal);

        return $"{(int)response.StatusCode}\n{string.Join('\n', headers)}\n{await response.Content.ReadAsStringAsync()}";
    }
}
