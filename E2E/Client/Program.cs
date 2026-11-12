// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Net.Http.Headers;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;

// Drives the AuthProxy image from the outside the way an Arc application's consumer would: authenticate, then
// receive an observable query over SSE and WebSocket and run a command. Any failure exits non-zero.
var baseAddress = new Uri(Environment.GetEnvironmentVariable("E2E_BASE_URL") ?? "http://localhost:8080");
var clientSecret = Environment.GetEnvironmentVariable("E2E_CLIENT_SECRET") ?? "e2e-throwaway-secret";
const string QueryName = "ArcSample.Greeting.Observe";
const string ExpectedMessage = "hello-through-authproxy";
var deadline = TimeSpan.FromSeconds(15);

using var http = new HttpClient { BaseAddress = baseAddress, Timeout = Timeout.InfiniteTimeSpan };
string? token = null;

await Step("unauthenticated query stream is refused", async cancellation =>
{
    using var response = await http.GetAsync("/.cratis/queries/sse", HttpCompletionOption.ResponseHeadersRead, cancellation);
    return response.StatusCode == HttpStatusCode.OK
        ? throw new InvalidOperationException("an unauthenticated caller was served the query stream")
        : $"status {(int)response.StatusCode}";
});

await Step("client credentials are exchanged for a token", async cancellation =>
{
    using var form = new FormUrlEncodedContent(new Dictionary<string, string>
    {
        ["grant_type"] = "client_credentials",
        ["service"] = "arc",
        ["client_id"] = "e2e-client",
        ["client_secret"] = clientSecret,
    });
    using var response = await http.PostAsync("/.cratis/token", form, cancellation);
    var body = await response.Content.ReadAsStringAsync(cancellation);
    response.EnsureSuccessStatusCode();
    token = JsonDocument.Parse(body).RootElement.GetProperty("access_token").GetString();
    return token is { Length: > 0 } ? "token issued" : throw new InvalidOperationException("no access_token in the response");
});

HttpRequestMessage Authorized(HttpMethod method, string path)
{
    var request = new HttpRequestMessage(method, path);
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
    return request;
}

await Step("observable query is delivered over SSE", async cancellation =>
{
    using var stream = Authorized(HttpMethod.Get, "/.cratis/queries/sse");
    stream.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
    using var response = await http.SendAsync(stream, HttpCompletionOption.ResponseHeadersRead, cancellation);
    response.EnsureSuccessStatusCode();
    using var reader = new StreamReader(await response.Content.ReadAsStreamAsync(cancellation));

    var connection = JsonDocument.Parse(await NextData(reader, cancellation)).RootElement;
    var connectionId = connection.GetProperty("payload").GetString();

    using var subscribe = Authorized(HttpMethod.Post, "/.cratis/queries/sse/subscribe");
    subscribe.Content = new StringContent(
        JsonSerializer.Serialize(new { connectionId, queryId = "sse-1", request = new { queryName = QueryName } }),
        Encoding.UTF8,
        "application/json");
    using var subscribed = await http.SendAsync(subscribe, cancellation);
    subscribed.EnsureSuccessStatusCode();

    var result = await ReadUntilMessage(() => NextData(reader, cancellation));

    using var unsubscribe = Authorized(HttpMethod.Post, "/.cratis/queries/sse/unsubscribe");
    unsubscribe.Content = new StringContent(
        JsonSerializer.Serialize(new { connectionId, queryId = "sse-1" }),
        Encoding.UTF8,
        "application/json");
    using var unsubscribed = await http.SendAsync(unsubscribe, cancellation);
    unsubscribed.EnsureSuccessStatusCode();
    return result;
});

await Step("observable query is delivered over WebSocket", async cancellation =>
{
    using var socket = new ClientWebSocket();
    socket.Options.SetRequestHeader("Authorization", $"Bearer {token}");
    await socket.ConnectAsync(new UriBuilder(baseAddress) { Scheme = "ws", Path = "/.cratis/queries/ws" }.Uri, cancellation);

    var subscribe = JsonSerializer.Serialize(new { type = "Subscribe", queryId = "ws-1", payload = new { queryName = QueryName } });
    await socket.SendAsync(Encoding.UTF8.GetBytes(subscribe), WebSocketMessageType.Text, true, cancellation);
    var result = await ReadUntilMessage(() => NextSocketMessage(socket, cancellation));
    await socket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "done", cancellation);
    return result;
});

Console.WriteLine("E2E PASSED");
return 0;

async Task Step(string name, Func<CancellationToken, Task<string>> action)
{
    using var cancellation = new CancellationTokenSource(deadline);
    try
    {
        var observed = await action(cancellation.Token);
        Console.WriteLine($"PASS {name}: {observed}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"FAIL {name}: {ex.GetType().Name}: {ex.Message}");
        Environment.Exit(1);
    }
}

static async Task<string> NextData(StreamReader reader, CancellationToken cancellation)
{
    while (await reader.ReadLineAsync(cancellation) is { } line)
    {
        if (line.StartsWith("data:", StringComparison.Ordinal))
        {
            return line["data:".Length..].Trim();
        }
    }

    throw new InvalidOperationException("the event stream ended before a message arrived");
}

static async Task<string> NextSocketMessage(ClientWebSocket socket, CancellationToken cancellation)
{
    var buffer = new byte[16 * 1024];
    using var message = new MemoryStream();
    WebSocketReceiveResult received;
    do
    {
        received = await socket.ReceiveAsync(buffer, cancellation);
        message.Write(buffer, 0, received.Count);
    }
    while (!received.EndOfMessage);
    return Encoding.UTF8.GetString(message.ToArray());
}

// Skips protocol messages (connected, ping) until the query result carrying the expected data arrives.
async Task<string> ReadUntilMessage(Func<Task<string>> next)
{
    while (true)
    {
        var message = JsonDocument.Parse(await next()).RootElement;
        if (message.TryGetProperty("type", out var type) && type.GetString() == "QueryResult")
        {
            var data = message.GetProperty("payload").GetProperty("data");
            var text = data.GetProperty("message").GetString();
            return text == ExpectedMessage
                ? $"received {text}"
                : throw new InvalidOperationException($"unexpected query data: {data}");
        }
    }
}
