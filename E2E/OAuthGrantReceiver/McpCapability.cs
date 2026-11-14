// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;

namespace E2E.OAuthGrantReceiver;

static class McpCapability
{
    public static object Evidence() => new
    {
        admitted = true,
        kind = "oauth-grant",
        credentialId = "00000000-0000-4000-8000-000000000348",
        issuer = "https://issuer:8443",
        subject = "00000000-0000-4000-8000-000000000347",
        hashMatch = true
    };

    public static async Task<IResult> Respond(HttpRequest request)
    {
        using var document = await JsonDocument.ParseAsync(request.Body);
        var message = document.RootElement;
        if (message.GetProperty("jsonrpc").GetString() != "2.0") throw new Rejected("jsonrpc");
        var id = message.GetProperty("id").Clone();
        var method = message.GetProperty("method").GetString();
        object result;
        if (method == "tools/list")
        {
            result = new { tools = new[] { new { name = "read_grant", description = "Read verified test grant evidence", inputSchema = new { type = "object", properties = new { } } } } };
        }
        else if (method == "tools/call" && message.GetProperty("params").GetProperty("name").GetString() == "read_grant")
        {
            result = new { content = new[] { new { type = "text", text = JsonSerializer.Serialize(Evidence()) } }, isError = false };
        }
        else throw new Rejected("mcp-method");
        return Results.Json(new { jsonrpc = "2.0", id, result });
    }
}
