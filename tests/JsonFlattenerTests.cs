using System.Text.Json.Nodes;

namespace Snail.Toolkit.HashiCorp.Vault.Tests;

public class JsonFlattenerTests
{
    [Fact]
    public void Flatten_ScalarLandsUnderThePrefix()
    {
        var result = JsonFlattener.Flatten("a:b", JsonNode.Parse("\"value\""));

        var pair = Assert.Single(result);
        Assert.Equal("a:b", pair.Key);
        Assert.Equal("value", pair.Value);
    }

    [Fact]
    public void Flatten_ObjectMembersBecomeSegments()
    {
        var result = JsonFlattener.Flatten("root", JsonNode.Parse("""{"x": 1, "y": {"z": true}}"""));

        Assert.Equal("1", result["root:x"]);
        Assert.Equal("true", result["root:y:z"]);
    }

    [Fact]
    public void Flatten_ArrayElementsBecomeIndexes()
    {
        var result = JsonFlattener.Flatten("root", JsonNode.Parse("""["a", {"b": "c"}]"""));

        Assert.Equal("a", result["root:0"]);
        Assert.Equal("c", result["root:1:b"]);
    }

    [Fact]
    public void Flatten_NullBecomesANullValue()
    {
        var result = JsonFlattener.Flatten("root", JsonNode.Parse("""{"x": null}"""));

        Assert.True(result.ContainsKey("root:x"));
        Assert.Null(result["root:x"]);
    }

    [Fact]
    public void Expand_UnwrapsAJsonStringButKeepsOrdinaryText()
    {
        Assert.IsType<JsonObject>(JsonFlattener.Expand(JsonValue.Create("""{"a": 1}""")));
        Assert.IsType<JsonValue>(JsonFlattener.Expand(JsonValue.Create("just text")), exactMatch: false);
        Assert.IsType<JsonValue>(JsonFlattener.Expand(JsonValue.Create("{not json")), exactMatch: false);
        Assert.IsType<JsonValue>(JsonFlattener.Expand(JsonValue.Create(42)), exactMatch: false);
    }
}
