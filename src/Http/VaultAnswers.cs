using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace Snail.Toolkit.HashiCorp.Vault.Http;

/// <summary>The answers of the secret read and the login, refused as a configuration error when they are not objects.</summary>
/// <remarks>
/// The answers were once read as a <c>JsonNode</c> tree, where a member of the wrong JSON type failed
/// with <see cref="InvalidOperationException"/>, the exception the provider treats as a configuration
/// error that <see cref="VaultOptions.Optional"/> must not hide. A typed read fails with
/// <see cref="JsonException"/> instead, so the shape is checked where it is read: an answer, a section
/// or a field of the wrong JSON type still fails with <see cref="InvalidOperationException"/>, and only
/// a body that is not JSON at all fails with <see cref="JsonException"/>, as it always did. A field
/// is guarded by its converter; the answer itself, having no field to carry one, by these options.
/// </remarks>
internal static class VaultAnswers
{
    private static readonly JsonSerializerOptions Guarded = new(VaultJson.Default.Options)
    {
        Converters = { new ObjectOnlyConverter<SecretAnswer>(), new ObjectOnlyConverter<LoginAnswer>() },
    };

    /// <summary>The answer of a secret read.</summary>
    public static JsonTypeInfo<SecretAnswer> Secret { get; } = Of<SecretAnswer>();

    /// <summary>The answer of an AppRole login.</summary>
    public static JsonTypeInfo<LoginAnswer> Login { get; } = Of<LoginAnswer>();

    /// <summary>The failure of an answer that carries <paramref name="found"/> where <paramref name="expected"/> belongs.</summary>
    public static InvalidOperationException Malformed(JsonTokenType found, string expected) =>
        new($"Vault: the answer is malformed: {found} where {expected} belongs.");

    private static JsonTypeInfo<T> Of<T>() => (JsonTypeInfo<T>)Guarded.GetTypeInfo(typeof(T));
}

/// <summary>Reads an object with its source-generated metadata, and anything but an object as a malformed answer.</summary>
/// <typeparam name="T">The object's type, generated in <see cref="VaultJson"/>.</typeparam>
/// <remarks>Null never reaches it: the serializer reads it as no object.</remarks>
internal sealed class ObjectOnlyConverter<T> : JsonConverter<T>
{
    private JsonTypeInfo<T>? _shape;

    /// <inheritdoc/>
    public override T? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType is not JsonTokenType.StartObject)
            throw VaultAnswers.Malformed(reader.TokenType, "an object");

        _shape ??= (JsonTypeInfo<T>)VaultJson.Default.GetTypeInfo(typeof(T))!;

        return JsonSerializer.Deserialize(ref reader, _shape);
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options) =>
        throw new NotSupportedException("Vault answers are only read.");
}

/// <summary>Reads a 32-bit integer, and any other JSON value but null as a malformed answer.</summary>
internal sealed class IntegerOnlyConverter : JsonConverter<int?>
{
    /// <inheritdoc/>
    public override int? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType is JsonTokenType.Null)
            return null;

        if (reader.TokenType is JsonTokenType.Number && reader.TryGetInt32(out var number))
            return number;

        throw VaultAnswers.Malformed(reader.TokenType, "a 32-bit integer");
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, int? value, JsonSerializerOptions options) =>
        throw new NotSupportedException("Vault answers are only read.");
}

/// <summary>Reads a string, and any other JSON value but null as a malformed answer.</summary>
internal sealed class StringOnlyConverter : JsonConverter<string?>
{
    /// <inheritdoc/>
    public override string? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType is JsonTokenType.String)
            return reader.GetString();

        throw VaultAnswers.Malformed(reader.TokenType, "a string");
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, string? value, JsonSerializerOptions options) =>
        throw new NotSupportedException("Vault answers are only read.");
}
