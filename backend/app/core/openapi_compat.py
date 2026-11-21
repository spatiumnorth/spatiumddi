"""Make the published OpenAPI document consumable by code generators (#907).

FastAPI is a faithful OpenAPI 3.1 emitter, and 3.1 spells "nullable" as a
union with the JSON Schema ``null`` type::

    "feed_url": {"anyOf": [{"type": "string"}, {"type": "null"}], "title": "Feed Url"}

Strict generators do not all implement that arm. ``swift-openapi-generator``
skips the member it cannot model — and skipping a member drops **the whole
property** from the generated type, with a warning rather than an error. On
this document that silently removed 3,291 schema properties and 297 query
parameters from a client generated against a running control plane: models
missing a third of their fields, and ``limit`` gone from list endpoints, so the
client could not paginate at all. A client that compiles, passes review, and is
quietly incomplete is precisely the drift a generated client exists to prevent.

So the document states nullability the other way round — the way every
generator already handles, and the way JSON Schema described optional fields
before 3.1: the plain schema, with the property absent from ``required``::

    "feed_url": {"type": "string", "title": "Feed Url"}

**What this trades away.** The server still *sends* ``"feed_url": null`` rather
than omitting the key, so a strict response validator (schemathesis, and our
own live conformance fuzz) now sees an explicit null against a schema that no
longer admits one. That is a real, deliberate cost, taken because the
alternative — dropping ``null`` from responses via ``exclude_none`` — changes
the wire for every existing client of this API, and because the generated-code
failure is silent while the validator complaint is not. On the decode side
nothing is lost: an absent key and an explicit null both land as ``nil`` /
``undefined`` in every generator's optional-property handling.

**Request bodies keep their ``required``.** Moving nullability onto ``required``
is right for a response — an absent key and a null both decode to nil — and
wrong for a request, where ``required`` is not a hint but what the server
enforces: a field annotated ``X | None`` with no default is a key pydantic
demands, and a generated client that believed the document and omitted it
would get a 422 back. So the rewrite below collapses the union everywhere (a
dropped property is unusable in either direction) but leaves ``required``
alone on any schema reachable from a ``requestBody``. A schema used in both
directions keeps it too: telling a client it may omit a key the server rejects
is the worse of the two failures, and the real fix for one of those is to give
the field a default so it is honestly optional.

The union still collapses on the way in, so a generated client cannot send an
explicit ``null`` to clear a field — but it could not before either, because
the property it would have sent was dropped from the request model entirely.
Clearing through such a client goes through whatever the endpoint's own
convention is (the ``clear`` list on the address, subnet and DNS record
updates, #1211); being able to set the field at all is the step forward.

Applied to the served document (``app.openapi()``), so ``/api/openapi.json``,
``/api/docs`` and the release artifact ``scripts/export_openapi.py`` publishes
all say the same thing — a client generated against a running server and one
generated from the pinned release asset must not disagree.
"""

from __future__ import annotations

from typing import Any

#: Where a component reference points.
_SCHEMA_REF_PREFIX = "#/components/schemas/"

#: Keys whose values are *instance data*, not schemas — a ``default`` of
#: ``{"anyOf": [...]}`` is somebody's literal payload, not a union to rewrite.
#: ``default`` is context-sensitive: under ``responses`` it names the
#: default-response object, which very much does contain schemas, so the walk
#: below suppresses this set only where the parent is not a name-keyed map.
_VALUE_KEYS = frozenset({"example", "examples", "enum", "const", "default"})

#: Annotations worth carrying across a ``$ref`` collapse — prose a human
#: wrote, not machine-generated noise. See ``_strip_null_arms``.
_REF_SIBLINGS_WORTH_KEEPING = frozenset({"description", "deprecated"})

#: Objects whose *keys are arbitrary names* rather than OpenAPI keywords:
#: ``properties`` may legitimately hold a property called ``default``, and
#: ``responses`` a response called ``default``. Their children are always
#: recursed into.
_NAME_KEYED_MAPS = frozenset(
    {
        "properties",
        "patternProperties",
        "$defs",
        "definitions",
        "schemas",
        "responses",
        "content",
        "paths",
        "webhooks",
        "callbacks",
        "headers",
        # ``components.parameters`` / ``components.requestBodies`` are keyed by
        # arbitrary names too. FastAPI inlines both rather than emitting them,
        # so this is belt-and-braces — but the same key names appear on an
        # Operation Object holding a LIST, and the list branch below ignores
        # the flag, so listing them here cannot misread one.
        "parameters",
        "requestBodies",
    }
)


def collapse_nullable_unions(document: dict[str, Any]) -> dict[str, Any]:
    """Rewrite every ``X | null`` union in ``document`` as plain ``X``.

    Mutates in place (the caller owns FastAPI's cached document) and returns
    it for convenience. Idempotent: a second pass finds no ``null`` arms left.
    """
    _walk(document, name_keyed=False, request_schemas=_request_schemas(document))
    return document


def _request_schemas(document: dict[str, Any]) -> frozenset[str]:
    """Names under ``components/schemas`` reachable from any request body.

    Transitive: a request body's ``$ref`` pulls in everything that schema
    refers to, because a nested model is just as required as a top-level one.
    """
    reachable: set[str] = set()
    pending: list[str] = []

    def seed(node: Any) -> None:
        for name in _referenced_names(node):
            if name not in reachable:
                reachable.add(name)
                pending.append(name)

    for item in (document.get("paths") or {}).values():
        if not isinstance(item, dict):
            continue
        for operation in item.values():
            if isinstance(operation, dict) and operation.get("requestBody"):
                seed(operation["requestBody"])

    schemas = (document.get("components") or {}).get("schemas") or {}
    while pending:
        seed(schemas.get(pending.pop()))
    return frozenset(reachable)


def _referenced_names(node: Any) -> set[str]:
    """Every ``#/components/schemas/<name>`` reference under ``node``."""
    found: set[str] = set()
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith(_SCHEMA_REF_PREFIX):
            found.add(ref[len(_SCHEMA_REF_PREFIX) :])
        for value in node.values():
            found |= _referenced_names(value)
    elif isinstance(node, list):
        for value in node:
            found |= _referenced_names(value)
    return found


def _walk(
    node: Any,
    *,
    name_keyed: bool,
    request_schemas: frozenset[str],
    in_request: bool = False,
    map_key: str | None = None,
) -> None:
    """Depth-first rewrite.

    ``name_keyed`` says the node's own keys came from a user-chosen namespace
    (property names, status codes, media types, paths), so none of them may be
    read as an OpenAPI keyword. ``in_request`` says this subtree describes
    something a client SENDS, where ``required`` is the server's demand rather
    than a description of what it returns.
    """
    if isinstance(node, list):
        for item in node:
            _walk(item, name_keyed=False, request_schemas=request_schemas, in_request=in_request)
        return
    if not isinstance(node, dict):
        return

    if not name_keyed:
        if not in_request:
            _drop_nullable_from_required(node)
        _strip_null_arms(node)

    for key, value in node.items():
        if not name_keyed and key in _VALUE_KEYS:
            continue
        child_name_keyed = not name_keyed and key in _NAME_KEYED_MAPS
        if name_keyed and map_key == "schemas":
            # ``key`` is the component's own name, so this is where a named
            # schema learns whether anything sends it.
            child_in_request = key in request_schemas
        elif not name_keyed and key == "requestBody":
            # An INLINE request body — no ``$ref`` for the reachability scan
            # above to have found.
            child_in_request = True
        else:
            child_in_request = in_request
        _walk(
            value,
            name_keyed=child_name_keyed,
            request_schemas=request_schemas,
            in_request=child_in_request,
            map_key=key if child_name_keyed else None,
        )


def _drop_nullable_from_required(schema: dict[str, Any]) -> None:
    """Move nullability from the union onto the ``required`` list.

    This is the half that keeps the rewrite honest for the 971 properties that
    were nullable *and* required — ``str | None`` with no default is a required
    key that may carry null. Collapsing the union without this would tell a
    client the value is always a string, and the generated model would be
    non-optional and fail to decode the first null it meets.
    """
    properties = schema.get("properties")
    required = schema.get("required")
    if not isinstance(properties, dict) or not isinstance(required, list):
        return
    nullable = {
        name
        for name, subschema in properties.items()
        if isinstance(subschema, dict) and _is_nullable(subschema)
    }
    if not nullable:
        return
    remaining = [name for name in required if name not in nullable]
    if remaining:
        schema["required"] = remaining
    else:
        # An empty ``required`` is legal in 2020-12 but forbidden in OpenAPI
        # 3.0, and generators read it as an oddity worth warning about. FastAPI
        # omits the key when nothing is required; match that.
        del schema["required"]


def _is_nullable(schema: dict[str, Any]) -> bool:
    """True if ``schema`` admits ``null`` through a union or a type array."""
    for keyword in ("anyOf", "oneOf"):
        arms = schema.get(keyword)
        if isinstance(arms, list) and any(_is_null_arm(arm) for arm in arms):
            return True
    types = schema.get("type")
    return isinstance(types, list) and "null" in types


def _is_null_arm(arm: Any) -> bool:
    return isinstance(arm, dict) and arm.get("type") == "null"


def _strip_null_arms(schema: dict[str, Any]) -> None:
    """Remove the ``null`` arm and collapse what is left, in place."""
    types = schema.get("type")
    if isinstance(types, list) and "null" in types:
        # Not a shape FastAPI emits, handled because a hand-written
        # ``json_schema_extra`` can, and it breaks the same generators.
        remaining = [t for t in types if t != "null"]
        if remaining:
            schema["type"] = remaining[0] if len(remaining) == 1 else remaining

    for keyword in ("anyOf", "oneOf"):
        arms = schema.get(keyword)
        if not isinstance(arms, list) or not any(_is_null_arm(arm) for arm in arms):
            continue
        rest = [arm for arm in arms if not _is_null_arm(arm)]
        if not rest:
            # A union of nothing but ``null`` — a field annotated ``None``.
            # There is no plain schema to collapse to, so leave it alone; the
            # property is already out of ``required`` and a generator drops it
            # either way.
            continue
        if len(rest) > 1:
            # e.g. ``Decimal | None`` -> [number, string-pattern, null]. Still
            # a union, just no longer a nullable one.
            schema[keyword] = rest
            continue

        member = rest[0]
        del schema[keyword]
        if isinstance(member, dict) and "$ref" in member:
            # ``$ref`` beside sibling keywords is legal in 3.1 and read
            # inconsistently by generators, so the reference is emitted with as
            # little beside it as possible. What FastAPI leaves there is a
            # generated wrapper title ("Response Get Account Api V1 …") plus,
            # sometimes, an operator-written ``description`` — the title says
            # nothing a client needs and goes; the description is somebody's
            # documentation and stays, since losing it to a mechanical rewrite
            # is a worse trade than a generator ignoring a keyword.
            kept = {k: v for k, v in schema.items() if k in _REF_SIBLINGS_WORTH_KEEPING}
            schema.clear()
            schema.update(member)
            for key, value in kept.items():
                schema.setdefault(key, value)
        elif isinstance(member, dict):
            # The member's own keywords win over the parent's: the parent
            # contributes annotations (``title``, ``description``, ``default``,
            # ``readOnly``), the member the actual type and constraints.
            schema.update(member)
