"""A port / Object Lock period that is not a whole, finite number is a 422 (#3946)."""

from __future__ import annotations

import json

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_backup_target_update_bounds import _headers

_URL = "/api/v1/backup/targets"
_FTP = {"host": "h", "username": "u", "password": "p", "remote_path": "/b"}
_S3 = {
    "bucket": "b",
    "access_key_id": "a",
    "secret_access_key": "s",
    "region": "us-east-1",
    "endpoint_url": "https://192.0.2.10",
    "object_lock_mode": "governance",
}


def _raw(kind: str, config: dict, extra: str) -> str:
    body = {"name": "d", "passphrase": "a-passphrase-long-enough", "enabled": False}
    body.update(kind=kind, config=config)
    # ``extra`` is a raw JSON member spliced in, so 1e999 reaches the server
    # as the literal a generated client would send.
    return json.dumps(body)[:-2] + ", " + extra + "}}"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind,base,member,field",
    [
        ("ftp", _FTP, '"port": 1e999', "port"),
        ("ftp", _FTP, '"port": 21.5', "port"),
        ("ftp", _FTP, '"port": "abc"', "port"),
        ("s3", _S3, '"object_lock_days": 1e999', "object_lock_days"),
        ("s3", _S3, '"object_lock_days": 1.5', "object_lock_days"),
    ],
)
async def test_add_bad_number_is_422(
    kind: str, base: dict, member: str, field: str, client: AsyncClient, db_session: AsyncSession
):
    headers = {**await _headers(db_session), "Content-Type": "application/json"}
    r = await client.post(_URL, content=_raw(kind, base, member), headers=headers)
    assert r.status_code == 422, r.text
    assert repr(field) in r.json()["detail"]


@pytest.mark.asyncio
async def test_edit_infinite_port_is_422(client: AsyncClient, db_session: AsyncSession):
    headers = await _headers(db_session)
    r = await client.post(
        _URL,
        json={
            "name": "d",
            "passphrase": "a-passphrase-long-enough",
            "enabled": False,
            "kind": "ftp",
            "config": {**_FTP, "port": 21},
        },
        headers=headers,
    )
    assert r.status_code == 201, r.text
    raw = '{"config": {"port": 1e999}}'
    r = await client.patch(
        f"{_URL}/{r.json()['id']}",
        content=raw,
        headers={**headers, "Content-Type": "application/json"},
    )
    assert r.status_code == 422, r.text
    assert "'port'" in r.json()["detail"]


_NFS = {"server": "h", "export": "/e"}


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["version", "uid", "gid", "timeout_s", "port"])
@pytest.mark.parametrize("member", ["1e999", "4.5", '"abc"'])
async def test_nfs_numeric_fields_bad_value_is_422(
    field: str, member: str, client: AsyncClient, db_session: AsyncSession
):
    headers = {**await _headers(db_session), "Content-Type": "application/json"}
    r = await client.post(_URL, content=_raw("nfs", _NFS, f'"{field}": {member}'), headers=headers)
    assert r.status_code == 422, r.text
    assert repr(field) in r.json()["detail"]


@pytest.mark.asyncio
@pytest.mark.parametrize("member", ['"version": 4', '"version": "4"', '"version": 3'])
async def test_nfs_numbers_and_numeric_text_are_taken(
    member: str, client: AsyncClient, db_session: AsyncSession
):
    headers = {**await _headers(db_session), "Content-Type": "application/json"}
    config = {**_NFS, "uid": 1000, "gid": 1000, "timeout_s": 30}
    r = await client.post(_URL, content=_raw("nfs", config, member), headers=headers)
    assert r.status_code == 201, r.text
