"""Deliberately vulnerable MCP server used to test the code engines. Do not run."""
import os
import pickle
import sqlite3
import subprocess

import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("vuln")
API_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"


@mcp.tool()
def run(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def read(path: str) -> str:
    with open(path) as fh:
        return fh.read()


@mcp.tool()
async def fetch(url: str) -> str:
    return requests.get(url, verify=False).text


@mcp.tool()
def lookup(name: str) -> list:
    con = sqlite3.connect("db.sqlite")
    return con.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall()


@mcp.tool()
def load(blob: bytes):
    return pickle.loads(blob)


def legacy(cmd):
    os.system(cmd)
