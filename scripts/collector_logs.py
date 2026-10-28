"""Check collector-preserved JSON records, not just a matching substring."""
import json
import time
from collector_stack import LIMIT, poll
from collector_files import open_runtime_file

CANARY = "collector-proof-secret-canary"


def read_private(path):
    with open_runtime_file(path) as stream:
        data = stream.read(LIMIT + 1)
    assert len(data) <= LIMIT, "telemetry fixture exceeded evidence bound"
    text = data.decode()
    assert CANARY not in text, "secret canary leaked to telemetry"
    return text


def records(path):
    try:
        text = read_private(path)
    except FileNotFoundError:
        return []
    # The exporter appends complete JSON lines. Ignore only the final partial line.
    lines = text.splitlines()
    if text and not text.endswith("\n"):
        lines.pop()
    return [record for line in lines for resource in json.loads(line)["resourceLogs"]
            for scope in resource["scopeLogs"] for record in scope["logRecords"]]


def verify(stack, observations):
    path = stack.data / "collected/collected.json"
    source = [json.loads(line) for line in read_private(stack.data / "logs/events.log").splitlines()]
    for trace, request_id in observations:
        event = next(e for e in source if e.get("correlation", {}).get("request_id") == request_id
                     and e.get("data", {}).get("kind") == "access")
        record = poll(lambda: next((r for r in records(path) if r.get("traceId") == trace
                      and json.loads(r["body"]["stringValue"]).get("data", {}).get("kind") == "access"), None),
                      "collected structured access event")
        assert record["spanId"] == event["correlation"]["span_id"]
        assert int(record["timeUnixNano"]) == event["timestamp_unix_nanos"]
        assert record["severityNumber"] == 9 and record["severityText"].lower() == "info"

    # Separate parser fixture: proves embedded newlines stay inside one record.
    # This is not a claim that Fluxheim emits arbitrary multiline messages.
    fixture = {"timestamp_unix_nanos": time.time_ns(), "level": "warn", "message": "collector fixture\nsecond line"}
    with open_runtime_file(stack.data / "logs/events.log", "a") as stream:
        stream.write(json.dumps(fixture) + "\n")
    record = poll(lambda: next((r for r in records(path) if
                  json.loads(r["body"]["stringValue"]).get("message") == fixture["message"]), None),
                  "multiline parser fixture")
    assert int(record["timeUnixNano"]) == fixture["timestamp_unix_nanos"]
    assert record["severityNumber"] == 13
