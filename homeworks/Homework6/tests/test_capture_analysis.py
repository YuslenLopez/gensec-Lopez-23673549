import io
import re
import time

import dpkt
import pytest

from app import RETENTION_SECONDS, analyses, app, expire_analyses, summarize
from capture_analysis import CaptureError, filter_packets, parse_capture


def capture_bytes():
    output = io.BytesIO()
    writer = dpkt.pcap.Writer(output)
    udp = dpkt.udp.UDP(sport=1234, dport=53, data=b'private')
    udp.ulen = len(udp)
    ip = dpkt.ip.IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02', p=17, data=udp)
    ip.len = len(ip)
    frame = dpkt.ethernet.Ethernet(src=b'\x00' * 6, dst=b'\x01' * 6, type=0x0800, data=ip)
    writer.writepkt(bytes(frame), ts=1700000000)
    return output.getvalue()


def test_parse_capture_metadata_only():
    packets = parse_capture('sample.pcap', capture_bytes())
    assert len(packets) == 1
    assert packets[0]['source'] == '10.0.0.1'
    assert packets[0]['destination_port'] == 53
    assert packets[0]['protocol'] == 'UDP'
    assert b'private' not in repr(packets).encode()


def test_validation_rejects_bad_extension_and_truncation():
    with pytest.raises(CaptureError):
        parse_capture('sample.txt', capture_bytes())
    with pytest.raises(CaptureError):
        parse_capture('sample.pcap', capture_bytes()[:-1])
    with pytest.raises(CaptureError):
        parse_capture('sample.pcapng', capture_bytes())


def test_filtering():
    packets = parse_capture('sample.pcap', capture_bytes())
    assert filter_packets(packets, {'ip': '10.0.0.2', 'protocol': 'UDP', 'destination_port': '53'}) == packets
    assert filter_packets(packets, {'source': '10.0.0.2'}) == []


def test_summary_and_time_filter():
    packets = parse_capture('sample.pcap', capture_bytes())
    summary = summarize(packets)
    assert (summary['count'], summary['bytes'], summary['sources'], summary['destinations']) == (1, packets[0]['length'], 1, 1)
    assert summary['protocols']['UDP'] == 1
    assert summary['bins'][0]['bytes'] == packets[0]['length']
    assert filter_packets(packets, {'end': 0}) == []


def test_pcapng_and_empty_capture():
    output = io.BytesIO()
    writer = dpkt.pcapng.Writer(output)
    frame = next(iter(dpkt.pcap.Reader(io.BytesIO(capture_bytes()))))[1]
    writer.writepkt(frame, ts=1700000000)
    assert parse_capture('sample.pcapng', output.getvalue())[0]['protocol'] == 'UDP'
    with pytest.raises(CaptureError):
        parse_capture('sample.pcapng', output.getvalue()[:-1])
    empty = io.BytesIO()
    dpkt.pcap.Writer(empty)
    assert parse_capture('empty.pcap', empty.getvalue()) == []


@pytest.fixture
def client():
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=True)
    analyses.clear()
    with app.test_client() as test_client:
        yield test_client
    analyses.clear()


def csrf(client):
    page = client.get('/').get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)


def upload_capture(client, data, filename='sample.pcap'):
    return client.post('/upload', data={'csrf_token': csrf(client), 'capture': (io.BytesIO(data), filename)},
                       content_type='multipart/form-data', follow_redirects=True)


def test_upload_filter_and_clear(client):
    page = upload_capture(client, capture_bytes()).get_data(as_text=True)
    assert 'Capture analyzed: 1 packets.' in page
    assert '10.0.0.1' in page
    assert 'data:image/svg+xml' in page
    assert 'private' not in page
    no_results = client.get('/?destination_port=80').get_data(as_text=True)
    assert 'No packets match these filters.' in no_results
    assert '1 active' in no_results
    response = client.post('/clear', data={'csrf_token': csrf(client)}, follow_redirects=True)
    assert b'Analysis cleared.' in response.data
    assert not analyses


def test_bad_files_empty_and_csrf(client):
    assert b'could not be verified' in client.post('/clear', follow_redirects=True).data
    assert b'Choose a .pcap or .pcapng' in upload_capture(client, b'not a capture', 'bad.txt').data
    assert b'Invalid or truncated PCAP header' in upload_capture(client, b'bad', 'bad.pcap').data
    empty = io.BytesIO()
    dpkt.pcap.Writer(empty)
    assert b'This capture contains no packets.' in upload_capture(client, empty.getvalue()).data


def test_oversized_upload_and_expiration(client):
    response = upload_capture(client, b'x' * (16 * 1024 * 1024 + 1))
    assert b'exceeds the 16 MB limit' in response.data
    upload_capture(client, capture_bytes())
    assert len(analyses) == 1
    next(iter(analyses.values()))['updated'] = time.monotonic() - RETENTION_SECONDS - 1
    expire_analyses()
    assert not analyses


def test_pagination_and_invalid_filters(client):
    output = io.BytesIO()
    writer = dpkt.pcap.Writer(output)
    frame = next(iter(dpkt.pcap.Reader(io.BytesIO(capture_bytes()))))[1]
    for index in range(51):
        writer.writepkt(frame, ts=1700000000 + index)
    assert b'PAGE 1 OF 2' in upload_capture(client, output.getvalue()).data
    assert b'PAGE 2 OF 2' in client.get('/?page=2').data
    assert b'Ports must be numbers' in client.get('/?source_port=99999', follow_redirects=True).data