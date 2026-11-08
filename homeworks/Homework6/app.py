import math
import os
import secrets
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlencode

import pygal
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_wtf.csrf import CSRFError, CSRFProtect
from pygal.style import Style
from werkzeug.utils import secure_filename

from capture_analysis import CaptureError, filter_packets, ip_sort_key, parse_capture


app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY') or secrets.token_hex(32),
    MAX_CONTENT_LENGTH=64 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
)
CSRFProtect(app)

RETENTION_SECONDS = 30 * 60
MAX_ANALYSES = 10
PAGE_SIZE = 50
analyses = {}
analyses_lock = threading.Lock()


def expire_analyses():
    now = time.monotonic()
    with analyses_lock:
        for key in [key for key, value in analyses.items() if now - value['updated'] >= RETENTION_SECONDS]:
            del analyses[key]


def cleanup_loop():
    while True:
        time.sleep(60)
        expire_analyses()


threading.Thread(target=cleanup_loop, daemon=True).start()


def current_analysis():
    expire_analyses()
    with analyses_lock:
        analysis = analyses.get(session.get('analysis_id'))
        if analysis is not None:
            analysis['updated'] = time.monotonic()
        return analysis


def summarize(packets):
    protocols = Counter(packet['protocol'] for packet in packets)
    earliest = min((packet['epoch'] for packet in packets), default=None)
    latest = max((packet['epoch'] for packet in packets), default=None)
    bins = []
    if packets:
        width = max(1, math.ceil((latest - earliest + 1) / 24))
        totals = Counter()
        for packet in packets:
            totals[int((packet['epoch'] - earliest) // width)] += packet['length']
        bins = [{'time': datetime.fromtimestamp(earliest + index * width, timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
                 'bytes': totals[index]} for index in range(int((latest - earliest) // width) + 1)]
    return {
        'count': len(packets), 'bytes': sum(packet['length'] for packet in packets),
        'sources': len({packet['source'] for packet in packets if packet['source']}),
        'destinations': len({packet['destination'] for packet in packets if packet['destination']}),
        'start': datetime.fromtimestamp(earliest, timezone.utc).strftime('%Y-%m-%d %H:%M:%S') if earliest is not None else None,
        'end': datetime.fromtimestamp(latest, timezone.utc).strftime('%Y-%m-%d %H:%M:%S') if latest is not None else None,
        'protocols': protocols, 'bins': bins,
    }


def make_charts(summary):
    if not summary['count']:
        return None, None
    style = Style(background='transparent', plot_background='transparent', foreground='#75817e',
                  foreground_strong='#172a2a', foreground_subtle='#dfe6e2',
                  colors=('#18735c', '#a7cd72', '#e2a76e', '#6e98aa', '#bd8d9d', '#87948b'),
                  font_family='Trebuchet MS, sans-serif', label_font_size=10, value_font_size=10)
    volume = pygal.Bar(style=style, height=220, width=700, show_legend=False, show_y_guides=True,
                       show_x_guides=False, show_border=False, margin=0, js=[])
    volume.x_labels = [item['time'][11:] if index % max(1, len(summary['bins']) // 5) == 0 else ''
                       for index, item in enumerate(summary['bins'])]
    volume.add('Captured bytes', [item['bytes'] for item in summary['bins']])
    protocols = pygal.Pie(style=style, height=180, width=180, inner_radius=0.75, show_legend=False,
                          show_labels=False, show_border=False, margin=0, js=[])
    for name, count in summary['protocols'].most_common():
        protocols.add(name, count)
    return volume.render_data_uri(), protocols.render_data_uri()


def read_filters():
    fields = ('source', 'destination', 'ip', 'protocol', 'source_port', 'destination_port', 'start', 'end', 'search')
    values = {field: request.args.get(field, '').strip()[:100] for field in fields}
    parsed = values.copy()
    for field in ('source_port', 'destination_port'):
        if values[field] and (not values[field].isascii() or not values[field].isdigit() or int(values[field]) > 65535):
            raise ValueError('Ports must be numbers between 0 and 65535.')
    for field in ('start', 'end'):
        if values[field]:
            try:
                value = datetime.fromisoformat(values[field])
                if value.tzinfo is not None:
                    raise ValueError
                parsed[field] = value.replace(tzinfo=timezone.utc).timestamp()
            except (ValueError, OverflowError, OSError):
                raise ValueError('Enter valid UTC start and end times.') from None
    if parsed['start'] != '' and parsed['end'] != '' and parsed['start'] > parsed['end']:
        raise ValueError('Start time must be before end time.')
    return values, parsed


@app.get('/')
def dashboard():
    analysis = current_analysis()
    if analysis is None:
        return render_template('dashboard.html', analysis=None)
    try:
        values, parsed = read_filters()
        packets = filter_packets(analysis['packets'], parsed)
    except ValueError as error:
        flash(str(error), 'error')
        return redirect(url_for('dashboard'))
    sort = request.args.get('sort', 'timestamp')
    if sort not in ('timestamp', 'source', 'destination', 'protocol', 'length'):
        sort = 'timestamp'
    direction = request.args.get('direction', 'asc')
    if direction not in ('asc', 'desc'):
        direction = 'asc'
    key = {'timestamp': lambda packet: packet['epoch'], 'source': lambda packet: ip_sort_key(packet['source']),
           'destination': lambda packet: ip_sort_key(packet['destination']), 'protocol': lambda packet: packet['protocol'],
           'length': lambda packet: packet['length']}[sort]
    packets.sort(key=key, reverse=direction == 'desc')
    pages = max(1, math.ceil(len(packets) / PAGE_SIZE))
    page = min(max(request.args.get('page', 1, type=int) or 1, 1), pages)

    def query_url(**changes):
        params = {key: value for key, value in request.args.items() if value}
        params.update({key: str(value) for key, value in changes.items()})
        return url_for('dashboard') + '?' + urlencode(params)

    summary = summarize(packets)
    volume_chart, protocol_chart = make_charts(summary)
    return render_template('dashboard.html', analysis=analysis, summary=summary, values=values,
                           active_count=sum(bool(value) for value in values.values()), sort=sort, direction=direction,
                           packets=packets[(page - 1) * PAGE_SIZE:page * PAGE_SIZE], page=page, pages=pages,
                           query_url=query_url, volume_chart=volume_chart, protocol_chart=protocol_chart)


@app.post('/upload')
def upload():
    uploaded = request.files.get('capture')
    if not uploaded or not uploaded.filename:
        flash('Choose a capture file to analyze.', 'error')
        return redirect(url_for('dashboard'))
    filename = secure_filename(uploaded.filename)
    try:
        packets = parse_capture(filename, uploaded.read())
    except CaptureError as error:
        flash(str(error), 'error')
        return redirect(url_for('dashboard'))
    expire_analyses()
    with analyses_lock:
        old_id = session.get('analysis_id')
        if old_id not in analyses and len(analyses) >= MAX_ANALYSES:
            flash('Analysis capacity is full. Try again after an existing session expires.', 'error')
            return redirect(url_for('dashboard'))
        analyses.pop(old_id, None)
        identifier = secrets.token_urlsafe(32)
        analyses[identifier] = {'filename': filename, 'packets': packets, 'updated': time.monotonic()}
        session['analysis_id'] = identifier
    flash(f'Capture analyzed: {len(packets):,} packets.', 'success')
    return redirect(url_for('dashboard'))


@app.post('/clear')
def clear():
    with analyses_lock:
        analyses.pop(session.pop('analysis_id', None), None)
    flash('Analysis cleared.', 'success')
    return redirect(url_for('dashboard'))


@app.errorhandler(413)
def too_large(error):
    flash('The upload exceeds the 64 MiB request limit.', 'error')
    return redirect(url_for('dashboard'))


@app.errorhandler(CSRFError)
def csrf_error(error):
    flash('The form expired or could not be verified. Please try again.', 'error')
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)