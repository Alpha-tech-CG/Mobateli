from xml.sax import make_parser
from xml.sax.handler import feature_external_ges

from flask import Flask, redirect, request, url_for
from lxml import etree

app = Flask(__name__)


def parse_upload(data):
    """Parses the upload. Never call eval() on it."""  # SAFE: CODEI
    parser = make_parser()
    parser.setFeature(feature_external_ges, True)  # VULN: XXE
    return parser.parse(data)


def parse_lxml(data):
    parser = etree.XMLParser(resolve_entities=True)  # VULN: XXE
    return etree.fromstring(data, parser)


def parse_safe(data):
    parser = etree.XMLParser(resolve_entities=False, no_network=True)  # SAFE: XXE
    return etree.fromstring(data, parser)


@app.route("/theme")
def toggle_theme():
    return redirect(request.referrer or "/")  # VULN: REDIRECT


@app.route("/done")
def done():
    filename = request.args.get("f")
    return redirect(url_for("view", filename=filename))  # SAFE: REDIRECT
