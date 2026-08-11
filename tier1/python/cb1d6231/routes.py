from flask import Flask

from auth import login_required

app = Flask(__name__)


@app.route("/reports")
@login_required
def reports():
    return "reports"


@app.route("/config/rotate-keys", methods=["POST"])
@login_required
def rotate_keys():
    return "rotated"
