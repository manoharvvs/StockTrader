from flask import Flask, render_template, request, redirect, url_for, flash, session
import boto3
import os
import uuid
from datetime import datetime
from boto3.dynamodb.conditions import Key, Attr
from decimal import Decimal
import json
import hashlib
import re
from functools import wraps

app = Flask(__name__)


@app.route('/')
def index():
    return render_template("index.html")







if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

