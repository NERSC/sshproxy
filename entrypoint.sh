#!/bin/sh

nslcd &

/usr/local/bin/gunicorn -b 0.0.0.0:5000 api:app

