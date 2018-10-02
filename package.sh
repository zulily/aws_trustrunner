#!/usr/bin/env bash
mkdir -p dist
rm -rf dist/*
rm aws_trustrunner.zip

cp *.py dist
cp -R trustdefs dist
pip install -r requirements.txt -t dist

(cd dist && zip -r ../aws_trustrunner *)
