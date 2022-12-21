#!/bin/sh
APP=hq
TESTCASE=/tmp/test.$APP.$(date +%s)
if [ $BSD_DEV ]; then . /etc/.bsdconf; fi
if [ ! -x /usr/local/go/bin/go ]; then BSDlive go; fi
if [ -e "$TESTCASE" ]; then rm -rf $TESTCASE; fi
mkdir -p $TESTCASE && cd $TESTCASE && (
	cd $BSD_DEV/$APP/APP/$APP
	/usr/local/go/bin/go run main.go c
)
if [ -e "$TESTCASE" ]; then rm -rf $TESTCASE; fi
