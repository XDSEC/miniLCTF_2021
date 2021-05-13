#!/bin/sh

echo $FLAG > /flag && \
export FLAG=not_flag && \
FLAG=not_flag

java -jar /java/minil_java.jar
