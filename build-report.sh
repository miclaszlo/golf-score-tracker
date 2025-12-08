#!/bin/bash

# Build PDF from Assignment-4-Report.md using pandoc

INPUT="Assignment-4-Report.md"
OUTPUT="Assignment-4-Report.pdf"

pandoc "$INPUT" -o "$OUTPUT" \
  --pdf-engine=xelatex \
  -V geometry:margin=1in \
  -V geometry:includeheadfoot \
  -V colorlinks=true \
  -V linkcolor=blue \
  -V urlcolor=blue \
  -V fontsize=11pt \
  -V mainfont="Arial" \
  -V sansfont="Arial" \
  -V monofont="Courier New" \
  -V linestretch=1.15 \
  -V parskip=0.5em \
  -V documentclass=report \
  -V classoption=titlepage \
  --toc \
  --toc-depth=3 \
  -H header.tex

echo "Generated: $OUTPUT"
