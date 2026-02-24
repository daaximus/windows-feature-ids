# Shorthand README

You will need to have the WDK installed and have IDA + symchk available through your PATH.

## Running

Place all the scripts in a directory together and execute it via Powershell:

`.\runner.ps1` -- this will spin up multiple jobs to process all the binaries in System32. 

You can change the directory in the Powershell script if you have other binaries you want to parse. The runner may also be used for other scripts.

`python process_features.py` this will parse all the analysis results in each binary folder and aggregate the results into a single file called `aggregate_feature_map.txt`. You can
run this periodically while the runner continues to see progress being made.

## VSCODE Highlight

Install the VSIX in the `\extensions` directory and then open the aggregate_feature_map.txt (change extension to .features) or open any of the .features in this repo to see them
nicely highlighted and readable.

<img width="1139" height="328" alt="Code_y82NwZucUS" src="https://github.com/user-attachments/assets/e3105be7-6b06-46b8-8638-ae467e22b966" />

That's all. Enjoy.

-----

# LICENSE

MIT License
Copyright (c) 2026 Daax

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
