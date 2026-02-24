import os
import re
import sys

# since we need to figure out which binary a result file belongs to and
# we prefer an explicit "binary: foo.dll" line in the file itself, but older
# analysis results don't have that. in those cases the results are nested
# under a directory named after the binary, so we walk up the path looking
# for a component with a known binary extension. this assumes you are using the
# runner.ps1 script.
def find_binary_name(filepath, lines):
    for line in lines:
        match = re.match(r"^binary:\s*(.+)$", line.strip(), re.IGNORECASE)
        if match:
            return match.group(1).strip()

    binary_exts = {".dll", ".exe", ".sys", ".drv", ".cpl", ".ocx", ".ax", ".efi", ".scr", ".mun", ".winmd"}
    parts = os.path.normpath(filepath).replace("\\", "/").split("/")
    for part in reversed(parts[:-1]):
        _, ext = os.path.splitext(part)
        if ext.lower() in binary_exts:
            return part

    return os.path.basename(os.path.dirname(filepath))


def parse_feature_map(filepath):
    features = {}
    binary_name = None
    in_feature_map = False

    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()

    for line in lines:
        line = line.strip()

        if line == "[[FEATURE MAP]]":
            in_feature_map = True
            continue

        if not in_feature_map:
            continue

        # blank lines before any data are skipped, but once we've collected
        # features a blank line means the section ended. a new [[SECTION]]
        # header while we have nothing means we overshot somehow so reset and
        # retry.
        if line == "" or (line.startswith("[[") and line.endswith("]]")):
            if features:
                break
            if line.startswith("[["):
                in_feature_map = False
            continue

        binary_match = re.match(r"^binary:\s*(.+)$", line, re.IGNORECASE)
        if binary_match:
            binary_name = binary_match.group(1).strip()
            continue

        if line.lower().startswith("unique features:"):
            continue

        # the two formats are: aggregated output includes inline refs after a 
        # semicolon, fresh analysis output is just name=id. we handle both so 
        # this script can aggregate its own previous output without losing 
        # ref data.
        ref_match = re.match(r"^(.+?)=(\d+)\s*;\s*ref\(s\):\s*(.+)$", line)
        if ref_match:
            raw_name = ref_match.group(1).strip()
            value = ref_match.group(2).strip()
            refs = [entry.strip() for entry in ref_match.group(3).split(",") if entry.strip()]
            
            # strip the mangled trait prefix so both "Feature_whatever" and
            # "__WilFeatureTraits_Feature_whatever" normalize to the same key
            name = re.sub(r"^__WilFeatureTraits_", "", raw_name)
            features[name] = (value, refs)
            
            continue

        simple_match = re.match(r"^(.+?)=(\d+)\s*$", line)
        if simple_match:
            raw_name = simple_match.group(1).strip()
            value = simple_match.group(2).strip()
            name = re.sub(r"^__WilFeatureTraits_", "", raw_name)
            features[name] = (value, [])
            continue

    if not binary_name:
        binary_name = find_binary_name(filepath, lines)

    for name, (value, refs) in features.items():
        if not refs:
            features[name] = (value, [binary_name])

    return features


def main():
    root_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    output_file = sys.argv[2] if len(sys.argv) > 2 else "aggregated_feature_map.txt"

    aggregated = {}
    file_count = 0

    for dirpath, dirnames, filenames in os.walk(root_dir):
        for fname in filenames:
            if fname == "AnalysisResults.txt":
                fpath = os.path.join(dirpath, fname)
                features = parse_feature_map(fpath)
                if features:
                    file_count += 1
                    for name, (value, refs) in features.items():
                        if name in aggregated:
                            aggregated[name]["refs"].update(refs)
                        else:
                            aggregated[name] = {"value": value, "refs": set(refs)}

    sorted_feats = sorted(aggregated.items(), key=lambda entry: entry[0].lower())

    with open(output_file, "w", encoding="utf-8") as out:
        for name, data in sorted_feats:
            refs_sorted = ", ".join(sorted(data["refs"], key=str.lower))
            out.write(f"{name}={data['value']} ; ref(s): {refs_sorted}\n")

    print(f"processed {file_count} files with feature maps.") 
    print(f"aggregated {len(aggregated)} unique features => {output_file}")


if __name__ == "__main__":
    main()
