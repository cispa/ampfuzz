#!/usr/bin/env python3

import json


def merge_targets(files):
    merged = {"targets": set(), "edges": set(), "callsite_dominators": dict()}

    for fname in files:
        with open(fname) as f:
            c = json.load(f)
        merged["targets"].update(c["targets"])
        merged["edges"].update(tuple(v) for v in c["edges"])
        merged["callsite_dominators"].update(c["callsite_dominators"])

    merged["targets"] = sorted(merged["targets"])
    merged["edges"] = sorted(merged["edges"])

    return merged


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('basefile', help="base targets.json file")
    parser.add_argument('extra_files', metavar="extra_target", nargs='*',
                        help="extra targets.json files to merge")

    args = parser.parse_args()

    merged = merge_targets([args.basefile] + args.extra_files)

    with open(args.basefile, 'w') as f:
        json.dump(merged, f)


if __name__ == '__main__':
    main()
