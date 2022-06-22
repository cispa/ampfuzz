#!/bin/sh

if [ ! "$#" = "2" ]; then

    cat 1>&2 <<_EOF_
Usage
- Discard taints
$ ./gen_library_abilist.sh path-to-library.so > xxlib_abilist.txt discard
- Return value is the union of the label of its arguments.
$ ./gen_library_abilist.sh path-to-library.so > xxlib_abilist.txt functional
- Define a custom wrapper by yourself
$ ./gen_library_abilist.sh path-to-library.so > xxlib_abilist.txt custom
visit https://clang.llvm.org/docs/DataFlowSanitizer.html to see more.
_EOF_

    exit 1

fi

NM=`which nm 2>/dev/null`

if [ "$NM" = "" ]; then
    echo "[-] Error: can't find 'nm' in your \$PATH. please install binutils" 1>&2
    exit 1
fi


(nm --defined-only $1; nm -D --defined-only $1) 2> /dev/null|sed -n 's/[0-9a-f]\+ [TtWw] \(.*\)$/\1/g;T;p'|sed -n 'p;s/@.*//g;T;p'|sort -u|sed -n 's/^/fun:/;h;s/$/=uninstrumented/;p;x;s/$/='"$2"'/;p'