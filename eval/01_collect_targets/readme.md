# Finding port information from packages/metadata

## Idea 1: Debian packages could have port information
* Download openvpn src package from debian, unpack -> no obvious port info (openvpn uses udp 1194)

## Idea 2: SElinux policies
* clone reference policies from https://github.com/SELinuxProject/refpolicy.git
* `policy/modules/kernel/corenetwork.te.in` contains lines of the form `network_port\(<name>(, <proto>,<port>,<s>)+\)`
* these define rules of the form `corenet_<proto>_<method>_<name>_port`, where `<method>` is `bind`, `send`, `sendrecv`, or `receive`
* grepping for these rules gives lines from `*.te` files of the form `corenet_<proto>_<method>_<name>_port(<type>_t)`
* grepping for `<type>_exec_t` gives matches in `*.fc` files, that list paths of executables with the specific rights

The mapping from `<type>_t` to `<type>_exec_t` appears to be by convention only, no guarantees.
