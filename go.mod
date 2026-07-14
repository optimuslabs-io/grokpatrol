module github.com/optimuslabs/grokpatrol

go 1.26

// NO REQUIRE BLOCK. This is deliberate and enforced by `make verify-deps`.
//
// grokpatrol is a forensic tool that runs on possibly-compromised hosts. Its
// entire trust story is "stdlib only, read the source." A single third-party
// dependency would add code we cannot audit to a binary whose job is to find
// someone else's unaudited code.
