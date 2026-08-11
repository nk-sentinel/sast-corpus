"""Memory-safety templates for C and C++.

Seven of the 2025 CWE Top 25 are memory-safety weaknesses — out-of-bounds write
and read, use-after-free, the three buffer-overflow classes and null-pointer
dereference — and the corpus had none of them. That is the single largest gap
against the published list, and it sits exactly where C and C++ analysis either
works or does not.

These are not taint problems. The bug is in the arithmetic and the lifetime, so
a tool needs bounds reasoning and pointer liveness rather than source-to-sink
tracing, and the safe siblings differ from their positives by one check rather
than by a sanitiser call. That makes the pairs unusually tight: often a single
comparison or a single `sizeof` separates them.

Everything here compiles, because build/syntax/check.sh runs gcc and g++ over it
and a fixture that does not parse scores as a miss for every tool.
"""

from gen.templates import template

OOB_WRITE = ("CWE-787", ["CWE-787", "CWE-120", "CWE-121", "CWE-122", "CWE-788"], "A03")
OOB_READ = ("CWE-125", ["CWE-125", "CWE-126", "CWE-127"], "A03")
CLASSIC_OVERFLOW = ("CWE-120", ["CWE-120", "CWE-787", "CWE-121", "CWE-676"], "A03")
STACK_OVERFLOW = ("CWE-121", ["CWE-121", "CWE-120", "CWE-787"], "A03")
HEAP_OVERFLOW = ("CWE-122", ["CWE-122", "CWE-120", "CWE-787"], "A03")
USE_AFTER_FREE = ("CWE-416", ["CWE-416", "CWE-825", "CWE-672"], "A03")
NULL_DEREF = ("CWE-476", ["CWE-476", "CWE-690"], "A03")
INT_OVERFLOW = ("CWE-190", ["CWE-190", "CWE-680", "CWE-131"], "A03")
FORMAT_STRING = ("CWE-134", ["CWE-134", "CWE-20"], "A03")

MAIN_C = ("#include <stdio.h>\n"
          "#include \"work.h\"\n\n"
          "int main(int argc, char **argv) {\n"
          "    if (argc < 2) {\n"
          "        return 1;\n"
          "    }\n"
          "    printf(\"%d\\n\", handle(argv[1]));\n"
          "    return 0;\n"
          "}\n")

MAIN_C_INT = ("#include <stdio.h>\n"
              "#include <stdlib.h>\n"
              "#include \"work.h\"\n\n"
              "int main(int argc, char **argv) {\n"
              "    if (argc < 2) {\n"
              "        return 1;\n"
              "    }\n"
              "    printf(\"%d\\n\", handle(atoi(argv[1])));\n"
              "    return 0;\n"
              "}\n")

HEADER_STR = "#ifndef WORK_H\n#define WORK_H\nint handle(const char *value);\n#endif\n"
HEADER_INT = "#ifndef WORK_H\n#define WORK_H\nint handle(int value);\n#endif\n"


def c_case(slug, weakness, vulnerable_body, safe_body, sink, safe_sink,
           why_vulnerable, why_safe, safe_sanitizer="custom-effective",
           integer_entry=False, includes="#include <string.h>\n"):
    entry = MAIN_C_INT if integer_entry else MAIN_C
    header = HEADER_INT if integer_entry else HEADER_STR
    body = "{}#include \"work.h\"\n\n{}"
    return template(
        slug, "c", "c", weakness, None, "inter-file",
        {"main.c": entry, "work.h": header, "work.c": body.format(includes, vulnerable_body)},
        "work.c", sink, why_vulnerable,
        {"main.c": entry, "work.h": header, "work.c": body.format(includes, safe_body)},
        "work.c", safe_sink, safe_sanitizer, why_safe,
        "main.c", "int main",
    )


MEMORY = [
    c_case(
        "c-strcpy@unbounded-copy", CLASSIC_OVERFLOW,
        ("int handle(const char *value) {\n"
         "    char buffer[32];\n"
         "    strcpy(buffer, value);\n"
         "    return (int) strlen(buffer);\n}\n"),
        ("int handle(const char *value) {\n"
         "    char buffer[32];\n"
         "    snprintf(buffer, sizeof(buffer), \"%s\", value);\n"
         "    return (int) strlen(buffer);\n}\n"),
        "strcpy(buffer, value)", "snprintf(buffer, sizeof(buffer)",
        "strcpy copies until it finds a terminator and never consults the size of the "
        "destination, so any argument longer than 31 characters writes past a 32-byte buffer",
        "snprintf is given the destination size and truncates rather than overrunning",
        includes="#include <string.h>\n#include <stdio.h>\n",
    ),
    c_case(
        "c-sprintf@stack-format-copy", STACK_OVERFLOW,
        ("int handle(const char *value) {\n"
         "    char line[64];\n"
         "    sprintf(line, \"account=%s\", value);\n"
         "    return (int) strlen(line);\n}\n"),
        ("int handle(const char *value) {\n"
         "    char line[64];\n"
         "    snprintf(line, sizeof(line), \"account=%s\", value);\n"
         "    return (int) strlen(line);\n}\n"),
        "sprintf(line,", "snprintf(line, sizeof(line)",
        "sprintf writes the formatted result into a fixed stack buffer with no length limit, so "
        "the return address and saved registers beyond `line` are reachable from the argument",
        "the same format with the destination size supplied, so the write stops at the boundary",
        includes="#include <stdio.h>\n#include <string.h>\n",
    ),
    c_case(
        "c-heap-alloc@off-by-one-allocation", HEAP_OVERFLOW,
        ("int handle(const char *value) {\n"
         "    char *copy = malloc(strlen(value));\n"
         "    if (copy == NULL) {\n        return 1;\n    }\n"
         "    strcpy(copy, value);\n"
         "    int length = (int) strlen(copy);\n"
         "    free(copy);\n"
         "    return length;\n}\n"),
        ("int handle(const char *value) {\n"
         "    char *copy = malloc(strlen(value) + 1);\n"
         "    if (copy == NULL) {\n        return 1;\n    }\n"
         "    strcpy(copy, value);\n"
         "    int length = (int) strlen(copy);\n"
         "    free(copy);\n"
         "    return length;\n}\n"),
        "strcpy(copy, value)", "strcpy(copy, value)",
        "the allocation is exactly strlen bytes and strcpy writes strlen plus one, so the "
        "terminating NUL lands one byte past the end of the heap block. The null check is "
        "present and correct, which is what makes this a single-character defect",
        "the allocation reserves the extra byte the terminator needs",
        includes="#include <string.h>\n#include <stdlib.h>\n",
    ),
    c_case(
        "c-index-write@unchecked-index-write", OOB_WRITE,
        ("static int slots[16];\n\n"
         "int handle(int value) {\n"
         "    slots[value] = 1;\n"
         "    return slots[value];\n}\n"),
        ("static int slots[16];\n\n"
         "int handle(int value) {\n"
         "    if (value < 0 || value >= 16) {\n        return -1;\n    }\n"
         "    slots[value] = 1;\n"
         "    return slots[value];\n}\n"),
        "slots[value] = 1", "slots[value] = 1",
        "the index arrives from the argument and is used to write with no bounds test at all. A "
        "negative value writes before the array as readily as a large one writes past it",
        "both ends of the range are checked before the write, which is what the negative case "
        "requires and a one-sided check would miss",
        integer_entry=True, includes="",
    ),
    c_case(
        "c-index-read@unchecked-index-read", OOB_READ,
        ("static const int slots[16] = {0};\n\n"
         "int handle(int value) {\n"
         "    return slots[value];\n}\n"),
        ("static const int slots[16] = {0};\n\n"
         "int handle(int value) {\n"
         "    if (value < 0 || value >= 16) {\n        return -1;\n    }\n"
         "    return slots[value];\n}\n"),
        "return slots[value]", "return slots[value]",
        "an unchecked index reads whatever follows the array in memory and returns it to the "
        "caller, which is how adjacent data is disclosed rather than corrupted",
        "the index is confined to the array before it is used",
        integer_entry=True, includes="",
    ),
    c_case(
        "c-uaf@use-after-free", USE_AFTER_FREE,
        ("int handle(const char *value) {\n"
         "    char *copy = strdup(value);\n"
         "    if (copy == NULL) {\n        return 1;\n    }\n"
         "    free(copy);\n"
         "    return (int) strlen(copy);\n}\n"),
        ("int handle(const char *value) {\n"
         "    char *copy = strdup(value);\n"
         "    if (copy == NULL) {\n        return 1;\n    }\n"
         "    int length = (int) strlen(copy);\n"
         "    free(copy);\n"
         "    copy = NULL;\n"
         "    return length;\n}\n"),
        "return (int) strlen(copy)", "int length = (int) strlen(copy)",
        "the block is read after it has been returned to the allocator. The pointer still holds "
        "the old address, so nothing about the expression looks wrong in isolation — only the "
        "order of the two statements makes it a defect",
        "the read happens before the free, and the pointer is cleared afterwards so a later use "
        "faults instead of reading a recycled block",
        includes="#include <string.h>\n#include <stdlib.h>\n",
    ),
    c_case(
        "c-nullderef@unchecked-allocation", NULL_DEREF,
        ("int handle(const char *value) {\n"
         "    char *copy = malloc(strlen(value) + 1);\n"
         "    strcpy(copy, value);\n"
         "    int length = (int) strlen(copy);\n"
         "    free(copy);\n"
         "    return length;\n}\n"),
        ("int handle(const char *value) {\n"
         "    char *copy = malloc(strlen(value) + 1);\n"
         "    if (copy == NULL) {\n        return -1;\n    }\n"
         "    strcpy(copy, value);\n"
         "    int length = (int) strlen(copy);\n"
         "    free(copy);\n"
         "    return length;\n}\n"),
        "strcpy(copy, value)", "if (copy == NULL)",
        "the allocation result is written to without being tested. malloc returns NULL under "
        "memory pressure and the very next statement dereferences it",
        "the result is tested before any use, which is the whole of the fix",
        includes="#include <string.h>\n#include <stdlib.h>\n",
    ),
    c_case(
        "c-intoverflow@allocation-size-overflow", INT_OVERFLOW,
        ("int handle(int value) {\n"
         "    char *buffer = malloc(value * 16);\n"
         "    if (buffer == NULL) {\n        return -1;\n    }\n"
         "    memset(buffer, 0, value * 16);\n"
         "    free(buffer);\n"
         "    return value;\n}\n"),
        ("int handle(int value) {\n"
         "    if (value < 0 || value > 4096) {\n        return -1;\n    }\n"
         "    char *buffer = malloc((size_t) value * 16);\n"
         "    if (buffer == NULL) {\n        return -1;\n    }\n"
         "    memset(buffer, 0, (size_t) value * 16);\n"
         "    free(buffer);\n"
         "    return value;\n}\n"),
        "malloc(value * 16)", "malloc((size_t) value * 16)",
        "the multiplication happens in int and wraps, so a large argument produces a small "
        "allocation followed by a memset of the intended size. The allocation is null-checked "
        "and the check passes, because the allocation genuinely succeeded — at the wrong size",
        "the count is bounded before the multiplication and the arithmetic is widened, so the "
        "product cannot wrap",
        integer_entry=True, includes="#include <stdlib.h>\n#include <string.h>\n",
    ),
    c_case(
        "c-formatstring@user-controlled-format", FORMAT_STRING,
        ("int handle(const char *value) {\n"
         "    printf(value);\n"
         "    return 0;\n}\n"),
        ("int handle(const char *value) {\n"
         "    printf(\"%s\", value);\n"
         "    return 0;\n}\n"),
        "printf(value)", "printf(\"%s\", value)",
        "the argument becomes the format string, so directives inside it are interpreted. %n "
        "writes to memory and %s walks the stack, which turns a print into both a read and a "
        "write primitive",
        "the value is passed as an argument to a constant format, so its contents are never "
        "interpreted as directives",
        includes="#include <stdio.h>\n",
    ),
]

CPP_MEMORY = [
    template(
        "cpp-dangling@dangling-reference", "cpp", "cpp", USE_AFTER_FREE, None, "inter-file",
        {"main.cpp": ("#include <iostream>\n#include \"work.hpp\"\n\n"
                      "int main(int argc, char **argv) {\n"
                      "    if (argc < 2) {\n        return 1;\n    }\n"
                      "    std::cout << handle(std::string(argv[1])) << std::endl;\n"
                      "    return 0;\n}\n"),
         "work.hpp": "#pragma once\n#include <string>\nstd::size_t handle(const std::string &value);\n",
         "work.cpp": ("#include <string>\n#include \"work.hpp\"\n\n"
                      "static const std::string &pick(const std::string &value) {\n"
                      "    std::string local = value + \"-normalised\";\n"
                      "    return local;\n}\n\n"
                      "std::size_t handle(const std::string &value) {\n"
                      "    const std::string &chosen = pick(value);\n"
                      "    return chosen.size();\n}\n")},
        "work.cpp", "return chosen.size()",
        "pick returns a reference to a local that is destroyed when it returns, so chosen binds "
        "to storage that no longer exists. The call site looks ordinary; only the callee's "
        "return type makes it a defect",
        {"main.cpp": ("#include <iostream>\n#include \"work.hpp\"\n\n"
                      "int main(int argc, char **argv) {\n"
                      "    if (argc < 2) {\n        return 1;\n    }\n"
                      "    std::cout << handle(std::string(argv[1])) << std::endl;\n"
                      "    return 0;\n}\n"),
         "work.hpp": "#pragma once\n#include <string>\nstd::size_t handle(const std::string &value);\n",
         "work.cpp": ("#include <string>\n#include \"work.hpp\"\n\n"
                      "static std::string pick(const std::string &value) {\n"
                      "    return value + \"-normalised\";\n}\n\n"
                      "std::size_t handle(const std::string &value) {\n"
                      "    const std::string chosen = pick(value);\n"
                      "    return chosen.size();\n}\n")},
        "work.cpp", "return chosen.size()", "custom-effective",
        "the value is returned and held by value, so its lifetime covers the use",
        "main.cpp", "int main",
    ),
    template(
        "cpp-vector-index@unchecked-index-read", "cpp", "cpp", OOB_READ, None, "inter-file",
        {"main.cpp": ("#include <iostream>\n#include \"work.hpp\"\n\n"
                      "int main(int argc, char **argv) {\n"
                      "    if (argc < 2) {\n        return 1;\n    }\n"
                      "    std::cout << handle(std::atoi(argv[1])) << std::endl;\n"
                      "    return 0;\n}\n"),
         "work.hpp": "#pragma once\n#include <cstdlib>\nint handle(int value);\n",
         "work.cpp": ("#include <vector>\n#include \"work.hpp\"\n\n"
                      "int handle(int value) {\n"
                      "    std::vector<int> slots(16, 0);\n"
                      "    return slots[value];\n}\n")},
        "work.cpp", "return slots[value]",
        "operator[] on a vector performs no bounds check, by design — it is the unchecked "
        "accessor. An out-of-range index reads past the buffer just as a raw array would",
        {"main.cpp": ("#include <iostream>\n#include \"work.hpp\"\n\n"
                      "int main(int argc, char **argv) {\n"
                      "    if (argc < 2) {\n        return 1;\n    }\n"
                      "    std::cout << handle(std::atoi(argv[1])) << std::endl;\n"
                      "    return 0;\n}\n"),
         "work.hpp": "#pragma once\n#include <cstdlib>\nint handle(int value);\n",
         "work.cpp": ("#include <stdexcept>\n#include <vector>\n#include \"work.hpp\"\n\n"
                      "int handle(int value) {\n"
                      "    std::vector<int> slots(16, 0);\n"
                      "    if (value < 0) {\n        return -1;\n    }\n"
                      "    try {\n"
                      "        return slots.at(static_cast<std::size_t>(value));\n"
                      "    } catch (const std::out_of_range &) {\n"
                      "        return -1;\n    }\n}\n")},
        "work.cpp", "return slots.at(", "custom-effective",
        "at() is the checked accessor and throws rather than reading past the end; the negative "
        "case is rejected before the cast, since converting a negative int to size_t would "
        "produce a very large index that at() would then reject for the wrong reason",
        "main.cpp", "int main",
    ),
]

MEMORY_ALL = MEMORY + CPP_MEMORY
