#pragma once

#include <string>

namespace agy::cli {

/* Determines whether the first argument matches a recognized CLI command verb */
bool is_cli_verb(const wchar_t* arg);

/* Executes the CLI command with the given argument array, returns process exit code */
int execute(int argc, wchar_t** argv);

} // namespace agy::cli

