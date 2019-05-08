#pragma once
#include <cstdint>
#include <cinttypes>
#include <memory>
#include <unordered_map>
#include <map>
#include <set>
#include <tchar.h>

class libscylla;
class native_win_api;
class process_access_help;
class api_reader;
class iat_searcher;
class module_info;
class api_info;
class configuration_holder;
class configuration;

class ImportModuleThunk;
class Logger;
class PluginLoader;

enum class scylla_status;
enum class scylla_severity;
enum class decompose_status;
enum class config_option;

struct decompose_state;
struct iat_search_result;

typedef std::pair<uintptr_t, std::shared_ptr<api_info>> api_pair;
typedef size_t pid_t;
